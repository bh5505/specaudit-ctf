"""Hermetic tests for the Ivanti (RiskSense) VM API arm.

A local stdlib HTTP server stands in for the Ivanti platform so the live REST
search/export/discovery path is exercised with no network and no third-party
client. Env overrides arm the arm without an INI file.
"""

from __future__ import annotations

import contextlib
import http.server
import json
import os
import threading
from urllib.parse import urlparse

import pytest

from extension.arms.ivanti import ARM_ID, IvantiArm
from extension.arms.ivanti.policy import ENV_SCOPE, resolve_config_path
from extension.contract import ArmSpec

# --------------------------------------------------------------------------
# mock Ivanti platform
# --------------------------------------------------------------------------


class _Handler(http.server.BaseHTTPRequestHandler):
    pages = 2
    page_size = 2
    search_hits = 0
    last_body = None

    def log_message(self, *args):  # silence
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlparse(self.path).path
        if path.endswith("/host/filter"):
            return self._send(200, [{"field": "ipAddress", "operators": ["CIDR", "IN"]}])
        if path.endswith("/host/export/template"):
            return self._send(200, {"exportableFields": [{"name": "id"}, {"name": "ipAddress"}]})
        if "/export/" in path:
            # a finished export: non-JSON bytes
            data = b"id,ipAddress\n1,10.0.0.1\n"
            self.send_response(200)
            self.send_header("content-type", "text/csv")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        return self._send(404, {})

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        type(self).last_body = body
        if path.endswith("/host/search"):
            type(self).search_hits += 1
            page = int(body.get("page", 0))
            total_pages = type(self).pages
            start = page * type(self).page_size
            if page >= total_pages:
                records = []
            else:
                records = [
                    {"id": str(start + i + 1), "ipAddress": f"10.0.0.{start+i+1}",
                     "hostName": "h" + str(start + i + 1)}
                    for i in range(type(self).page_size)
                ]
            payload = {
                "page": {"totalElements": total_pages * type(self).page_size,
                         "totalPages": total_pages},
                "_embedded": {"hosts": records},
            }
            return self._send(200, payload)
        if path.endswith("/hostFinding/search"):
            type(self).search_hits += 1
            page = int(body.get("page", 0))
            records = [] if page >= 1 else [{
                "id": "f1", "title": "CVE-2021-44790",
                "port": 443, "severityGroup": "CRITICAL",
                "host": {"hostId": 7, "ipAddress": "10.0.0.9"},
            }]
            return self._send(200, {"page": {"totalElements": 1, "totalPages": 1},
                                    "_embedded": {"hostFindings": records}})
        if path.endswith("/host/export"):
            return self._send(201, {"id": "exp-1"})
        return self._send(404, {})


@pytest.fixture
def ivanti_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    old = {k: os.environ.get(k) for k in
           ("IVANTI_API_KEY", "IVANTI_URL", "IVANTI_API_VER", "IVANTI_CLIENT_ID",
            ENV_SCOPE)}
    os.environ["IVANTI_API_KEY"] = "test-key"
    os.environ["IVANTI_URL"] = f"http://127.0.0.1:{port}"
    os.environ["IVANTI_API_VER"] = "/api/v1"
    os.environ["IVANTI_CLIENT_ID"] = "1550"
    # Every live action is scope-gated now: the armed platform must be inside
    # IVANTI_SCOPE, so the happy-path fixture names the loopback platform.
    os.environ[ENV_SCOPE] = "127.0.0.1"
    try:
        yield port
    finally:
        server.shutdown()
        thread.join()
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _spec():
    return ArmSpec(
        id=ARM_ID, protocols=("cli",), curated=True,
        tier="experimental", notes="",
    )


def test_list_tools_reports_armed(ivanti_server):
    arm = IvantiArm()
    res = arm.invoke(_spec(), "list_tools", {})
    assert res.ok
    assert "search" in res.output["read_actions"]
    assert res.output["armed"] is True
    assert res.output["default_size"] == 750


def test_search_pulls_hosts(ivanti_server):
    arm = IvantiArm()
    res = arm.invoke(_spec(), "search", {"endp": "host"})
    assert res.ok, res.error
    assert res.output["count"] == 4  # 2 pages * 2
    ips = [r["ipAddress"] for r in res.output["records"]]
    assert "10.0.0.1" in ips and "10.0.0.4" in ips
    assert "hostName" in res.output["records"][0]


def test_search_honors_pages_limit(ivanti_server):
    arm = IvantiArm()
    res = arm.invoke(_spec(), "search", {"endp": "host", "pages": 1})
    assert res.ok
    assert res.output["count"] == 2  # page 0 only


def test_search_findings_lifts_host(ivanti_server):
    arm = IvantiArm()
    res = arm.invoke(_spec(), "search", {"endp": "hostFinding", "extract_host": True})
    assert res.ok, res.error
    rec = res.output["records"][0]
    assert rec["host_ip"] == "10.0.0.9"
    assert rec["host_id"] == 7
    # nested host is JSON-encoded
    assert isinstance(rec["host"], str)


def test_filters_and_fields_discovery(ivanti_server):
    arm = IvantiArm()
    res = arm.invoke(_spec(), "filters", {"endp": "host"})
    assert res.ok and res.output["filters"][0]["field"] == "ipAddress"
    res2 = arm.invoke(_spec(), "fields", {"endp": "host"})
    assert res2.ok and res2.output["fields"][0]["name"] == "id"


def test_export_downloads_csv(ivanti_server, tmp_path):
    arm = IvantiArm()
    save = str(tmp_path / "out.csv")
    res = arm.invoke(_spec(), "export", {"endp": "host", "save": save})
    assert res.ok, res.error
    assert res.output["saved_csv"] == save
    assert res.output["bytes"] > 0
    assert os.path.exists(save)


def test_search_save_writes_csv(ivanti_server, tmp_path):
    arm = IvantiArm()
    save = str(tmp_path / "hosts.csv")
    res = arm.invoke(_spec(), "search", {"endp": "host", "save": save})
    assert res.ok
    assert res.output["saved_csv"] == save
    assert os.path.exists(save)
    assert os.path.getsize(save) > 0


def test_unarmed_reports_error():
    for k in ("IVANTI_API_KEY", "IVANTI_URL", "IVANTI_API_VER", "IVANTI_CLIENT_ID"):
        os.environ.pop(k, None)
    arm = IvantiArm()
    res = arm.invoke(_spec(), "search", {"endp": "host"})
    assert not res.ok
    assert "unarmed" in (res.error or "")


def test_scope_required_refuses_without_reaching_platform(ivanti_server,
                                                          monkeypatch):
    """Scope is not optional: a configured platform with no IVANTI_SCOPE must be
    refused, and the refusal must come before any HTTP request."""
    monkeypatch.delenv(ENV_SCOPE, raising=False)
    arm = IvantiArm()
    listed = arm.invoke(_spec(), "list_tools", {})
    assert listed.output["armed"] is False
    before = _Handler.search_hits
    res = arm.invoke(_spec(), "search", {"endp": "host"})
    assert not res.ok
    assert ENV_SCOPE in (res.error or "")
    assert _Handler.search_hits == before, "no request may reach the platform unarmed"


def test_scope_outside_refuses_platform(ivanti_server, monkeypatch):
    """A scope that does not contain the configured platform is a refusal."""
    monkeypatch.setenv(ENV_SCOPE, "10.99.0.0/16")
    arm = IvantiArm()
    before = _Handler.search_hits
    res = arm.invoke(_spec(), "search", {"endp": "host"})
    assert not res.ok
    assert "outside" in (res.error or "")
    assert _Handler.search_hits == before


def test_scope_inside_proceeds(ivanti_server):
    """The happy path: platform inside the armed scope runs (mock transport)."""
    arm = IvantiArm()
    res = arm.invoke(_spec(), "filters", {"endp": "host"})
    assert res.ok, res.error


def test_unknown_endpoint_refused(ivanti_server):
    arm = IvantiArm()
    res = arm.invoke(_spec(), "search", {"endp": "nope"})
    assert not res.ok
    assert "endp must be one of" in (res.error or "")


def test_unknown_action_refused(ivanti_server):
    arm = IvantiArm()
    res = arm.invoke(_spec(), "frobnicate", {})
    assert not res.ok


def _write_ini(path, url, api_ver="/api/v1", client_id="1550", api_key="test-key"):
    path.write_text(
        "[platform]\n"
        f"url = {url}\n"
        f"api_ver = {api_ver}\n"
        f"client_id = {client_id}\n"
        "[secrets]\n"
        f"api_key = {api_key}\n",
        encoding="utf-8")
    return str(path)


@pytest.fixture
def ivanti_platform():
    """A mock platform that does NOT touch the environment.

    The shared ``ivanti_server`` fixture arms the arm through IVANTI_* env vars;
    the explicit-config tests must clear those instead, so they use this bare
    server (monkeypatch's teardown would otherwise re-set the credentials after
    the fixture restored them, leaking state into later modules).
    """
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join()


_CREDENTIAL_KEYS = ("IVANTI_CONFIG", "IVANTI_URL", "IVANTI_API_VER",
                    "IVANTI_CLIENT_ID", "IVANTI_API_KEY")


@contextlib.contextmanager
def _clean_env(scope):
    """Clear the credential env and set IVANTI_SCOPE, restoring exactly."""
    saved = {k: os.environ.get(k) for k in (*_CREDENTIAL_KEYS, ENV_SCOPE)}
    try:
        for key in _CREDENTIAL_KEYS:
            os.environ.pop(key, None)
        if scope is None:
            os.environ.pop(ENV_SCOPE, None)
        else:
            os.environ[ENV_SCOPE] = scope
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_explicit_config_out_of_scope_refused_before_contact(ivanti_platform,
                                                              tmp_path):
    """The gate must check the *effective* config (payload "config"), not the
    default one. With the default config unconfigured the old gate returned ""
    and skipped authorization entirely while the client dialed the explicit
    config - a live request with no scope check."""
    ini = _write_ini(tmp_path / "explicit.ini",
                     f"http://127.0.0.1:{ivanti_platform}")
    arm = IvantiArm()
    before = _Handler.search_hits
    with _clean_env("10.99.0.0/16"):
        res = arm.invoke(_spec(), "search", {"endp": "host", "config": ini})
    assert not res.ok
    assert "outside" in (res.error or "")
    assert _Handler.search_hits == before, \
        "no request may reach the out-of-scope explicit platform"


def test_explicit_config_requires_scope(ivanti_platform, tmp_path):
    """A missing IVANTI_SCOPE still refuses an explicit-config dispatch: the fix
    must not turn an unconfigured default target into a silent allow."""
    ini = _write_ini(tmp_path / "noscope.ini",
                     f"http://127.0.0.1:{ivanti_platform}")
    arm = IvantiArm()
    before = _Handler.search_hits
    with _clean_env(None):
        res = arm.invoke(_spec(), "search", {"endp": "host", "config": ini})
    assert not res.ok
    assert ENV_SCOPE in (res.error or "")
    assert _Handler.search_hits == before


def test_explicit_config_in_scope_proceeds_on_same_target(ivanti_platform,
                                                          tmp_path):
    """Gate and dial agree: an in-scope explicit config proceeds, and the
    dispatch stamp names that same target."""
    ini = _write_ini(tmp_path / "ok.ini", f"http://127.0.0.1:{ivanti_platform}")
    arm = IvantiArm()
    with _clean_env("127.0.0.1"):
        res = arm.invoke(_spec(), "search", {"endp": "host", "config": ini})
    assert res.ok, res.error
    assert res.output["count"] == 4
    assert res.output["dispatch"]["target"] == f"http://127.0.0.1:{ivanti_platform}"


def test_success_result_carries_dispatch_audit_and_stamp(ivanti_server, capsys):
    """A gated successful pull leaves the same audit trail the other
    scope-gated arms do: a [dispatch] stderr line and a provenance stamp."""
    arm = IvantiArm()
    res = arm.invoke(_spec(), "filters", {"endp": "host"})
    assert res.ok, res.error
    assert res.output["dispatch"] == {
        "dispatch": "true", "scope": "127.0.0.1",
        "target": f"http://127.0.0.1:{ivanti_server}",
    }
    err = capsys.readouterr().err
    assert "[dispatch]" in err
    assert "arm=ivanti" in err
    assert f"target=http://127.0.0.1:{ivanti_server}" in err
