"""Hermetic tests for the Ivanti (RiskSense) VM API arm.

A local stdlib HTTP server stands in for the Ivanti platform so the live REST
search/export/discovery path is exercised with no network and no third-party
client. Env overrides arm the arm without an INI file.
"""

from __future__ import annotations

import http.server
import json
import os
import threading
from urllib.parse import urlparse

import pytest

from extension.arms.ivanti import ARM_ID, IvantiArm
from extension.arms.ivanti.policy import resolve_config_path
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
           ("IVANTI_API_KEY", "IVANTI_URL", "IVANTI_API_VER", "IVANTI_CLIENT_ID")}
    os.environ["IVANTI_API_KEY"] = "test-key"
    os.environ["IVANTI_URL"] = f"http://127.0.0.1:{port}"
    os.environ["IVANTI_API_VER"] = "/api/v1"
    os.environ["IVANTI_CLIENT_ID"] = "1550"
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


def test_unknown_endpoint_refused(ivanti_server):
    arm = IvantiArm()
    res = arm.invoke(_spec(), "search", {"endp": "nope"})
    assert not res.ok
    assert "endp must be one of" in (res.error or "")


def test_unknown_action_refused(ivanti_server):
    arm = IvantiArm()
    res = arm.invoke(_spec(), "frobnicate", {})
    assert not res.ok
