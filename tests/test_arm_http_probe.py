"""Hermetic contract tests for the dispatch-scoped http-probe arm."""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from extension.arms.httpprobe import ARM_ID, HttpProbeArm
from extension.arms.httpprobe.policy import argv_for
from extension.contract import ArmSpec, Extension, load_catalog
from extension.invoke_profiles import invoke_profile


def _spec() -> ArmSpec:
    return ArmSpec(ARM_ID, ("cli",), True, "Fixture arm.", "research")


def _fake_curl(tmp_path: Path) -> Path:
    script = tmp_path / "curl-fixture.py"
    script.write_text(
        """import http.client, sys, urllib.parse
args = sys.argv[1:]
headers = {}
i = 0
while i < len(args):
    if args[i] == '-H':
        name, value = args[i + 1].split(':', 1)
        headers[name] = value.lstrip(' ')
        i += 2
    elif args[i] == '--':
        url = args[i + 1]
        break
    else:
        i += 1
p = urllib.parse.urlsplit(url)
conn_cls = http.client.HTTPSConnection if p.scheme == 'https' else http.client.HTTPConnection
conn = conn_cls(p.hostname, p.port, timeout=10)
path = urllib.parse.urlunsplit(('', '', p.path or '/', p.query, ''))
conn.request('GET', path, headers=headers)
r = conn.getresponse()
body = r.read()
out = sys.stdout.buffer
out.write(f'HTTP/1.1 {r.status} {r.reason}\\r\\n'.encode())
for k, v in r.getheaders(): out.write(f'{k}: {v}\\r\\n'.encode())
out.write(b'\\r\\n' + body)
""",
        encoding="utf-8",
    )
    if os.name == "nt":
        wrapper = tmp_path / "curl.bat"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
        return wrapper
    wrapper = tmp_path / "curl"
    wrapper.write_text(f"#!{sys.executable}\nexec(open(r'{script}').read())\n", encoding="utf-8")
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    return wrapper


def _arm(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, timeout: float = 30) -> HttpProbeArm:
    monkeypatch.setenv("HTTP_PROBE_BIN", str(_fake_curl(tmp_path)))
    return HttpProbeArm(timeout=timeout)


def _serve(handler: type[BaseHTTPRequestHandler]) -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _report(result: Any) -> dict[str, Any]:
    return json.loads(result.output["output"])


def test_scope_absent_refuses(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    arm = _arm(monkeypatch, tmp_path)
    monkeypatch.delenv("HTTP_PROBE_DISPATCH_SCOPE", raising=False)
    result = arm.invoke(_spec(), "probe", {"url": "http://127.0.0.1:9/"})
    assert result.ok is False
    assert "HTTP_PROBE_DISPATCH_SCOPE" in result.error


def test_blanket_scope_refuses(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    arm = _arm(monkeypatch, tmp_path)
    monkeypatch.setenv("HTTP_PROBE_DISPATCH_SCOPE", "*")
    result = arm.invoke(_spec(), "probe", {"url": "http://127.0.0.1:9/"})
    assert result.ok is False
    assert "blanket scope" in result.error


def test_loopback_delivers_headers_exactly(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    received: dict[str, str] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            for name in ("Header-X", "Header-Y", "Header-Z"):
                received[name] = self.headers[name]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"HTTP/body-start")

        def log_message(self, *_args: Any) -> None:
            pass

    server, _ = _serve(Handler)
    try:
        monkeypatch.setenv("HTTP_PROBE_DISPATCH_SCOPE", "127.0.0.1")
        sent = {"Header-X": "one", "Header-Y": "two spaces", "Header-Z": "z:3"}
        result = _arm(monkeypatch, tmp_path).invoke(
            _spec(), "probe", {"url": f"http://127.0.0.1:{server.server_port}/", "headers": sent}
        )
        assert result.ok is True
        report = _report(result)
        assert report["status"] == 200
        assert report["body_head"] == "HTTP/body-start"
        assert received == sent
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    "headers, reason",
    [
        ({"Host": "elsewhere"}, "duplicate or mangle"),
        ({"X-Long": "x" * 513}, "exceeds 512"),
        ({"Bad_Name": "x"}, "RFC token"),
    ],
)
def test_invalid_headers_refused_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    headers: dict[str, str],
    reason: str,
) -> None:
    monkeypatch.setenv("HTTP_PROBE_DISPATCH_SCOPE", "127.0.0.1")
    result = _arm(monkeypatch, tmp_path).invoke(
        _spec(), "probe", {"url": "http://127.0.0.1:9/", "headers": headers}
    )
    assert result.ok is False and reason in result.error
    assert "[dispatch]" not in capsys.readouterr().err


def test_closed_schema_and_malformed_url_refuse_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HTTP_PROBE_DISPATCH_SCOPE", "127.0.0.1")
    arm = _arm(monkeypatch, tmp_path)
    extra = arm.invoke(
        _spec(), "probe", {"url": "http://127.0.0.1:9/", "surprise": True}
    )
    malformed = arm.invoke(_spec(), "probe", {"url": "http://[broken/"})
    bad_port = arm.invoke(_spec(), "probe", {"url": "http://127.0.0.1:notaport/"})
    assert extra.ok is False and "surprise" in extra.error
    assert malformed.ok is False and "well-formed" in malformed.error
    assert bad_port.ok is False and "well-formed" in bad_port.error
    assert "[dispatch]" not in capsys.readouterr().err


def test_secret_header_is_masked_everywhere(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = "Bearer xyz-super-secret"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.headers["Authorization"].encode())

        def log_message(self, *_args: Any) -> None:
            pass

    server, _ = _serve(Handler)
    try:
        monkeypatch.setenv("HTTP_PROBE_DISPATCH_SCOPE", "127.0.0.1")
        result = _arm(monkeypatch, tmp_path).invoke(
            _spec(),
            "probe",
            {
                "url": f"http://127.0.0.1:{server.server_port}/",
                "headers": {"Authorization": raw, "X-Copy": raw},
            },
        )
        rendered = json.dumps(result.to_dict()) + capsys.readouterr().err
        assert raw not in rendered
        assert rendered.count("Be...23") >= 2
    finally:
        server.shutdown()
        server.server_close()


def test_redirects_surface_as_data_and_are_never_followed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    followed = threading.Event()

    class Target(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            followed.set()
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args: Any) -> None:
            pass

    target, _ = _serve(Target)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}/next")
            self.end_headers()
            self.wfile.write(b"redirect-data")

        def log_message(self, *_args: Any) -> None:
            pass

    redirect, _ = _serve(Redirect)
    try:
        monkeypatch.setenv("HTTP_PROBE_DISPATCH_SCOPE", "127.0.0.1")
        result = _arm(monkeypatch, tmp_path).invoke(
            _spec(), "probe", {"url": f"http://127.0.0.1:{redirect.server_port}/"}
        )
        assert result.ok is True and _report(result)["status"] == 302
        assert followed.wait(0.1) is False
    finally:
        redirect.shutdown(); redirect.server_close()
        target.shutdown(); target.server_close()


def test_timeout_is_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class Slow(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            time.sleep(0.5)

        def log_message(self, *_args: Any) -> None:
            pass

    server, _ = _serve(Slow)
    try:
        monkeypatch.setenv("HTTP_PROBE_DISPATCH_SCOPE", "127.0.0.1")
        result = _arm(monkeypatch, tmp_path, timeout=0.05).invoke(
            _spec(), "probe", {"url": f"http://127.0.0.1:{server.server_port}/"}
        )
        assert result.ok is False and "timed out" in result.error
    finally:
        server.shutdown(); server.server_close()


def test_argv_and_catalog_registration() -> None:
    payload = {"url": "https://example.test/p", "headers": {"X-One": "1", "X-Two": "2"}}
    assert argv_for("curl", "probe", payload) == [
        "curl", "-sS", "-o", "-", "-D", "-", "--max-time", "30",
        "-H", "X-One: 1", "-H", "X-Two: 2", "--", "https://example.test/p",
    ]
    entry = load_catalog().get(ARM_ID)
    assert entry.curated is True and entry.protocols == ("cli",)
    assert ARM_ID in Extension().arms
    profile = invoke_profile(ARM_ID, "probe")
    assert profile is not None
    assert profile.approval_ref == "operator://dispatch-scope/HTTP_PROBE_DISPATCH_SCOPE"
