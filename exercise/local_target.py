"""Disposable loopback HTTP target for an explicitly selected operator scenario."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shlex
import shutil
import tempfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Iterator


class TargetError(ValueError):
    """Local target setup or cleanup could not be completed."""


def available() -> bool:
    return os.name == "posix" and shutil.which("curl") is not None


@contextmanager
def target() -> Iterator[tuple[str, str, dict, dict]]:
    """Scope one real http-probe invocation to a temporary synthetic listener.

    This is a sequential CLI lifecycle: scoped environment changes are restored
    on exit. It is not a general-purpose sandbox or a concurrent library API.
    The adapter still performs normal admission, scope checks and bounded curl
    execution. The wrapper only disables ambient curl config and proxy routing.
    """
    curl = shutil.which("curl")
    if os.name != "posix" or curl is None:
        raise TargetError("http-target requires POSIX and an installed curl executable")
    body = json.dumps({"service": "specaudit-synthetic", "canary": secrets.token_hex(16),
                       "environment": "disposable-loopback"}, sort_keys=True).encode()
    metadata = {"kind": "synthetic-http-target", "bind": "127.0.0.1",
                "body_sha256": hashlib.sha256(body).hexdigest(), "response_body": body.decode(),
                "requests": [], "cleanup": "pending", "curl": str(Path(curl).resolve())}

    class Handler(BaseHTTPRequestHandler):
        server_version = "SpecAuditSynthetic/1.0"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(2.0)

        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            status = 200 if self.path == "/ctf/status" else 404
            metadata["requests"].append({"method": "GET", "path": self.path[:256], "status": status})
            # A cap also bounds unrelated local requests during the short run.
            del metadata["requests"][:-32]
            payload = body if status == 200 else b"not found"
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-SpecAudit-Target", "synthetic")
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    endpoint = f"http://127.0.0.1:{server.server_port}/ctf/status"
    metadata["url"] = endpoint
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="specaudit-http-target-") as temporary:
            wrapper = Path(temporary) / "curl-no-config"
            wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(str(Path(curl).resolve()))
                               + " -q --noproxy '*' \"$@\"\n", encoding="utf-8")
            wrapper.chmod(0o700)
            settings = {"HTTP_PROBE_BIN": str(wrapper), "HTTP_PROBE_DISPATCH_SCOPE": endpoint,
                        "CURL_HOME": temporary, "XDG_CONFIG_HOME": temporary,
                        "NO_PROXY": "*", "no_proxy": "*"}
            for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
                        "http_proxy", "https_proxy", "all_proxy", "ftp_proxy"):
                settings[key] = None
            previous = {key: os.environ.get(key) for key in settings}
            try:
                for key, value in settings.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
                yield "http-probe", "probe", {"url": endpoint, "headers": {}}, metadata
            finally:
                for key, value in previous.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        metadata["cleanup"] = "stopped" if not thread.is_alive() else "failed"
        if thread.is_alive():
            raise TargetError("synthetic HTTP target did not stop")
