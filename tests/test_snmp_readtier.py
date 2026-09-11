"""Hermetic bounded SNMP read-arm and custody tests."""

from __future__ import annotations

import hashlib
import json
import socket
import threading
from pathlib import Path

import pytest

from extension.arms.snmp_readtier import ARM_ID, SnmpReadtierArm
from extension.arms.snmp_readtier.codec import build_get, parse_response
from extension.arms.snmp_readtier.policy import ENV_SCOPE
from extension.contract import ArmSpec, Catalog, CatalogEntry, Extension, describe

DEMO = Path(__file__).parents[1] / "extension" / "arms" / "snmp_readtier" / "data" / "demo-response.hex"


def _ext() -> Extension:
    entry = CatalogEntry(ARM_ID, "arm", ("cli",), True, "test", "experimental")
    return Extension(catalog=Catalog([entry]), arms={ARM_ID: SnmpReadtierArm()})


def _server(reply: bytes | None) -> tuple[int, threading.Thread]:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    def run() -> None:
        try:
            _request, peer = server.recvfrom(4096)
            if reply is not None:
                server.sendto(reply, peer)
        finally:
            server.close()
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return port, thread


def _map_port(monkeypatch: pytest.MonkeyPatch, actual: int) -> None:
    real = socket.getaddrinfo
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, **kw: real(host, actual if port == 161 else port, **kw))


def _args() -> dict:
    return {"host": "127.0.0.1", "community": "public", "oids": ["sysDescr.0"], "timeout_ms": 100}


def _receipt(capsys) -> dict:
    lines = [line for line in capsys.readouterr().err.splitlines() if line]
    assert len(lines) == 1
    return json.loads(lines[0])


def test_demo_response_and_request_codec() -> None:
    parsed = parse_response(bytes.fromhex(DEMO.read_text().strip()))
    assert parsed["request_id"] == 42
    assert parsed["varbinds"] == [{"oid": ".1.3.6.1.2.1.1.1.0", "value_type": "octets", "value": "demo"}]
    request = build_get("public", [".1.3.6.1.2.1.1.1.0"], 42)
    assert request.startswith(b"0") and b"public" in request


def test_probe_is_digest_bound_and_does_not_echo_community(monkeypatch, capsys) -> None:
    reply = bytes.fromhex(DEMO.read_text().strip())
    port, thread = _server(reply)
    _map_port(monkeypatch, port)
    monkeypatch.setenv(ENV_SCOPE, "127.0.0.1")
    monkeypatch.setattr("extension.arms.snmp_readtier.arm.secrets.randbelow", lambda _n: 41)
    result = _ext().invoke(ARM_ID, "probe", _args())
    thread.join(1)
    assert result.ok is True
    row = result.output["results"][0]
    assert row["status"] == "returned" and row["value"]["data"] == "demo"
    assert row["raw_response_sha256"] == hashlib.sha256(reply).hexdigest()
    receipt = _receipt(capsys)
    assert receipt["output_sha256"] and "public" not in json.dumps(receipt)


def test_timeout_is_unknown_not_wrong_community(monkeypatch, capsys) -> None:
    port, thread = _server(None)
    _map_port(monkeypatch, port)
    monkeypatch.setenv(ENV_SCOPE, "127.0.0.1")
    result = _ext().invoke(ARM_ID, "probe", _args())
    thread.join(1)
    assert result.ok is False and result.output["reason"] == "udp_no_response"
    assert result.output["results"][0]["status"] == "unknown"
    assert _receipt(capsys)["reason"] == "udp_no_response"


def test_malformed_reply_fails_closed(monkeypatch, capsys) -> None:
    port, thread = _server(b"not-ber")
    _map_port(monkeypatch, port)
    monkeypatch.setenv(ENV_SCOPE, "127.0.0.1")
    result = _ext().invoke(ARM_ID, "probe", _args())
    thread.join(1)
    assert result.ok is False and result.output["reason"] == "malformed_response"
    assert _receipt(capsys)["results"][0]["raw_response_sha256"]


def test_policy_requires_explicit_community_and_scope(capsys) -> None:
    args = _args()
    del args["community"]
    result = _ext().invoke(ARM_ID, "probe", args)
    assert result.ok is False and "community" in result.error
    assert _receipt(capsys)["reason"] == "input_refusal"
    result = _ext().invoke(ARM_ID, "probe", _args())
    assert result.ok is False and ENV_SCOPE in result.error
    _receipt(capsys)
    malformed = _args() | {"oids": [object()]}
    assert _ext().invoke(ARM_ID, "probe", malformed).ok is False
    _receipt(capsys)


def test_oid_inventory_is_frozen(capsys) -> None:
    listed = _ext().invoke(ARM_ID, "list_tools", {})
    assert list(listed.output["oid_allowlist"]) == ["sysDescr.0", "sysUpTime.0", "sysName.0"]
    bad = _args() | {"oids": [".1.3.6.1.2.1.1.6.0"]}
    assert _ext().invoke(ARM_ID, "probe", bad).ok is False
    _receipt(capsys)


def test_registration_profiles() -> None:
    assert describe(ARM_ID).tier == "experimental"
    from extension.invoke_profiles import invoke_profile
    assert invoke_profile(ARM_ID, "list_tools").side_effects == ("local-read",)
    probe = invoke_profile(ARM_ID, "probe")
    assert probe.side_effects == ("network-egress",) and probe.synthetic_only is False
