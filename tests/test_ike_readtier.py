"""Hermetic bounded IKE read-arm and custody tests."""

from __future__ import annotations

import hashlib
import json
import socket
import threading
from pathlib import Path

import pytest

from extension.arms.ike_readtier import ARM_ID, IkeReadtierArm
from extension.arms.ike_readtier.codec import build_sa_init, parse_reply
from extension.arms.ike_readtier.policy import ENV_SCOPE
from extension.contract import Catalog, CatalogEntry, Extension, describe

DEMO = Path(__file__).parents[1] / "extension" / "arms" / "ike_readtier" / "data" / "demo-reply.hex"
COOKIE = bytes.fromhex("0102030405060708")


def _ext() -> Extension:
    entry = CatalogEntry(ARM_ID, "arm", ("cli",), True, "test", "experimental")
    return Extension(catalog=Catalog([entry]), arms={ARM_ID: IkeReadtierArm()})


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
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, **kw: real(host, actual if port == 500 else port, **kw))


def _args() -> dict:
    return {"host": "127.0.0.1", "ports": [500], "timeout_ms": 100}


def _receipt(capsys) -> dict:
    lines = [line for line in capsys.readouterr().err.splitlines() if line]
    assert len(lines) == 1
    return json.loads(lines[0])


def test_fixed_packet_has_sa_and_no_ke_payload() -> None:
    packet = build_sa_init(COOKIE)
    assert len(packet) == int.from_bytes(packet[24:28], "big")
    assert packet[16] == 1 and packet[18] == 2
    # The sole chained payload is SA; its next-payload byte is zero.
    assert packet[28] == 0
    reply = parse_reply(bytes.fromhex(DEMO.read_text().strip()), COOKIE)
    assert reply["capability_echo"] is True
    assert reply["responder_cookie"] == "1112131415161718"


def test_probe_records_responder_cookie_and_digest(monkeypatch, capsys) -> None:
    reply = bytes.fromhex(DEMO.read_text().strip())
    port, thread = _server(reply)
    _map_port(monkeypatch, port)
    monkeypatch.setenv(ENV_SCOPE, "127.0.0.1")
    monkeypatch.setattr("extension.arms.ike_readtier.arm.secrets.token_bytes", lambda _n: COOKIE)
    result = _ext().invoke(ARM_ID, "probe", _args())
    thread.join(1)
    assert result.ok is True and result.output["initiator_cookie"] == COOKIE.hex()
    row = result.output["results"][0]
    assert row["status"] == "responded" and row["capability_echo"] is True
    assert row["raw_response_sha256"] == hashlib.sha256(reply).hexdigest()
    receipt = _receipt(capsys)
    assert receipt["output_sha256"] and receipt["results"] == result.output["results"]


def test_timeout_remains_unknown(monkeypatch, capsys) -> None:
    port, thread = _server(None)
    _map_port(monkeypatch, port)
    monkeypatch.setenv(ENV_SCOPE, "127.0.0.1")
    result = _ext().invoke(ARM_ID, "probe", _args())
    thread.join(1)
    assert result.ok is False and result.output["reason"] == "udp_no_response"
    assert result.output["results"][0]["status"] == "unknown"
    assert _receipt(capsys)["reason"] == "udp_no_response"


def test_malformed_reply_is_digest_bound(monkeypatch, capsys) -> None:
    port, thread = _server(b"bad-ike")
    _map_port(monkeypatch, port)
    monkeypatch.setenv(ENV_SCOPE, "127.0.0.1")
    result = _ext().invoke(ARM_ID, "probe", _args())
    thread.join(1)
    assert result.ok is False and result.output["reason"] == "no_valid_response"
    assert result.output["results"][0]["reason"] == "malformed_response"
    assert _receipt(capsys)["results"][0]["raw_response_sha256"]


def test_natt_requires_marker_and_accepts_marked_demo() -> None:
    raw = bytes.fromhex(DEMO.read_text().strip())
    parsed = parse_reply(b"\0\0\0\0" + raw, COOKIE, natt=True)
    assert parsed["capability_echo"] is True
    with pytest.raises(ValueError, match="marker"):
        parse_reply(raw, COOKIE, natt=True)


def test_policy_freezes_ports_and_scope(capsys) -> None:
    bad = _args() | {"ports": [4500]}
    assert _ext().invoke(ARM_ID, "probe", bad).ok is False
    _receipt(capsys)
    result = _ext().invoke(ARM_ID, "probe", _args())
    assert result.ok is False and ENV_SCOPE in result.error
    _receipt(capsys)
    malformed = _args() | {"ports": {500}}
    assert _ext().invoke(ARM_ID, "probe", malformed).ok is False
    _receipt(capsys)


def test_registration_profiles() -> None:
    assert describe(ARM_ID).tier == "experimental"
    from extension.invoke_profiles import invoke_profile
    listed = invoke_profile(ARM_ID, "list_tools")
    probe = invoke_profile(ARM_ID, "probe")
    assert listed.side_effects == ("local-read",)
    assert probe.side_effects == ("network-egress",) and probe.roe_ref.endswith("QA2-D")
