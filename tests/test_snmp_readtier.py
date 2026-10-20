"""Hermetic bounded SNMP read-arm and custody tests."""

from __future__ import annotations

import hashlib
import socket
import threading
from pathlib import Path

import pytest

from extension.arms.snmp_readtier import ARM_ID, SnmpReadtierArm
from extension.arms.snmp_readtier import codec
from extension.arms.snmp_readtier.codec import build_get, parse_response
from extension.arms.snmp_readtier.policy import MAX_OIDS, normalize_oid
from extension.contract import Catalog, CatalogEntry, Extension

DEMO = Path(__file__).parents[1] / "extension" / "arms" / "snmp_readtier" / "data" / "demo-response.hex"


def _ext() -> Extension:
    entry = CatalogEntry(ARM_ID, "arm", ("cli",), "test")
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
    monkeypatch.setattr("extension.arms.snmp_readtier.arm.secrets.randbelow", lambda _n: 41)
    result = _ext().invoke(ARM_ID, "probe", _args())
    thread.join(1)
    assert result.ok is True
    assert result.output["version"] == "v2c"
    row = result.output["results"][0]
    assert row["status"] == "returned" and row["value"]["data"] == "demo"
    assert row["raw_response_sha256"] == hashlib.sha256(reply).hexdigest()
    assert result.output["request_sha256"]
    assert "public" not in str(result.output)
    assert capsys.readouterr().err == ""


def test_timeout_is_unknown_not_wrong_community(monkeypatch, capsys) -> None:
    port, thread = _server(None)
    _map_port(monkeypatch, port)
    result = _ext().invoke(ARM_ID, "probe", _args())
    thread.join(1)
    assert result.ok is False and result.output["reason"] == "udp_no_response"
    assert result.output["results"][0]["status"] == "unknown"
    assert capsys.readouterr().err == ""


def test_malformed_reply_fails_closed(monkeypatch, capsys) -> None:
    port, thread = _server(b"not-ber")
    _map_port(monkeypatch, port)
    result = _ext().invoke(ARM_ID, "probe", _args())
    thread.join(1)
    assert result.ok is False and result.output["reason"] == "malformed_response"
    assert result.output["results"][0]["raw_response_sha256"] == hashlib.sha256(b"not-ber").hexdigest()
    assert capsys.readouterr().err == ""


def test_policy_requires_explicit_community_and_valid_arguments(capsys) -> None:
    args = _args()
    del args["community"]
    result = _ext().invoke(ARM_ID, "probe", args)
    assert result.ok is False and "community" in result.error
    assert result.output["reason"] == "input_refusal"
    malformed = _args() | {"oids": [object()]}
    assert _ext().invoke(ARM_ID, "probe", malformed).ok is False
    assert capsys.readouterr().err == ""


def test_list_tools_reports_aliases_not_allowlist() -> None:
    listed = _ext().invoke(ARM_ID, "list_tools", {})
    assert listed.ok is True
    assert listed.output["oid_aliases"] == {
        "sysDescr.0": ".1.3.6.1.2.1.1.1.0",
        "sysUpTime.0": ".1.3.6.1.2.1.1.3.0",
        "sysName.0": ".1.3.6.1.2.1.1.5.0",
    }
    assert "oid_allowlist" not in listed.output
    assert listed.output["max_oids"] == MAX_OIDS
    assert listed.output["snmp_versions"] == ["v2c", "v3-usm"]
    assert {"user", "auth_protocol", "auth_password", "priv_protocol", "priv_password"} <= set(listed.output["arg_keys"])


def _v2c_response(request_id: int, community: str, rows: list[tuple[str, int, bytes]]) -> bytes:
    bindings = b"".join(
        codec.tlv(0x30, codec.tlv(0x06, codec.oid_bytes(oid)) + codec.tlv(tag, value))
        for oid, tag, value in rows
    )
    pdu = codec.tlv(
        0xA2,
        codec.integer(request_id) + codec.integer(0) + codec.integer(0) + codec.tlv(0x30, bindings),
    )
    return codec.tlv(0x30, codec.integer(1) + codec.tlv(0x04, community.encode()) + pdu)


def test_arbitrary_numeric_oids_pass_through(monkeypatch, capsys) -> None:
    oids = ["sysDescr.0", ".1.3.6.1.2.1.1.6.0", "1.3.6.1.2.1.1.7.0", ".1.3.6.1.4.1.99999.1.2.3"]
    canonical = [".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.6.0",
                 ".1.3.6.1.2.1.1.7.0", ".1.3.6.1.4.1.99999.1.2.3"]
    assert [normalize_oid(value) for value in oids] == canonical
    seen: dict = {}
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    reply = _v2c_response(42, "public", [
        (canonical[0], 0x04, b"demo"),
        (canonical[1], 0x04, b"lab-closet"),
        (canonical[2], 0x02, b"\x48"),
        (canonical[3], 0x04, b"custom"),
    ])

    def run() -> None:
        try:
            request, peer = server.recvfrom(65535)
            seen["request"] = request
            server.sendto(reply, peer)
        finally:
            server.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    _map_port(monkeypatch, port)
    monkeypatch.setattr("extension.arms.snmp_readtier.arm.secrets.randbelow", lambda _n: 41)
    result = _ext().invoke(ARM_ID, "probe", _args() | {"oids": oids, "timeout_ms": 500})
    thread.join(1)
    assert result.ok is True
    assert [row["oid"] for row in result.output["results"]] == canonical
    assert result.output["results"][2]["value"] == {"type": "integer", "data": 72}
    assert result.output["results"][3]["value"] == {"type": "octets", "data": "custom"}
    assert codec.oid_bytes(".1.3.6.1.4.1.99999.1.2.3") in seen["request"]
    assert result.output["reason"] is None
    assert capsys.readouterr().err == ""


def test_malformed_oids_are_refused(capsys) -> None:
    bad_oids = [
        "", "   ", "sysDescr", ".", "1", "1..3.6", ".1..3.6",
        "1.3.6.1.2.1.1.6.0.", "1.3.6.1.2.1.1.-1.0", "1.3.6.a.1",
        "9.1.2.3", "1.99.2.3", "1.3.6.1.2.1.4294967296.0",
        "+1.3.6", "1.3.6 .1", 123, None, object(),
    ]
    for bad in bad_oids:
        result = _ext().invoke(ARM_ID, "probe", _args() | {"oids": [bad]})
        assert result.ok is False, bad
        assert result.output["reason"] == "input_refusal", bad
        assert "malformed or duplicate" in result.error, bad
    duplicate = _ext().invoke(ARM_ID, "probe", _args() | {"oids": ["sysDescr.0", ".1.3.6.1.2.1.1.1.0"]})
    assert duplicate.ok is False and "malformed or duplicate" in duplicate.error
    too_many = [f".1.3.6.1.4.1.99999.1.{index}" for index in range(MAX_OIDS + 1)]
    over = _ext().invoke(ARM_ID, "probe", _args() | {"oids": too_many})
    assert over.ok is False and f"one to {MAX_OIDS}" in over.error
    assert _ext().invoke(ARM_ID, "probe", _args() | {"oids": []}).ok is False
    assert capsys.readouterr().err == ""
