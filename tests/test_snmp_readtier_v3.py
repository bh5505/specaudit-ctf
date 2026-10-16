"""Hermetic SNMPv3 USM codec and arm tests (no live targets)."""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import threading

import pytest

import extension.arms.snmp_readtier.codec as codec
from extension.arms.snmp_readtier import ARM_ID, SnmpReadtierArm
from extension.arms.snmp_readtier.codec import (
    build_v3_discovery, build_v3_get, localize_key, parse_response_v3,
    parse_response_v3_report,
)
from extension.arms.snmp_readtier.policy import ENV_SCOPE, args_refusal
from extension.contract import ArmSpec, Catalog, CatalogEntry, Extension

ENGINE_ID = bytes.fromhex("80001f8880e9630000d61ff449")
OID = ".1.3.6.1.2.1.1.1.0"
USER = "testuser"
AUTH_PASSWORD = "maplesyrup"
PRIV_PASSWORD = "privacypass"


def _ext() -> Extension:
    entry = CatalogEntry(ARM_ID, "arm", ("cli",), True, "test", "experimental")
    return Extension(catalog=Catalog([entry]), arms={ARM_ID: SnmpReadtierArm()})


def _pdu(tag: int, request_id: int, value: bytes, report: bool = False) -> bytes:
    oid = ".1.3.6.1.6.3.15.1.1.4.0" if report else OID
    value_tlv = codec.tlv(0x41, b"\x01") if report else codec.tlv(0x04, value)
    binding = codec.tlv(0x30, codec.tlv(0x06, codec.oid_bytes(oid)) + value_tlv)
    return codec.tlv(tag, codec.integer(request_id) + codec.integer(0) + codec.integer(0) + codec.tlv(0x30, binding))


def _report(request_id: int = 41) -> bytes:
    security = codec._usm(ENGINE_ID, 7, 1234, b"", b"", b"")
    body = codec.integer(3) + codec._header(99, 0) + codec.tlv(0x04, security)
    body += codec._scoped(ENGINE_ID, _pdu(0xA8, request_id, b"", True))
    return codec.tlv(0x30, body)


def _response(request_id: int, auth_protocol: str, priv_protocol: str, value: bytes = b"v3-demo") -> bytes:
    flags = (auth_protocol != "none") | ((priv_protocol != "none") << 1)
    scoped = codec._scoped(ENGINE_ID, _pdu(0xA2, request_id, value))
    privacy = b""
    data = scoped
    if priv_protocol != "none":
        key = localize_key(auth_protocol, PRIV_PASSWORD, ENGINE_ID)
        salt = bytes.fromhex("0102030405060708")
        if priv_protocol == "des":
            privacy = (7).to_bytes(4, "big") + salt[-4:]
            iv = bytes(a ^ b for a, b in zip(key[8:16], privacy))
            data = codec.tlv(0x04, codec._des_cbc_encrypt(key[:8], iv, scoped + bytes((-len(scoped)) % 8)))
        else:
            privacy = salt
            iv = (7).to_bytes(4, "big") + (1234).to_bytes(4, "big") + salt
            data = codec.tlv(0x04, codec._aes_cfb(key[:16], iv, scoped))
    auth = bytes(12) if auth_protocol != "none" else b""
    raw = codec.tlv(0x30, codec.integer(3) + codec._header(100, int(flags)) +
                    codec.tlv(0x04, codec._usm(ENGINE_ID, 7, 1234, USER.encode(), auth, privacy)) + data)
    if auth_protocol != "none":
        parts = codec._v3_parts(raw)
        digest = hmac.new(localize_key(auth_protocol, AUTH_PASSWORD, ENGINE_ID), raw,
                          codec._hash_name(auth_protocol)).digest()  # auth field is initially zero
        raw = raw[:parts["auth_offset"]] + digest[:12] + raw[parts["auth_offset"] + 12:]
    return raw


def test_password_localization_and_fixed_usm_digest_vector(monkeypatch) -> None:
    # RFC 3414 A.3.1/A.3.2 MD5 password-to-key localization vector.
    assert codec.password_to_key("md5", "maplesyrup").hex() == "9faf3283884e92834ebc9847d8edd963"
    assert localize_key("md5", "maplesyrup", bytes.fromhex("000000000000000000000002")).hex() == "526f5eed9fcce26f8964c2930787d82b"
    monkeypatch.setattr(codec.secrets, "token_bytes", lambda size: bytes.fromhex("0102030405060708"))
    packet = build_v3_get(41, 42, ENGINE_ID, 7, 1234, USER, "sha", AUTH_PASSWORD,
                          "none", None, [OID])
    parts = codec._v3_parts(packet)
    assert parts["auth"].hex() == "24c9f526c0c9b652ab4ffd6c"
    zeroed = packet[:parts["auth_offset"]] + bytes(12) + packet[parts["auth_offset"] + 12:]
    expected = hmac.new(localize_key("sha", AUTH_PASSWORD, ENGINE_ID), zeroed, hashlib.sha1).digest()[:12]
    assert parts["auth"] == expected


def test_embedded_block_ciphers_match_published_vectors() -> None:
    # FIPS-197 C.1 AES-128 and FIPS 46-3 DES examples.
    assert codec._aes_encrypt(bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                              bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert codec._des_block(bytes.fromhex("133457799bbcdff1"),
                            bytes.fromhex("0123456789abcdef")).hex() == "85e813540f0ab405"


def test_discovery_message_and_report_parser() -> None:
    discovery = build_v3_discovery(41)
    parts = codec._v3_parts(discovery)
    assert parts["flags"] == 0 and parts["engine_id"] == b"" and parts["user"] == b""
    assert parse_response_v3_report(_report()) == {"engine_id": ENGINE_ID, "boots": 7, "time": 1234}


@pytest.mark.parametrize("auth,privacy", [
    ("none", "none"), ("md5", "none"), ("sha", "none"), ("sha256", "none"),
    ("md5", "des"), ("sha", "aes128"), ("sha256", "aes128"),
])
def test_parse_authenticated_and_private_response_round_trips(auth: str, privacy: str) -> None:
    raw = _response(41, auth, privacy)
    parsed = parse_response_v3(raw, 41, USER, auth,
                               AUTH_PASSWORD if auth != "none" else None,
                               privacy, PRIV_PASSWORD if privacy != "none" else None)
    assert parsed["engine_id"] == ENGINE_ID
    assert parsed["varbinds"] == [{"oid": OID, "value_type": "octets", "value": "v3-demo"}]
    if auth != "none":
        tampered = raw[:-1] + bytes((raw[-1] ^ 1,))
        with pytest.raises(codec.PacketError, match="authentication failed"):
            parse_response_v3(tampered, 41, USER, auth, AUTH_PASSWORD, privacy,
                              PRIV_PASSWORD if privacy != "none" else None)


def test_v3_policy_defaults_and_validation() -> None:
    base = {"host": "127.0.0.1", "user": USER, "oids": ["sysDescr.0"], "timeout_ms": 100}
    assert args_refusal(base) is None
    assert "auth_password" in args_refusal(base | {"auth_protocol": "sha"})
    assert "requires authentication" in args_refusal(base | {"priv_protocol": "aes128", "priv_password": "x"})
    assert "auth_protocol" in args_refusal(base | {"auth_protocol": "bogus"})
    assert "user" in args_refusal(base | {"user": "\ud800"})


def test_arm_v3_discovery_then_authenticated_get(monkeypatch, capsys) -> None:
    report = _report()
    response = _response(41, "sha", "none")
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def run() -> None:
        try:
            first, peer = server.recvfrom(65535)
            assert codec._v3_parts(first)["engine_id"] == b""
            server.sendto(report, peer)
            second, peer = server.recvfrom(65535)
            assert codec._v3_parts(second)["user"] == USER.encode()
            server.sendto(response, peer)
        finally:
            server.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    monkeypatch.setenv(ENV_SCOPE, "127.0.0.1")
    monkeypatch.setattr("extension.arms.snmp_readtier.arm.secrets.randbelow", lambda _n: 40)
    args = {"host": "127.0.0.1", "port": port, "user": USER, "auth_protocol": "sha",
            "auth_password": AUTH_PASSWORD, "oids": ["sysDescr.0"], "timeout_ms": 500}
    result = _ext().invoke(ARM_ID, "probe", args)
    thread.join(1)
    assert result.ok and result.output["version"] == "v3"
    assert result.output["results"][0]["value"]["data"] == "v3-demo"
    receipt = json.loads(capsys.readouterr().err.strip())
    assert receipt["version"] == "v3" and receipt["request_sha256"]
    assert AUTH_PASSWORD not in json.dumps(receipt)
