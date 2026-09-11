"""Minimal stdlib BER/SNMP codecs, including SNMPv3 USM."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any


class PacketError(ValueError):
    pass


def _length(size: int) -> bytes:
    if size < 0x80:
        return bytes((size,))
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(raw),)) + raw


def tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _length(len(value)) + value


def integer(value: int) -> bytes:
    if value < 0:
        raise PacketError("negative integers are not emitted")
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return tlv(0x02, raw)


def oid_bytes(text: str) -> bytes:
    parts = [int(part) for part in text.strip(".").split(".")]
    if len(parts) < 2 or parts[0] > 2 or (parts[0] < 2 and parts[1] > 39):
        raise PacketError("invalid OID")
    output = bytearray((40 * parts[0] + parts[1],))
    for part in parts[2:]:
        if part < 0:
            raise PacketError("invalid OID")
        encoded = [part & 0x7f]
        part >>= 7
        while part:
            encoded.append(0x80 | (part & 0x7f))
            part >>= 7
        output.extend(reversed(encoded))
    return bytes(output)


def oid_text(raw: bytes) -> str:
    if not raw:
        raise PacketError("empty OID")
    first = min(raw[0] // 40, 2)
    parts = [first, raw[0] - first * 40]
    value = 0
    pending = False
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7f)
        pending = bool(byte & 0x80)
        if not pending:
            parts.append(value)
            value = 0
    if pending:
        raise PacketError("truncated OID")
    return "." + ".".join(str(part) for part in parts)


def _varbinds(oids: list[str]) -> bytes:
    return tlv(0x30, b"".join(tlv(0x30, tlv(0x06, oid_bytes(oid)) + tlv(0x05, b"")) for oid in oids))


def _request_pdu(request_id: int, oids: list[str]) -> bytes:
    return tlv(0xA0, integer(request_id) + integer(0) + integer(0) + _varbinds(oids))


def build_get(community: str, oids: list[str], request_id: int) -> bytes:
    # Keep the original SNMPv2c encoding byte-for-byte stable.
    body = integer(1) + tlv(0x04, community.encode("utf-8")) + _request_pdu(request_id, oids)
    return tlv(0x30, body)


class _Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.pos = 0

    def item(self, expected: int | None = None) -> tuple[int, bytes]:
        tag, value, _ = self.item_at(expected)
        return tag, value

    def item_at(self, expected: int | None = None) -> tuple[int, bytes, int]:
        if self.pos + 2 > len(self.raw):
            raise PacketError("truncated TLV")
        tag = self.raw[self.pos]
        self.pos += 1
        first = self.raw[self.pos]
        self.pos += 1
        if first & 0x80:
            count = first & 0x7f
            if count == 0 or count > 4 or self.pos + count > len(self.raw):
                raise PacketError("invalid BER length")
            size = int.from_bytes(self.raw[self.pos:self.pos + count], "big")
            self.pos += count
        else:
            size = first
        start = self.pos
        if self.pos + size > len(self.raw):
            raise PacketError("truncated value")
        value = self.raw[self.pos:self.pos + size]
        self.pos += size
        if expected is not None and tag != expected:
            raise PacketError(f"unexpected tag {tag:#x}")
        return tag, value, start

    def done(self) -> None:
        if self.pos != len(self.raw):
            raise PacketError("trailing BER bytes")


def _int(raw: bytes) -> int:
    if not raw or raw[0] & 0x80:
        raise PacketError("invalid non-negative integer")
    return int.from_bytes(raw, "big")


def _value(tag: int, raw: bytes) -> tuple[str, Any]:
    if tag == 0x02:
        return "integer", _int(raw)
    if tag == 0x04:
        return "octets", raw.decode("utf-8", errors="replace")
    if tag == 0x05:
        return "null", None
    if tag == 0x06:
        return "oid", oid_text(raw)
    if tag in (0x41, 0x42, 0x43, 0x46):
        names = {0x41: "counter32", 0x42: "gauge32", 0x43: "timeticks", 0x46: "counter64"}
        return names[tag], int.from_bytes(raw, "big")
    if tag in (0x80, 0x81, 0x82):
        return {0x80: "no_such_object", 0x81: "no_such_instance", 0x82: "end_of_mib"}[tag], None
    return f"tag_{tag:02x}", raw.hex()


def _parse_pdu(raw: bytes, expected_tag: int | None = None) -> tuple[int, dict[str, Any]]:
    reader = _Reader(raw)
    tag, pdu = reader.item()
    reader.done()
    if expected_tag is not None and tag != expected_tag:
        raise PacketError(f"unexpected PDU tag {tag:#x}")
    fields = _Reader(pdu)
    _, request_id = fields.item(0x02)
    _, error_status = fields.item(0x02)
    _, error_index = fields.item(0x02)
    _, varbind_list = fields.item(0x30)
    fields.done()
    rows = []
    bindings = _Reader(varbind_list)
    while bindings.pos < len(bindings.raw):
        _, varbind = bindings.item(0x30)
        item = _Reader(varbind)
        _, name = item.item(0x06)
        value_tag, value = item.item()
        item.done()
        value_type, decoded = _value(value_tag, value)
        rows.append({"oid": oid_text(name), "value_type": value_type, "value": decoded})
    return tag, {"request_id": _int(request_id), "error_status": _int(error_status),
                 "error_index": _int(error_index), "varbinds": rows}


def parse_response(raw: bytes) -> dict[str, Any]:
    root = _Reader(raw)
    _, message = root.item(0x30)
    root.done()
    body = _Reader(message)
    _, version = body.item(0x02)
    _, community = body.item(0x04)
    pdu_tag, pdu = body.item(0xA2)
    body.done()
    if _int(version) != 1:
        raise PacketError("response is not SNMPv2c")
    _, parsed = _parse_pdu(tlv(pdu_tag, pdu), 0xA2)
    return {"community": community.decode("utf-8", errors="strict"), **parsed}


# RFC 3414 password-to-key and key localization.
def _hash_name(protocol: str) -> str:
    names = {"md5": "md5", "sha": "sha1", "sha256": "sha256"}
    try:
        return names[protocol.lower()]
    except (AttributeError, KeyError) as exc:
        raise PacketError("unsupported authentication protocol") from exc


def password_to_key(protocol: str, password: str | bytes) -> bytes:
    password_bytes = password.encode("utf-8") if isinstance(password, str) else password
    if not password_bytes:
        raise PacketError("empty USM password")
    digest = hashlib.new(_hash_name(protocol))
    consumed = 0
    offset = 0
    while consumed < 1_048_576:
        amount = min(64, 1_048_576 - consumed)
        chunk = bytearray()
        while len(chunk) < amount:
            take = min(amount - len(chunk), len(password_bytes) - offset)
            chunk.extend(password_bytes[offset:offset + take])
            offset = (offset + take) % len(password_bytes)
        digest.update(chunk)
        consumed += amount
    return digest.digest()


def localize_key(protocol: str, password: str | bytes, engine_id: bytes) -> bytes:
    ku = password_to_key(protocol, password)
    return hashlib.new(_hash_name(protocol), ku + engine_id + ku).digest()


def _usm(engine_id: bytes, boots: int, engine_time: int, user: bytes,
         auth: bytes, privacy: bytes) -> bytes:
    return tlv(0x30, tlv(0x04, engine_id) + integer(boots) + integer(engine_time) +
               tlv(0x04, user) + tlv(0x04, auth) + tlv(0x04, privacy))


def _header(msg_id: int, flags: int) -> bytes:
    return tlv(0x30, integer(msg_id) + integer(65_507) + tlv(0x04, bytes((flags,))) + integer(3))


def _scoped(engine_id: bytes, pdu: bytes) -> bytes:
    return tlv(0x30, tlv(0x04, engine_id) + tlv(0x04, b"") + pdu)


def build_v3_discovery(request_id: int) -> bytes:
    security = _usm(b"", 0, 0, b"", b"", b"")
    body = integer(3) + _header(request_id, 0) + tlv(0x04, security) + _scoped(b"", _request_pdu(request_id, []))
    return tlv(0x30, body)


def _v3_parts(raw: bytes) -> dict[str, Any]:
    root = _Reader(raw)
    _, message, message_start = root.item_at(0x30)
    root.done()
    body = _Reader(message)
    _, version = body.item(0x02)
    if _int(version) != 3:
        raise PacketError("response is not SNMPv3")
    _, header = body.item(0x30)
    headers = _Reader(header)
    _, msg_id = headers.item(0x02)
    _, _max_size = headers.item(0x02)
    _, flags = headers.item(0x04)
    _, security_model = headers.item(0x02)
    headers.done()
    if len(flags) != 1 or _int(security_model) != 3:
        raise PacketError("invalid SNMPv3 header")
    _, security, security_start = body.item_at(0x04)
    data_tag, data = body.item()
    body.done()
    sec_outer = _Reader(security)
    _, usm, usm_start = sec_outer.item_at(0x30)
    sec_outer.done()
    fields = _Reader(usm)
    _, engine_id = fields.item(0x04)
    _, boots = fields.item(0x02)
    _, engine_time = fields.item(0x02)
    _, user = fields.item(0x04)
    _, auth, auth_start = fields.item_at(0x04)
    _, privacy = fields.item(0x04)
    fields.done()
    # Absolute offset of the authentication value within the original packet.
    auth_absolute = message_start + security_start + usm_start + auth_start
    boots_value, time_value = _int(boots), _int(engine_time)
    if boots_value > 0x7fffffff or time_value > 0x7fffffff:
        raise PacketError("USM engine boots/time is out of range")
    return {"msg_id": _int(msg_id), "flags": flags[0], "engine_id": engine_id,
            "boots": boots_value, "time": time_value, "user": user,
            "auth": auth, "auth_offset": auth_absolute, "privacy": privacy,
            "data_tag": data_tag, "data": data}


def parse_response_v3_report(raw: bytes) -> dict[str, Any]:
    parts = _v3_parts(raw)
    if parts["data_tag"] != 0x30:
        raise PacketError("encrypted discovery Report")
    scoped = _Reader(parts["data"])
    _, context_engine = scoped.item(0x04)
    _, _context_name = scoped.item(0x04)
    pdu_tag, pdu = scoped.item()
    scoped.done()
    _, parsed = _parse_pdu(tlv(pdu_tag, pdu), 0xA8)
    if not any(row["oid"] == ".1.3.6.1.6.3.15.1.1.4.0" for row in parsed["varbinds"]):
        raise PacketError("Report is not usmStatsUnknownEngineIDs")
    engine_id = parts["engine_id"] or context_engine
    if not engine_id:
        raise PacketError("Report omitted authoritative engine ID")
    return {"engine_id": engine_id, "boots": parts["boots"], "time": parts["time"]}


def _auth_digest(raw: bytes, protocol: str, password: str, engine_id: bytes,
                 offset: int, size: int) -> bytes:
    zeroed = raw[:offset] + bytes(size) + raw[offset + size:]
    return hmac.new(localize_key(protocol, password, engine_id), zeroed,
                    _hash_name(protocol)).digest()[:12]


def build_v3_get(request_id: int, msg_id: int, engine_id: bytes, boots: int, time: int,
                 user: str, auth_protocol: str, auth_password: str | None,
                 priv_protocol: str, priv_password: str | None, oids: list[str]) -> bytes:
    auth_protocol = auth_protocol.lower()
    priv_protocol = priv_protocol.lower()
    if not 0 <= request_id <= 0x7fffffff or not 0 <= msg_id <= 0x7fffffff:
        raise PacketError("SNMPv3 request/message ID is out of range")
    if not 0 <= boots <= 0x7fffffff or not 0 <= time <= 0x7fffffff:
        raise PacketError("USM engine boots/time is out of range")
    if auth_protocol not in {"none", "md5", "sha", "sha256"} or priv_protocol not in {"none", "des", "aes128"}:
        raise PacketError("unsupported USM protocol")
    if auth_protocol != "none" and not auth_password:
        raise PacketError("authentication password required")
    if priv_protocol != "none" and (auth_protocol == "none" or not priv_password):
        raise PacketError("privacy requires authentication and a privacy password")
    user_bytes = user.encode("utf-8")
    flags = (1 if auth_protocol != "none" else 0) | (2 if priv_protocol != "none" else 0)
    scoped = _scoped(engine_id, _request_pdu(request_id, oids))
    privacy = b""
    data = scoped
    if priv_protocol != "none":
        key = localize_key(auth_protocol, priv_password or "", engine_id)
        salt = secrets.token_bytes(8)
        if priv_protocol == "des":
            if len(key) < 16:
                raise PacketError("localized DES key is too short")
            privacy = boots.to_bytes(4, "big") + salt[-4:]
            iv = bytes(a ^ b for a, b in zip(key[8:16], privacy))
            padded = scoped + bytes((-len(scoped)) % 8)
            data = tlv(0x04, _des_cbc_encrypt(key[:8], iv, padded))
        else:
            privacy = salt
            iv = boots.to_bytes(4, "big") + time.to_bytes(4, "big") + salt
            data = tlv(0x04, _aes_cfb(key[:16], iv, scoped))
    auth = bytes(12) if auth_protocol != "none" else b""
    message = tlv(0x30, integer(3) + _header(msg_id, flags) +
                  tlv(0x04, _usm(engine_id, boots, time, user_bytes, auth, privacy)) + data)
    if auth_protocol != "none":
        parts = _v3_parts(message)
        digest = _auth_digest(message, auth_protocol, auth_password or "", engine_id,
                              parts["auth_offset"], len(parts["auth"]))
        message = message[:parts["auth_offset"]] + digest + message[parts["auth_offset"] + 12:]
    return message


def _decode_scoped(raw: bytes) -> dict[str, Any]:
    outer = _Reader(raw)
    _, scoped = outer.item(0x30)
    # RFC 3414 DES padding octets have no defined value; ignore the bounded tail.
    fields = _Reader(scoped)
    _, context_engine = fields.item(0x04)
    _, _context_name = fields.item(0x04)
    pdu_tag, pdu = fields.item()
    fields.done()
    _, parsed = _parse_pdu(tlv(pdu_tag, pdu), 0xA2)
    return {"context_engine_id": context_engine, **parsed}


def parse_response_v3(raw: bytes, expected_request_id: int, user: str,
                      auth_protocol: str, auth_password: str | None,
                      priv_protocol: str, priv_password: str | None) -> dict[str, Any]:
    parts = _v3_parts(raw)
    auth_protocol, priv_protocol = auth_protocol.lower(), priv_protocol.lower()
    expected_flags = (1 if auth_protocol != "none" else 0) | (2 if priv_protocol != "none" else 0)
    if parts["flags"] & 3 != expected_flags:
        raise PacketError("response security level does not match request")
    if parts["user"] != user.encode("utf-8"):
        raise PacketError("response USM user does not match")
    if auth_protocol != "none":
        if len(parts["auth"]) != 12 or not auth_password:
            raise PacketError("response authentication parameters are invalid")
        expected = _auth_digest(raw, auth_protocol, auth_password, parts["engine_id"],
                                parts["auth_offset"], len(parts["auth"]))
        if not hmac.compare_digest(parts["auth"], expected):
            raise PacketError("response USM authentication failed")
    elif parts["auth"]:
        raise PacketError("unexpected response authentication parameters")
    if priv_protocol == "none":
        if parts["data_tag"] != 0x30:
            raise PacketError("unexpected encrypted ScopedPDU")
        scoped_raw = tlv(0x30, parts["data"])
    else:
        if parts["data_tag"] != 0x04 or not priv_password:
            raise PacketError("missing encrypted ScopedPDU")
        key = localize_key(auth_protocol, priv_password, parts["engine_id"])
        if priv_protocol == "des":
            if len(parts["privacy"]) != 8 or len(parts["data"]) % 8:
                raise PacketError("invalid DES privacy parameters")
            iv = bytes(a ^ b for a, b in zip(key[8:16], parts["privacy"]))
            scoped_raw = _des_cbc_decrypt(key[:8], iv, parts["data"])
        elif priv_protocol == "aes128":
            if len(parts["privacy"]) != 8:
                raise PacketError("invalid AES privacy parameters")
            iv = parts["boots"].to_bytes(4, "big") + parts["time"].to_bytes(4, "big") + parts["privacy"]
            scoped_raw = _aes_cfb_decrypt(key[:16], iv, parts["data"])
        else:
            raise PacketError("unsupported privacy protocol")
    parsed = _decode_scoped(scoped_raw)
    if parsed["request_id"] != expected_request_id:
        raise PacketError("response request-id does not match")
    return {"engine_id": parts["engine_id"], "boots": parts["boots"], "time": parts["time"],
            "request_id": parsed["request_id"], "error_status": parsed["error_status"],
            "error_index": parsed["error_index"], "varbinds": parsed["varbinds"]}


# Compact pure-Python AES-128 encryption (CFB uses only the encrypt primitive).
def _gf_mul(a: int, b: int) -> int:
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return out


def _aes_sbox(x: int) -> int:
    inv = 0
    # Compute the inverse in GF(2^8); this runs once while constructing the table.
    if x:
        inv = next(y for y in range(1, 256) if _gf_mul(x, y) == 1)
    return inv ^ ((inv << 1) | (inv >> 7)) & 0xFF ^ ((inv << 2) | (inv >> 6)) & 0xFF ^ ((inv << 3) | (inv >> 5)) & 0xFF ^ ((inv << 4) | (inv >> 4)) & 0xFF ^ 0x63


_AES_SBOX = tuple(_aes_sbox(i) for i in range(256))


def _aes_expand(key: bytes) -> list[bytes]:
    if len(key) != 16:
        raise PacketError("AES-128 key must be 16 bytes")
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    while len(words) < 44:
        temp = words[-1][:]
        if len(words) % 4 == 0:
            temp = [_AES_SBOX[temp[1]], _AES_SBOX[temp[2]], _AES_SBOX[temp[3]], _AES_SBOX[temp[0]]]
            temp[0] ^= rcon
            rcon = _gf_mul(rcon, 2)
        words.append([a ^ b for a, b in zip(words[-4], temp)])
    return [bytes(sum(words[i:i + 4], [])) for i in range(0, 44, 4)]


def _aes_encrypt(key: bytes, block: bytes) -> bytes:
    state = list(block)
    rounds = _aes_expand(key)
    def add(r: int) -> None:
        nonlocal state
        state = [a ^ b for a, b in zip(state, rounds[r])]
    add(0)
    for rnd in range(1, 11):
        state = [_AES_SBOX[x] for x in state]
        state = [state[0], state[5], state[10], state[15], state[4], state[9], state[14], state[3],
                 state[8], state[13], state[2], state[7], state[12], state[1], state[6], state[11]]
        if rnd != 10:
            mixed = []
            for i in range(0, 16, 4):
                a = state[i:i + 4]
                mixed.extend((_gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3],
                              a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3],
                              a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3),
                              _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)))
            state = mixed
        add(rnd)
    return bytes(state)


def _aes_cfb(key: bytes, iv: bytes, data: bytes) -> bytes:
    out = bytearray()
    feedback = iv
    for pos in range(0, len(data), 16):
        chunk = data[pos:pos + 16]
        stream = _aes_encrypt(key, feedback)
        transformed = bytes(a ^ b for a, b in zip(chunk, stream))
        out.extend(transformed)
        # CFB decrypt feeds ciphertext; infer direction from caller is impossible.  A separate
        # implementation below chooses feedback via an explicit argument.
        feedback = transformed
    return bytes(out)


def _aes_cfb_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    out = bytearray()
    feedback = iv
    for pos in range(0, len(data), 16):
        chunk = data[pos:pos + 16]
        stream = _aes_encrypt(key, feedback)
        out.extend(bytes(a ^ b for a, b in zip(chunk, stream)))
        feedback = chunk
    return bytes(out)


# DES tables and primitives (FIPS 46-3), used only for RFC 3414 CBC privacy.
_IP = (58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7)
_FP = (40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25)
_E = (32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1)
_P = (16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25)
_PC1 = (57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4)
_PC2 = (14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32)
_SHIFTS = (1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1)
_S = (
(14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13),
(15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9),
(10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12),
(7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14),
(2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3),
(12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13),
(4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12),
(13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11))


def _permute(value: int, source_bits: int, table: tuple[int, ...]) -> int:
    out = 0
    for bit in table:
        out = (out << 1) | ((value >> (source_bits - bit)) & 1)
    return out


def _des_keys(key: bytes) -> list[int]:
    value = _permute(int.from_bytes(key, "big"), 64, _PC1)
    c, d = value >> 28, value & ((1 << 28) - 1)
    keys = []
    for shift in _SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & ((1 << 28) - 1)
        d = ((d << shift) | (d >> (28 - shift))) & ((1 << 28) - 1)
        keys.append(_permute((c << 28) | d, 56, _PC2))
    return keys


def _des_block(key: bytes, block: bytes, decrypt: bool = False) -> bytes:
    value = _permute(int.from_bytes(block, "big"), 64, _IP)
    left, right = value >> 32, value & 0xFFFFFFFF
    keys = _des_keys(key)
    if decrypt:
        keys.reverse()
    for subkey in keys:
        expanded = _permute(right, 32, _E) ^ subkey
        svalue = 0
        for box in range(8):
            six = (expanded >> (42 - box * 6)) & 0x3F
            row = ((six & 0x20) >> 4) | (six & 1)
            col = (six >> 1) & 0xF
            svalue = (svalue << 4) | _S[box][row * 16 + col]
        left, right = right, left ^ _permute(svalue, 32, _P)
    return _permute((right << 32) | left, 64, _FP).to_bytes(8, "big")


def _des_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    out = bytearray()
    previous = iv
    for pos in range(0, len(data), 8):
        block = bytes(a ^ b for a, b in zip(data[pos:pos + 8], previous))
        previous = _des_block(key, block)
        out.extend(previous)
    return bytes(out)


def _des_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    out = bytearray()
    previous = iv
    for pos in range(0, len(data), 8):
        block = data[pos:pos + 8]
        out.extend(bytes(a ^ b for a, b in zip(_des_block(key, block, True), previous)))
        previous = block
    return bytes(out)
