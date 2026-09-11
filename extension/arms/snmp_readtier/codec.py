"""Minimal BER subset for one SNMPv2c GET request and response."""

from __future__ import annotations

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


def build_get(community: str, oids: list[str], request_id: int) -> bytes:
    varbinds = b"".join(tlv(0x30, tlv(0x06, oid_bytes(oid)) + tlv(0x05, b"")) for oid in oids)
    pdu = integer(request_id) + integer(0) + integer(0) + tlv(0x30, varbinds)
    body = integer(1) + tlv(0x04, community.encode("utf-8")) + tlv(0xA0, pdu)
    return tlv(0x30, body)


class _Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.pos = 0

    def item(self, expected: int | None = None) -> tuple[int, bytes]:
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
        if self.pos + size > len(self.raw):
            raise PacketError("truncated value")
        value = self.raw[self.pos:self.pos + size]
        self.pos += size
        if expected is not None and tag != expected:
            raise PacketError(f"unexpected tag {tag:#x}")
        return tag, value

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


def parse_response(raw: bytes) -> dict[str, Any]:
    root = _Reader(raw)
    _, message = root.item(0x30)
    root.done()
    body = _Reader(message)
    _, version = body.item(0x02)
    _, community = body.item(0x04)
    _, pdu = body.item(0xA2)
    body.done()
    if _int(version) != 1:
        raise PacketError("response is not SNMPv2c")
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
        tag, value = item.item()
        item.done()
        value_type, decoded = _value(tag, value)
        rows.append({"oid": oid_text(name), "value_type": value_type, "value": decoded})
    return {
        "community": community.decode("utf-8", errors="strict"),
        "request_id": _int(request_id),
        "error_status": _int(error_status),
        "error_index": _int(error_index),
        "varbinds": rows,
    }
