"""Fixed-shape IKEv1 main-mode SA proposal construction and reply parsing."""

from __future__ import annotations

import struct
from typing import Any


class PacketError(ValueError):
    pass


# Transform attributes: AES-CBC, SHA-1, pre-shared-key authentication,
# MODP-2048, and a 256-bit AES key. No secret or keying payload is present.
_ATTRIBUTES = struct.pack("!HHHHHHHHHH", 0x8001, 7, 0x8002, 2, 0x8003, 1, 0x8004, 14, 0x800E, 256)
_TRANSFORM = struct.pack("!BBHBBH", 0, 0, 8 + len(_ATTRIBUTES), 1, 1, 0) + _ATTRIBUTES
_PROPOSAL = struct.pack("!BBHBBBB", 0, 0, 8 + len(_TRANSFORM), 1, 1, 0, 1) + _TRANSFORM
_SA_BODY = struct.pack("!II", 1, 1) + _PROPOSAL
_SA = struct.pack("!BBH", 0, 0, 4 + len(_SA_BODY)) + _SA_BODY


def build_sa_init(initiator_cookie: bytes) -> bytes:
    if len(initiator_cookie) != 8 or initiator_cookie == b"\0" * 8:
        raise PacketError("initiator cookie must be eight non-zero bytes")
    length = 28 + len(_SA)
    header = struct.pack("!8s8sBBBBII", initiator_cookie, b"\0" * 8, 1, 0x10, 2, 0, 0, length)
    return header + _SA


def _payload(raw: bytes, offset: int, expected: int) -> tuple[int, bytes, int]:
    if offset + 4 > len(raw):
        raise PacketError("truncated payload header")
    next_payload, _reserved, length = struct.unpack_from("!BBH", raw, offset)
    if length < 4 or offset + length > len(raw):
        raise PacketError("invalid payload length")
    return next_payload, raw[offset + 4:offset + length], offset + length


def _capability_echo(sa_body: bytes) -> bool:
    if len(sa_body) < 8:
        raise PacketError("truncated SA payload")
    doi, situation = struct.unpack_from("!II", sa_body)
    if (doi, situation) != (1, 1):
        return False
    next_payload, proposal, end = _payload(sa_body, 8, 2)
    if end != len(sa_body) or next_payload != 0 or len(proposal) < 4:
        return False
    proposal_number, protocol_id, spi_size, transform_count = struct.unpack_from("!BBBB", proposal)
    if (proposal_number, protocol_id, spi_size, transform_count) != (1, 1, 0, 1):
        return False
    next_transform, transform, transform_end = _payload(proposal, 4, 3)
    if transform_end != len(proposal) or next_transform != 0 or len(transform) < 4:
        return False
    number, transform_id, _reserved = struct.unpack_from("!BBH", transform)
    if (number, transform_id) != (1, 1):
        return False
    attrs = transform[4:]
    if len(attrs) % 4:
        raise PacketError("invalid transform attributes")
    found: dict[int, int] = {}
    for offset in range(0, len(attrs), 4):
        kind, value = struct.unpack_from("!HH", attrs, offset)
        if not kind & 0x8000:
            raise PacketError("variable-length attributes are outside the MVP subset")
        found[kind & 0x7fff] = value
    return all(found.get(kind) == value for kind, value in {1: 7, 2: 2, 3: 1, 4: 14, 14: 256}.items())


def parse_reply(raw: bytes, initiator_cookie: bytes, *, natt: bool = False) -> dict[str, Any]:
    if natt:
        if not raw.startswith(b"\0\0\0\0"):
            raise PacketError("NAT-T reply lacks the non-ESP marker")
        raw = raw[4:]
    if len(raw) < 28:
        raise PacketError("truncated ISAKMP header")
    init, responder, next_payload, version, exchange, flags, message_id, length = struct.unpack_from("!8s8sBBBBII", raw)
    if length != len(raw) or init != initiator_cookie or responder == b"\0" * 8:
        raise PacketError("reply cookie or length mismatch")
    if version >> 4 != 1 or exchange != 2 or message_id != 0:
        raise PacketError("reply is not an IKEv1 main-mode response")
    # Walk the declared payload chain. MVP accepts an SA reply followed by benign
    # trailing payloads (e.g. Vendor ID / Notify that real responders append); it
    # records their types instead of rejecting a real responder. A Notify-only
    # chain is still a valid presence proof: negotiation answerable but incomplete.
    PTYPE_NAME = {1: "sa", 4: "ke", 5: "id", 10: "nonce", 11: "notify", 13: "vid"}
    seen_types: list[str] = []
    capability = False
    offset = 28
    ptype = next_payload
    for _ in range(8):
        if ptype == 0 or offset >= len(raw):
            break
        following, body, end = _payload(raw, offset, ptype)
        seen_types.append(PTYPE_NAME.get(ptype, str(ptype)))
        if ptype == 1:
            capability = _capability_echo(body)
        offset = end
        ptype = following
    return {
        "responder_cookie": responder.hex(),
        "capability_echo": capability,
        "version": f"{version >> 4}.{version & 0x0f}",
        "flags": flags,
        "trailing_payload_types": seen_types,
        "negotiation_complete": capability,
    }
