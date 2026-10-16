"""Bounded IKEv1 responder-presence probe with no key establishment."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import socket
import sys
from typing import Any, Mapping

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from .codec import PacketError, build_sa_init, parse_reply
from .policy import (
    ALLOWED_ACTIONS, ARM_ID, ARG_KEYS, DEFAULT_PORTS, ENV_SCOPE, LIST_ACTIONS,
    MAX_RESPONSE_BYTES, args_refusal, authorize_host,
)


class IkeReadtierArm:
    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(self, spec: ArmSpec, action: str, args: Mapping[str, Any]) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in LIST_ACTIONS:
            if payload:
                return Result(False, spec.id, action, None, "list_tools takes no arguments")
            return Result(True, spec.id, action, {
                "read_actions": sorted(ALLOWED_ACTIONS | LIST_ACTIONS),
                "dispatch_actions": [],
                "arg_keys": sorted(ARG_KEYS),
                "default_ports": list(DEFAULT_PORTS),
                "proposal": "IKEv1 main mode: AES256-SHA1-PSK-MODP2048 SA only",
                "boundary": "responder presence and capability echo only; no KE payload or key establishment",
                "arming": f"set {ENV_SCOPE} to explicit authorized targets",
            }, None)
        if action not in ALLOWED_ACTIONS:
            return Result(False, spec.id, action, None, f"action {action!r} is not on the allowlist (bounded reads only)")
        return self._probe(spec, action, payload)

    def _probe(self, spec: ArmSpec, action: str, payload: dict[str, Any]) -> Result:
        args_hash = _normalized_args_hash(payload)
        refusal = args_refusal(payload)
        if refusal is None:
            refusal = authorize_host(payload["host"].strip())
        if refusal:
            return _finish(spec, action, args_hash, None, [], False, "input_refusal", refusal)

        host = payload["host"].strip()
        ports = payload.get("ports", list(DEFAULT_PORTS))
        cookie = secrets.token_bytes(8)
        if cookie == b"\0" * 8:
            cookie = secrets.token_bytes(8)
        if cookie == b"\0" * 8:
            return _finish(spec, action, args_hash, None, [], False, "local_random_failure", "could not generate a non-zero initiator cookie in two attempts")
        packet = build_sa_init(cookie)
        rows: list[dict[str, Any]] = []
        for port in ports:
            wire = (b"\0\0\0\0" + packet) if port == 4500 else packet
            request_sha = hashlib.sha256(wire).hexdigest()
            try:
                addresses = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
                if not addresses:
                    raise OSError("target did not resolve")
                family, socktype, proto, _, address = addresses[0]
                with socket.socket(family, socktype, proto) as client:
                    client.settimeout(payload["timeout_ms"] / 1000)
                    client.connect(address)
                    client.send(wire)
                    raw = client.recv(MAX_RESPONSE_BYTES)
            except socket.timeout:
                rows.append(_row(port, "unknown", "udp_no_response", request_sha, None, None))
                continue
            except ConnectionRefusedError:
                rows.append(_row(port, "refused", "connection_refused", request_sha, None, None))
                continue
            except OSError as exc:
                rows.append(_row(port, "failed", "socket_error", request_sha, None, None, str(exc)))
                continue
            digest = hashlib.sha256(raw).hexdigest()
            try:
                parsed = parse_reply(raw, cookie, natt=port == 4500)
                rows.append(_row(port, "responded", None, request_sha, digest, parsed))
            except PacketError as exc:
                rows.append(_row(port, "failed", "malformed_response", request_sha, digest, None, str(exc)))

        ok = any(row["status"] == "responded" for row in rows)
        if ok:
            reason = None
            error = None
        elif rows and all(row["reason"] == "udp_no_response" for row in rows):
            reason = "udp_no_response"
            error = "UDP timeout; absence is not a responder or capability verdict"
        elif rows and all(row["reason"] == "connection_refused" for row in rows):
            reason = "connection_refused"
            error = "UDP targets refused the probe"
        else:
            reason = "no_valid_response"
            error = "no valid IKEv1 response was received"
        return _finish(spec, action, args_hash, cookie.hex(), rows, ok, reason, error)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(value: Any) -> str:
    try:
        encoded = _canonical_json(value)
    except (TypeError, ValueError):
        encoded = f"<{type(value).__name__}>"
    return hashlib.sha256(encoded.encode()).hexdigest()


def _host(raw: Any) -> Any:
    if not isinstance(raw, str):
        return {"type": type(raw).__name__}
    text = raw.strip().lower().rstrip(".")
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        return text


def _normalized_args_hash(payload: dict[str, Any]) -> str:
    return _hash({
        "host": _host(payload.get("host")),
        "ports": payload.get("ports", list(DEFAULT_PORTS)),
        "timeout_ms": payload.get("timeout_ms"),
        "arg_keys": sorted(payload),
    })


def _row(port: int, status: str, reason: str | None, request_sha: str, response_sha: str | None, reply: dict[str, Any] | None, detail: str | None = None) -> dict[str, Any]:
    return {
        "port": port, "status": status, "reason": reason,
        "request_sha256": request_sha, "raw_response_sha256": response_sha,
        "responder_cookie": reply["responder_cookie"] if reply else None,
        "capability_echo": reply["capability_echo"] if reply else None,
        "detail": detail,
    }


def _finish(spec: ArmSpec, action: str, args_hash: str, cookie: str | None, rows: list[dict[str, Any]], ok: bool, reason: str | None, error: str | None) -> Result:
    output = {"reason": reason, "initiator_cookie": cookie, "results": rows, "boundary": "presence/capability only; no key establishment"}
    receipt = {
        "schema": "ike-readtier.probe-receipt.v1", "arm": ARM_ID, "action": action,
        "normalized_args_sha256": args_hash, "initiator_cookie": cookie,
        "results": rows, "status": "complete" if ok else "failed", "reason": reason,
        "output_sha256": hashlib.sha256(_canonical_json(output).encode()).hexdigest(),
    }
    print(_canonical_json(receipt), file=sys.stderr, flush=True)
    return Result(ok, spec.id, action, output, error)
