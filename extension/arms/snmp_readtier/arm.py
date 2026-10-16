"""Bounded, stdlib-only SNMPv2c and SNMPv3 USM identity reads."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import socket
import sys
from typing import Any, Mapping

from ...contract import TRANSPORT_CLI, ArmSpec, NotInstalledError, Result
from .codec import (
    PacketError, build_get, build_v3_discovery, build_v3_get, parse_response,
    parse_response_v3, parse_response_v3_report,
)
from .policy import (
    ALLOWED_ACTIONS, ARM_ID, ARG_KEYS, DEFAULT_COMMUNITY, DEFAULT_PORT, ENV_SCOPE,
    LIST_ACTIONS, MAX_RESPONSE_BYTES, OID_ALLOWLIST, args_refusal, authorize_host,
    normalize_oid,
)


class SnmpReadtierArm:
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
                "oid_allowlist": dict(OID_ALLOWLIST),
                "default_port": DEFAULT_PORT,
                "documented_community_example": DEFAULT_COMMUNITY,
                "snmp_versions": ["v2c", "v3-usm"],
                "arming": f"set {ENV_SCOPE} to explicit authorized targets; v2c community and v3 credentials remain explicit arguments",
            }, None)
        if action not in ALLOWED_ACTIONS:
            return Result(False, spec.id, action, None, f"action {action!r} is not on the allowlist (bounded reads only)")
        return self._probe(spec, action, payload)

    def _probe(self, spec: ArmSpec, action: str, payload: dict[str, Any]) -> Result:
        args_hash = _normalized_args_hash(payload)
        version = "v3" if "user" in payload else "v2c"
        refusal = args_refusal(payload)
        if refusal is None:
            refusal = authorize_host(payload["host"].strip())
        if refusal:
            return _finish(spec, action, args_hash, None, [], False, "input_refusal", refusal, version)

        host = payload["host"].strip()
        port = payload.get("port", DEFAULT_PORT)
        canonical_oids = [str(normalize_oid(value)) for value in payload["oids"]]
        request_id = secrets.randbelow(0x7ffffffe) + 1
        request = build_get(payload["community"], canonical_oids, request_id) if version == "v2c" else None
        request_sha = hashlib.sha256(request).hexdigest() if request is not None else None
        try:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
            if not addresses:
                raise OSError("target did not resolve")
            family, socktype, proto, _, address = addresses[0]
            with socket.socket(family, socktype, proto) as client:
                client.settimeout(payload["timeout_ms"] / 1000)
                client.connect(address)
                if version == "v3":
                    discovery = build_v3_discovery(request_id)
                    client.send(discovery)
                    report_raw = client.recv(MAX_RESPONSE_BYTES)
                    report = parse_response_v3_report(report_raw)
                    request = build_v3_get(
                        request_id, secrets.randbelow(0x7ffffffe) + 1,
                        report["engine_id"], report["boots"], report["time"], payload["user"],
                        payload.get("auth_protocol", "none"), payload.get("auth_password"),
                        payload.get("priv_protocol", "none"), payload.get("priv_password"), canonical_oids,
                    )
                    request_sha = hashlib.sha256(request).hexdigest()
                assert request is not None
                client.send(request)
                raw = client.recv(MAX_RESPONSE_BYTES)
        except socket.timeout:
            rows = [_row(oid, "unknown", None, None, "udp_no_response") for oid in canonical_oids]
            return _finish(spec, action, args_hash, request_sha, rows, False, "udp_no_response", "UDP timeout; absence is not an identity or credential verdict", version)
        except ConnectionRefusedError:
            rows = [_row(oid, "failed", None, None, "connection_refused") for oid in canonical_oids]
            return _finish(spec, action, args_hash, request_sha, rows, False, "connection_refused", "UDP target refused the probe", version)
        except OSError as exc:
            rows = [_row(oid, "failed", None, None, "socket_error") for oid in canonical_oids]
            return _finish(spec, action, args_hash, request_sha, rows, False, "socket_error", str(exc), version)
        except (PacketError, UnicodeError) as exc:
            digest = hashlib.sha256(report_raw).hexdigest() if "report_raw" in locals() else None
            rows = [_row(oid, "failed", None, digest, "malformed_response") for oid in canonical_oids]
            return _finish(spec, action, args_hash, request_sha, rows, False, "malformed_response", str(exc), version)

        response_sha = hashlib.sha256(raw).hexdigest()
        try:
            if version == "v2c":
                parsed = parse_response(raw)
                if parsed["request_id"] != request_id:
                    raise PacketError("response request-id does not match")
                if parsed["community"] != payload["community"]:
                    rows = [_row(oid, "failed", None, response_sha, "community_mismatch_response") for oid in canonical_oids]
                    return _finish(spec, action, args_hash, request_sha, rows, False, "community_mismatch_response", "response carried a different community", version)
            else:
                parsed = parse_response_v3(
                    raw, request_id, payload["user"], payload.get("auth_protocol", "none"),
                    payload.get("auth_password"), payload.get("priv_protocol", "none"), payload.get("priv_password"),
                )
            by_oid = {row["oid"]: row for row in parsed["varbinds"]}
            rows = []
            for oid in canonical_oids:
                found = by_oid.get(oid)
                if found is None:
                    rows.append(_row(oid, "missing", None, response_sha, "varbind_missing"))
                else:
                    status = "unavailable" if found["value_type"].startswith(("no_such", "end_of")) else "returned"
                    rows.append(_row(oid, status, {"type": found["value_type"], "data": found["value"]}, response_sha, None if status == "returned" else found["value_type"]))
            if parsed["error_status"]:
                return _finish(spec, action, args_hash, request_sha, rows, False, "agent_error", f"SNMP error-status {parsed['error_status']} at index {parsed['error_index']}", version)
        except (PacketError, UnicodeError) as exc:
            rows = [_row(oid, "failed", None, response_sha, "malformed_response") for oid in canonical_oids]
            return _finish(spec, action, args_hash, request_sha, rows, False, "malformed_response", str(exc), version)
        return _finish(spec, action, args_hash, request_sha, rows, True, None, None, version)


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
    raw_oids = payload.get("oids")
    oids = [normalize_oid(value) or {"sha256": _hash(value)} for value in raw_oids] if isinstance(raw_oids, list) else {"type": type(raw_oids).__name__}
    def secret_hash(name: str) -> Any:
        value = payload.get(name)
        return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest() if isinstance(value, str) else {"type": type(value).__name__}
    return _hash({
        "host": _host(payload.get("host")), "port": payload.get("port", DEFAULT_PORT),
        "community_sha256": secret_hash("community"), "user_sha256": secret_hash("user"),
        "auth_protocol": payload.get("auth_protocol", "none"), "auth_password_sha256": secret_hash("auth_password"),
        "priv_protocol": payload.get("priv_protocol", "none"), "priv_password_sha256": secret_hash("priv_password"),
        "oids": oids, "timeout_ms": payload.get("timeout_ms"), "arg_keys": sorted(payload),
    })


def _row(oid: str, status: str, value: Any, digest: str | None, reason: str | None) -> dict[str, Any]:
    return {"oid": oid, "status": status, "value": value, "raw_response_sha256": digest, "reason": reason}


def _finish(spec: ArmSpec, action: str, args_hash: str, request_sha: str | None, rows: list[dict[str, Any]], ok: bool, reason: str | None, error: str | None, version: str) -> Result:
    output = {"version": version, "reason": reason, "request_sha256": request_sha, "results": rows}
    receipt = {
        "schema": "snmp-readtier.probe-receipt.v1", "arm": ARM_ID, "action": action,
        "normalized_args_sha256": args_hash, "request_sha256": request_sha, "version": version,
        "results": rows, "status": "complete" if ok else "failed", "reason": reason,
        "output_sha256": hashlib.sha256(_canonical_json(output).encode()).hexdigest(),
    }
    print(_canonical_json(receipt), file=sys.stderr, flush=True)
    return Result(ok, spec.id, action, output, error)
