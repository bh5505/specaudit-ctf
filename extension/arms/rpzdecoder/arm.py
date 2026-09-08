"""Curated rpz-decoder arm: raw IP/domain extraction from an RPZ zone.

Ad-hoc, unscheduled threat-intel extraction over an operator-supplied
Response Policy Zone. ``decode`` is a pure in-process pass over an
AXFR dump; ``fetch``/``status`` shell out to dig against the zone
master under the dispatch gate. The arm returns bounded reports
(counts, action distribution, samples, file paths) — the raw
indicator lists land in files, never inline in a Result.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Mapping

from ...contract import (
    TRANSPORT_CLI,
    ArmSpec,
    NotInstalledError,
    Result,
)
from ..dispatch import authorize, log_dispatch, stamp
from ..mcp_client import redact
from . import decoder
from .decoder import ZoneDecodeError
from .policy import (
    ALLOWED_ACTIONS,
    ARG_KEYS,
    ARMING,
    ARM_ID,
    CAVEATS,
    DEFAULT_PORT,
    DIG_QUERY_TIMEOUT,
    DISPATCH_ACTIONS,
    ENV_DISPATCH_SCOPE,
    ENV_MASTER,
    ENV_ZONE,
    MAX_DUMP_BYTES,
    MAX_OUTPUT_CHARS,
    SAMPLE_INDICATORS,
    TIMEOUT_SECONDS,
    args_refusal,
    keyfile_refusal,
    master_refusal,
    port_refusal,
    resolve_dig,
    zone_refusal,
)

_LIST_TOOLS_ACTIONS = frozenset({"list_tools", "tools/list"})


class RpzDecoderArm:
    """Specialized transport for catalog id rpz-decoder.

    ``installed`` reports handler presence only: the decode core is
    in-process, and dig is only required by the dispatch-tier actions,
    which return evaluated failures when it is missing.
    """

    ARM_ID = ARM_ID
    protocol = TRANSPORT_CLI

    def __init__(self, timeout: float = TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    def installed(self, spec: ArmSpec) -> bool:
        return spec.id == ARM_ID

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        if spec.id != ARM_ID:
            raise NotInstalledError(spec.id)
        payload = dict(args)
        if action in _LIST_TOOLS_ACTIONS:
            return self._list_tools(spec, action)
        if action not in ALLOWED_ACTIONS and action not in DISPATCH_ACTIONS:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=f"action {action!r} is not on the allowlist "
                "(decode an AXFR dump, or dispatch-gated fetch/status; "
                f"arming: {ARMING}; caveats: {'; '.join(CAVEATS)})",
            )
        refusal = args_refusal(action, payload)
        if refusal:
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=refusal,
            )
        if action == "decode":
            return self._decode(spec, action, payload)
        return self._dispatched(spec, action, payload)

    # ------------------------------------------------------------------
    # decode (in-process read tier)

    def _decode(self, spec: ArmSpec, action: str, payload: dict) -> Result:
        dump = Path(str(payload["dump"]))
        if not dump.is_file():
            return _fail(spec, action, f"dump not found: {dump}")
        size = dump.stat().st_size
        if size > MAX_DUMP_BYTES:
            return _fail(
                spec,
                action,
                f"dump exceeds MAX_DUMP_BYTES ({size} > {MAX_DUMP_BYTES})",
            )
        try:
            raw = dump.read_bytes()
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            return _fail(spec, action, f"dump is not valid UTF-8: {exc}")
        except OSError as exc:
            return _fail(spec, action, f"dump unreadable: {exc}")
        if not text.strip():
            return _fail(spec, action, "dump is empty")
        try:
            zone = self._zone_from_dump(text)
        except ZoneDecodeError as exc:
            return _fail(spec, action, str(exc))
        expected = payload.get("zone")
        if isinstance(expected, str) and expected.strip():
            expected = expected.strip().rstrip(".")
            if expected != zone:
                return _fail(
                    spec,
                    action,
                    f"dump holds zone {zone!r}, args.zone said {expected!r}",
                )
        include_control = bool(payload.get("include_control"))
        report = decoder.decode_axfr(text, zone, include_control=include_control)
        output: dict[str, Any] = {
            "zone": zone,
            "serial": report["serial"],
            "counts": report["counts"],
            "actions": report["actions"],
            "samples": {
                "ips": report["ips"][:SAMPLE_INDICATORS],
                "domains": report["domains"][:SAMPLE_INDICATORS],
            },
            "caveats": list(CAVEATS),
        }
        if payload.get("outdir"):
            output["files"] = _write_lists(Path(str(payload["outdir"])), report)
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=_bounded(output),
            error=None,
        )

    @staticmethod
    def _zone_from_dump(text: str) -> str:
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 7 and parts[2] == "IN" and parts[3] == "SOA":
                owner = parts[0].rstrip(".")
                if owner.endswith(".rpz.threatstop.local"):
                    return owner
        raise ZoneDecodeError("no SOA for a *.rpz.threatstop.local zone in dump")

    # ------------------------------------------------------------------
    # fetch / status (dispatch tier)

    def _dispatched(
        self, spec: ArmSpec, action: str, payload: dict
    ) -> Result:
        zone_arg = payload.get("zone")
        master_arg = payload.get("master")
        zone = (str(zone_arg).strip().rstrip(".") if zone_arg else None) or (
            _env(ENV_ZONE) or ""
        )
        master = (str(master_arg).strip() if master_arg else None) or (
            _env(ENV_MASTER) or ""
        )
        port = payload.get("port")
        if zone_refusal(zone):
            return _fail(spec, action, zone_refusal(zone) or "zone refused")
        if master_refusal(master):
            return _fail(spec, action, master_refusal(master) or "master refused")
        if port_refusal(port):
            return _fail(spec, action, port_refusal(port) or "port refused")
        port = int(port) if port is not None else DEFAULT_PORT

        binary = resolve_dig()
        if binary is None:
            return _fail(
                spec,
                action,
                "dig binary not found (set RPZDECODER_DIG_BIN or install dig)",
            )

        target = f"//{master}:{port}/{zone}"
        scope, dispatch_refusal = authorize(ENV_DISPATCH_SCOPE, action, target)
        if scope is None:
            return _fail(spec, action, dispatch_refusal or "dispatch not armed")
        log_dispatch(ARM_ID, action, scope, target)

        secret: str | None = None
        query = ["soa"] if action == "status" else ["axfr"]
        cmd = [
            binary,
            f"@{master}",
            "-p",
            str(port),
            zone,
            *query,
            "+tcp",
            DIG_QUERY_TIMEOUT,
            "+tries=1",
            "+noall",
            "+answer",
        ]
        if action == "fetch":
            keyfile = Path(str(payload["keyfile"]))
            key_refusal = keyfile_refusal(keyfile)
            if key_refusal:
                return _fail(spec, action, key_refusal)
            lines = [
                line.strip()
                for line in keyfile.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            key_name, secret = lines[0], lines[1]
            cmd = [binary, "-y", f"hmac-md5:{key_name}:{secret}", *cmd[1:]]

        dump_bytes = b""
        stdout_text = ""
        try:
            if action == "fetch":
                outdir = (
                    Path(str(payload["outdir"]))
                    if payload.get("outdir")
                    else Path(".")
                )
                outdir.mkdir(parents=True, exist_ok=True)
                raw_path = outdir / "zone-axfr.txt"
                with raw_path.open("wb") as handle:
                    proc = subprocess.run(
                        cmd,
                        stdout=handle,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.DEVNULL,
                        timeout=self.timeout,
                        check=False,
                    )
                stderr_text = (proc.stderr or b"").decode("utf-8", errors="replace")
                dump_bytes = raw_path.read_bytes()
            else:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.timeout,
                    check=False,
                )
                stdout_text = proc.stdout or ""
                stderr_text = proc.stderr or ""
        except subprocess.TimeoutExpired:
            return _fail(spec, action, f"{action} timed out after {self.timeout}s")
        except OSError as exc:
            return _fail(spec, action, f"dig failed to run: {exc}")

        stdout_text = _scrub(stdout_text, secret)
        stderr_text = _scrub(stderr_text, secret)
        if proc.returncode != 0 or "Transfer failed" in stdout_text:
            detail = (stderr_text or stdout_text or f"{action} failed").strip()
            return _fail(spec, action, detail[:MAX_OUTPUT_CHARS])

        if action == "status":
            return self._status(spec, action, zone, master, port, stdout_text, scope, target)

        # fetch: decode the captured dump and write the raw lists.
        try:
            text = decoder.read_dump_bytes(dump_bytes, zone)
            report = decoder.decode_axfr(text, zone)
        except ZoneDecodeError as exc:
            return _fail(spec, action, str(exc))
        output: dict[str, Any] = {
            "zone": zone,
            "master": master,
            "port": port,
            "serial": report["serial"],
            "counts": report["counts"],
            "actions": report["actions"],
            "samples": {
                "ips": report["ips"][:SAMPLE_INDICATORS],
                "domains": report["domains"][:SAMPLE_INDICATORS],
            },
            "dispatch": stamp(scope, target),
            "caveats": list(CAVEATS),
        }
        if payload.get("outdir"):
            output["files"] = _write_lists(Path(str(payload["outdir"])), report)
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=_bounded(output),
            error=None,
        )

    def _status(
        self,
        spec: ArmSpec,
        action: str,
        zone: str,
        master: str,
        port: int,
        stdout_text: str,
        scope: Any,
        target: str,
    ) -> Result:
        serial = None
        refresh = None
        for line in stdout_text.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[2] == "IN" and parts[3] == "SOA":
                try:
                    serial = int(parts[6])
                    refresh = int(parts[7])
                except (IndexError, ValueError):
                    serial = refresh = None
        output: dict[str, Any] = {
            "zone": zone,
            "master": master,
            "port": port,
            "serial": serial,
            "refresh": refresh,
            "dispatch": stamp(scope, target),
        }
        return Result(
            ok=True, arm_id=spec.id, action=action, output=output, error=None
        )

    # ------------------------------------------------------------------

    def _list_tools(self, spec: ArmSpec, action: str) -> Result:
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={
                "tools": [
                    {"name": "decode", "args": sorted(ARG_KEYS["decode"])},
                    {"name": "fetch", "args": sorted(ARG_KEYS["fetch"])},
                    {"name": "status", "args": sorted(ARG_KEYS["status"])},
                ],
                "caveats": list(CAVEATS),
                "arming": ARMING,
            },
            error=None,
        )


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _scrub(text: str, secret: str | None) -> str:
    if secret and secret in text:
        text = text.replace(secret, "[REDACTED]")
    return text


def _write_lists(outdir: Path, report: dict[str, Any]) -> dict[str, str]:
    outdir.mkdir(parents=True, exist_ok=True)
    ips_path = outdir / "ips.txt"
    domains_path = outdir / "domains.txt"
    ndjson_path = outdir / "indicators.ndjson"
    ips_path.write_text("\n".join(report["ips"]) + "\n", encoding="utf-8")
    domains_path.write_text("\n".join(report["domains"]) + "\n", encoding="utf-8")
    ndjson_path.write_text("\n".join(report["ndjson"]) + "\n", encoding="utf-8")
    return {
        "ips": str(ips_path),
        "domains": str(domains_path),
        "ndjson": str(ndjson_path),
    }


def _bounded(output: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(output)
    if len(text) > MAX_OUTPUT_CHARS:
        trimmed = dict(output)
        samples = output.get("samples", {})
        trimmed["samples"] = {
            "ips": samples.get("ips", [])[:5],
            "domains": samples.get("domains", [])[:5],
        }
        trimmed["truncated"] = True
        return trimmed
    return output


def _fail(spec: ArmSpec, action: str, error: str) -> Result:
    return Result(
        ok=False,
        arm_id=spec.id,
        action=action,
        output=None,
        error=redact(error[:MAX_OUTPUT_CHARS]),
    )
