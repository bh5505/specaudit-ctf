"""Private, durable synthetic-range operator sessions over existing admission paths.

This module never infers authority from a catalog row or caller-edited plan.
Only fixed local recipes are accepted, and each actual invocation goes through
extension.dispatch with a fresh Mode-A attempt and verified artifact bytes.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

from exercise_operator.__main__ import (
    OperatorError, bounded_regular, contracts, encoded, fresh_output,
    grade as grade_challenge, inventory as challenge_inventory,
    prepare as prepare_challenge, strict_json, write,
)
from extension.arms.learning_operator import ACTIONS, _sample
from extension.contract import Extension
from extension.dispatch import dispatch_invoke, dispatch_range
from extension.encode import artifact_filename
from extension.envelopes import parse_execution_result
from extension.invoke_profiles import INVOKE_PROFILES, invoke_profile
from .synthetic_readers import recipes as reader_recipes

SCHEMA = "specaudit.ctf.operator-session.v1"
MAX_PLAN_BYTES = 256_000
LEARNING = {action.replace("_", "-"): action for action in ACTIONS}
READERS = reader_recipes()
DEFAULT_LOCAL = ("range", "asset-recon", "stix-lookup", *LEARNING, *READERS)
LOCAL = (*DEFAULT_LOCAL, "http-target")
PACKAGE_ROOT = Path(__file__).resolve().parents[1]


class SessionError(ValueError):
    """A refused plan, changed run, or unsafe operation."""


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def recipe(identifier: str) -> tuple[str, str, dict]:
    """Return only bundled offline evidence and a fixed admitted action."""
    if identifier in LEARNING:
        return "learning-operator", LEARNING[identifier], _sample(LEARNING[identifier])
    if identifier == "stix-lookup":
        from extension.arms.attackstix.policy import demo_bundle_path
        return "attack-stix-data", "technique", {"bundle": str(demo_bundle_path()), "id": "T1552"}
    if identifier == "asset-recon":
        from extension.arms.assetrecon import arm
        fixture = Path(arm.__file__).parent / "fixtures"
        return "asset-recon", "discover", {
            "seeds": {"domains": ["example.test"]},
            "organization_hints": ["Example Research"],
            "limits": {"max_depth": 5},
            "fixtures": [{"source": source, "path": str(fixture / filename)} for source, filename in (
                ("crtsh", "ct.json"), ("dns", "dns.json"),
                ("registry", "registry.json"), ("shodan", "shodan.json"))],
        }
    if identifier in READERS:
        return reader_recipes()[identifier]
    raise SessionError(f"unknown local scenario: {identifier}")


def _portable(value: Any) -> Any:
    """Plan references a packaged source identity, never an installation path."""
    if isinstance(value, str):
        path = Path(value)
        if path.is_absolute() and path.exists() and path.is_relative_to(PACKAGE_ROOT):
            return "fixture://" + str(path.relative_to(PACKAGE_ROOT))
    if isinstance(value, dict):
        return {key: _portable(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_portable(child) for child in value]
    return value


def _stage(root: Path, identifier: str, value: Any, receipts: list[dict]) -> Any:
    if isinstance(value, str) and value.startswith("fixture://"):
        relative = value.removeprefix("fixture://")
        source = PACKAGE_ROOT / relative
        if not source.exists() or not source.resolve().is_relative_to(PACKAGE_ROOT):
            raise SessionError("packaged fixture is unavailable")
        if source.is_dir():
            paths = sorted(source.rglob("*"))
            if len(paths) > 64 or any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in paths):
                raise SessionError("bundled fixture directory has unsafe entries")
            copied = 0
            for path in paths:
                if path.is_file():
                    copied += path.stat().st_size
                    if copied > 1_048_576:
                        raise SessionError("bundled fixture directory exceeds byte limit")
                    output = f"targets/{identifier}/{relative}/{path.relative_to(source)}"
                    receipt = _record(root, output, path.read_bytes())
                    receipt["source"] = value + "/" + str(path.relative_to(source))
                    receipts.append(receipt)
            if not receipts:
                raise SessionError("bundled fixture directory contains no files")
            return str(root / "targets" / identifier / relative)
        if not source.is_file():
            raise SessionError("bundled fixture is not a regular file")
        raw = source.read_bytes()
        if len(raw) > 1_048_576:
            raise SessionError("bundled fixture exceeds byte limit")
        output = f"targets/{identifier}/{relative}"
        receipt = _record(root, output, raw)
        receipt["source"] = value
        receipts.append(receipt)
        return str(root / output)
    if isinstance(value, dict):
        return {key: _stage(root, identifier, child, receipts) for key, child in value.items()}
    if isinstance(value, list):
        return [_stage(root, identifier, child, receipts) for child in value]
    return value


def _rebind(root: Path, identifier: str, value: Any) -> Any:
    """Reconstruct executed paths from the persisted plan and run location."""
    if isinstance(value, str) and value.startswith("fixture://"):
        return str(root / "targets" / identifier / value.removeprefix("fixture://"))
    if isinstance(value, dict):
        return {key: _rebind(root, identifier, child) for key, child in value.items()}
    if isinstance(value, list):
        return [_rebind(root, identifier, child) for child in value]
    return value


def make_plan(selected: list[str] | None = None) -> dict:
    names = selected or list(DEFAULT_LOCAL)
    if len(names) > len(LOCAL) or len(set(names)) != len(names) or set(names) - set(LOCAL):
        raise SessionError("scenarios must be distinct shipped local scenario IDs")
    steps = []
    for identifier in names:
        if identifier in {"range", "http-target"}:
            steps.append({"id": identifier, "args": {}})
        else:
            arm_id, action, args = recipe(identifier)
            if invoke_profile(arm_id, action) is None:
                raise SessionError(f"recipe admission missing: {arm_id}.{action}")
            steps.append({"id": identifier, "args": _portable(args)})
    return {"schema": SCHEMA, "kind": "plan", "steps": steps,
            "scope": "bundled synthetic fixtures and offline evaluations; optional contained loopback target; no external provider, scanner, or model dispatch"}


def validate_plan(plan: Any) -> dict:
    if not isinstance(plan, dict) or set(plan) != {"schema", "kind", "steps", "scope"} or plan.get("schema") != SCHEMA or plan.get("kind") != "plan" or plan.get("scope") != make_plan(["range"])["scope"]:
        raise SessionError("plan schema or scope changed")
    steps = plan["steps"]
    if not isinstance(steps, list) or not steps or len(steps) > len(LOCAL):
        raise SessionError("plan needs a bounded number of fixed local steps")
    seen = set()
    for row in steps:
        if not isinstance(row, dict) or set(row) != {"id", "args"} or not isinstance(row["id"], str) or row["id"] not in LOCAL or row["id"] in seen or not isinstance(row["args"], dict):
            raise SessionError("plan step must have one distinct known ID and object args")
        identifier, args = row["id"], row["args"]
        seen.add(identifier)
        if identifier in {"range", "http-target"} and args != {}:
            raise SessionError("range and local target recipes accept no override arguments")
        if identifier in {"asset-recon", "stix-lookup", *READERS} and args != _portable(recipe(identifier)[2]):
            raise SessionError("bundled file-reading recipe paths and arguments are fixed; use the six inline review scenarios for edited inputs")
        if identifier in LEARNING:
            from extension.arms.learning_operator import MAX_ARGS_BYTES, REQUIRED, _json
            action = LEARNING[identifier]
            if set(args) - ACTIONS[action] or not REQUIRED[action] <= set(args):
                raise SessionError(f"{identifier} has unknown or missing input fields")
            try:
                if len(_json(args)) > MAX_ARGS_BYTES:
                    raise SessionError("inline inputs exceed action byte limit")
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                raise SessionError("invalid inline scenario arguments") from exc
    if len(encoded(plan)) > MAX_PLAN_BYTES:
        raise SessionError("plan exceeds 256000 bytes")
    return plan


def read_plan(path: Path) -> tuple[dict, bytes]:
    raw = bounded_regular(path)
    if len(raw) > MAX_PLAN_BYTES:
        raise SessionError("plan exceeds 256000 bytes")
    return validate_plan(strict_json(raw)), raw


def inventory() -> dict:
    """Map every surveyed row, not just the recipes that execute locally."""
    ext = Extension()
    scenario_for = {recipe(name)[0]: [] for name in DEFAULT_LOCAL if name != "range"}
    scenario_for["http-probe"] = ["http-target"]
    for name in DEFAULT_LOCAL:
        if name != "range":
            scenario_for[recipe(name)[0]].append(name)
    availability = {row["id"]: row for row in ext.availability()}
    rows = []
    for entry in ext.list_entries():
        profiles = sorted((value for value in INVOKE_PROFILES.values() if value.arm_id == entry.id),
                          key=lambda value: value.action)
        admitted = [profile.action for profile in profiles]
        local = scenario_for.get(entry.id, [])
        if entry.kind == "methodology-only":
            boundary = "methodology only; no dispatch adapter"
            operational_state = "methodology-only"
        elif local:
            boundary = ("opt-in disposable loopback listener with installed curl; no other target authority"
                        if entry.id == "http-probe" else
                        "bundled offline recipe; other actions require their own inputs and authority")
            operational_state = "opt-in-local-target" if entry.id == "http-probe" else "synthetic-ready"
        elif not admitted:
            boundary = "no admitted invoke action"
            operational_state = "external-setup"
        elif all(action in {"list_tools", "tools/list"} for action in admitted):
            boundary = "static metadata only; no operational recipe"
            operational_state = "metadata-only"
        else:
            boundary = "admitted adapter; no bundled local scenario; upstream binary, endpoint, caller evidence, or separate scope may be required"
            operational_state = "external-setup"
        rows.append({"id": entry.id, "kind": entry.kind, "tier": entry.tier,
                     "curated": entry.curated, "protocols": list(entry.protocols), "notes": entry.notes,
                     "operational_state": operational_state, "scenarios": local,
                     "admitted_actions": admitted,
                     "action_profiles": [{"action": profile.action, "default_off": profile.default_off,
                                          "synthetic_only": profile.synthetic_only,
                                          "safety_class": profile.safety_class,
                                          "side_effects": list(profile.side_effects),
                                          "approval_ref": profile.approval_ref, "roe_ref": profile.roe_ref}
                                         for profile in profiles],
                     "installed_probe": availability.get(entry.id, {}).get("installed"),
                     "boundary": boundary})
    return {"schema": SCHEMA, "kind": "inventory", "local_scenarios": list(DEFAULT_LOCAL),
            "opt_in_scenarios": ["http-target"],
            "catalog": rows, "challenges": challenge_inventory()["challenges"],
            "limitations": "Catalog admission or installation does not grant target authority. Five live-service and one planted-code challenge require separately operated targets/evidence; seven fixture-backed challenges support offline packets and exact comparison. The opt-in http-target starts a disposable loopback server and calls installed curl; no external scanners or providers run in the default suite."}


def _record(root: Path, relative: str, raw: bytes) -> dict:
    return write(root, relative, raw)


def _artifact(root: Path, name: str, claim: dict) -> tuple[dict, Any]:
    try:
        filename = artifact_filename(claim["digest"])
        relative = f"steps/{name}/artifacts/{filename}"
        raw = bounded_regular(root / relative)
        if sha(raw) != claim["digest"][7:]:
            raise SessionError("artifact digest mismatch")
        parsed = strict_json(raw)
        return {"path": relative, "sha256": sha(raw), "bytes": len(raw), "kind": claim["kind"]}, parsed
    except (KeyError, TypeError, OSError, OperatorError) as exc:
        raise SessionError("claimed artifact missing, malformed, or changed") from exc


def _persist(root: Path, journal: dict) -> None:
    raw = encoded(journal)
    temporary = root / (".journal-" + secrets.token_hex(8))
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, root / "journal.json")


def run(destination: Path, plan: dict, *, plan_bytes: bytes | None = None) -> dict:
    validate_plan(plan)
    root = fresh_output(destination)
    root.chmod(0o700)
    plan_raw = plan_bytes if plan_bytes is not None else encoded(plan)
    _record(root, "plan.json", plan_raw)
    journal: dict[str, Any] = {"schema": SCHEMA, "kind": "run", "state": "running",
        "plan_sha256": sha(plan_raw), "execution_root": str(root), "steps": [], "status": "incomplete",
        "limitations": "Local file hashes detect read-back changes, not producer authentication, external custody, target contact, or effective controls. Edited inline review inputs are caller declarations."}
    _persist(root, journal)
    ext = Extension()
    for step in plan["steps"]:
        identifier = step["id"]
        directory = root / "steps" / identifier / "artifacts"
        directory.mkdir(mode=0o700, parents=True)
        attempt = "attempt-" + secrets.token_hex(32)
        inputs: list[dict] = []
        args = _stage(root, identifier, step["args"], inputs) if identifier in {"asset-recon", "stix-lookup", *READERS} else step["args"]
        producer_stderr = io.StringIO()
        target_metadata = None
        with contextlib.redirect_stderr(producer_stderr):
            if identifier == "range":
                request_doc = {"kind": "synthetic-range", "seed": 123, "arm_ids": []}
                request_receipt = _record(root, f"steps/{identifier}/request.json", encoded(request_doc))
                outcome = dispatch_range(ext, seed=123, arm_ids=[], attempt_id=attempt, artifact_dir=str(directory))
            elif identifier == "http-target":
                from .local_target import target

                with target() as (arm_id, action, target_args, target_metadata):
                    request_doc = {"arm_id": arm_id, "action": action, "args": target_args}
                    request_receipt = _record(root, f"steps/{identifier}/request.json", encoded(request_doc))
                    outcome = dispatch_invoke(ext, arm_id=arm_id, action=action, args=target_args,
                                              attempt_id=attempt, artifact_dir=str(directory))
            else:
                arm_id, action, _ = recipe(identifier)
                request_doc = {"arm_id": arm_id, "action": action, "args": args}
                request_receipt = _record(root, f"steps/{identifier}/request.json", encoded(request_doc))
                outcome = dispatch_invoke(ext, arm_id=arm_id, action=action, args=args,
                                          attempt_id=attempt, artifact_dir=str(directory))
        row: dict[str, Any] = {"id": identifier, "attempt_id": attempt,
                               "exit_code": outcome.exit_code, "status": "failed", "artifacts": [], "inputs": inputs,
                               "plan_request_sha256": sha(encoded(step["args"])), "request": request_receipt}
        if identifier == "http-target":
            row["request_sha256"] = sha(encoded(target_args))
        elif identifier != "range":
            row["request_sha256"] = sha(encoded(args))
        if target_metadata is not None:
            body = target_metadata.pop("response_body")
            row["target_source"] = _record(root, f"targets/{identifier}/canary.json", body.encode("utf-8"))
            row["target"] = target_metadata
        stderr_raw = producer_stderr.getvalue().encode("utf-8")
        if stderr_raw:
            if len(stderr_raw) > 16_384:
                row["reason"] = "producer stderr exceeded custody byte limit"
            else:
                row["producer_stderr"] = _record(root, f"steps/{identifier}/producer-stderr.txt", stderr_raw)
        if outcome.envelope is not None:
            relative = f"steps/{identifier}/envelope.json"
            row["envelope"] = _record(root, relative, encoded(outcome.envelope))
            parsed = parse_execution_result(outcome.envelope)
            row["dispatch_status"] = parsed.status
            try:
                claims = outcome.envelope.get("artifacts", [])
                if not isinstance(claims, list) or len(claims) != 1:
                    raise SessionError("exactly one report artifact required")
                for claim in claims:
                    receipt, report = _artifact(root, identifier, claim)
                    row["artifacts"].append(receipt)
                    row["report_kind"] = receipt["kind"]
                    row["assessment"] = _assessment(identifier, report, target_metadata)
                if outcome.exit_code == 0 and parsed.schema_ok and parsed.status == "complete" and "reason" not in row:
                    row["status"] = "complete"
            except SessionError as exc:
                row["reason"] = str(exc)
        else:
            row["reason"] = "pre-dispatch attempt/artifact refusal"
        if outcome.stderr_line and row["status"] != "complete":
            row.setdefault("reason", "admitted action failed; inspect retained envelope")
        journal["steps"].append(row)
        _persist(root, journal)
    journal["state"] = "closed"
    journal["status"] = "complete" if all(row["status"] == "complete" for row in journal["steps"]) else "failed"
    _persist(root, journal)
    return {"schema": SCHEMA, "kind": "run", "run_dir": str(root),
            "status": journal["status"], "steps": [{"id": row["id"], "status": row["status"],
            "assessment_type": row.get("assessment", {}).get("type"),
            "reason": row.get("reason")} for row in journal["steps"]]}


def _assessment(identifier: str, report: Any, target_metadata: dict | None = None) -> dict:
    if not isinstance(report, dict):
        raise SessionError("report artifact is not a JSON object")
    if identifier == "range":
        if not isinstance(report.get("fixtures"), list):
            raise SessionError("range report has no fixture roster")
        return {"type": "synthetic-lifecycle", "status": report.get("status"),
                "fixtures": len(report["fixtures"]), "matched": sum(row.get("matched_expected") is True for row in report["fixtures"])}
    if identifier in LEARNING:
        assessment = report.get("assessment")
        if not isinstance(assessment, dict):
            raise SessionError("learning report lacks an assessment")
        return {"type": "offline-review", "workflow": LEARNING[identifier],
                "result": assessment, "source_class": report.get("source_class")}
    if identifier == "http-target":
        if not isinstance(target_metadata, dict) or target_metadata.get("cleanup") != "stopped":
            raise SessionError("local target cleanup was not verified")
        try:
            observed = strict_json(report["output"].encode("utf-8"))
            if (observed["status"] != 200 or sha(observed["body_head"].encode("utf-8")) != target_metadata["body_sha256"]
                    or report["dispatch"]["target"] != target_metadata["url"]
                    or {"method": "GET", "path": "/ctf/status", "status": 200} not in target_metadata["requests"]):
                raise SessionError("target response, receipt, or request did not match synthetic canary")
        except (KeyError, TypeError, AttributeError, OperatorError) as exc:
            raise SessionError("target response lacks a verified canary") from exc
        return {"type": "contained-loopback-target", "status": 200,
                "body_sha256": target_metadata["body_sha256"], "requests": target_metadata["requests"],
                "cleanup": "stopped"}
    return {"type": "offline-adapter", "status": report.get("status"),
            "result_sha256": sha(encoded(report)), "result_bytes": len(encoded(report)),
            "summary": {key: report[key] for key in ("count_matched", "counts", "requests", "reason", "attack_id", "name") if key in report}}


def _files(root: Path) -> set[str]:
    """List a bounded tree without following symlinks or special entries."""
    names: set[str] = set()
    queue = [(root, 0)]
    visited = 0
    while queue:
        directory, depth = queue.pop()
        if depth > 12:
            raise SessionError("run directory depth exceeds limit")
        with os.scandir(directory) as scan:
            for entry in scan:
                visited += 1
                if visited > 512 or entry.is_symlink():
                    raise SessionError("run inventory limit or symlink encountered")
                if entry.is_dir(follow_symlinks=False):
                    queue.append((Path(entry.path), depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    names.add(str(Path(entry.path).relative_to(root)))
                else:
                    raise SessionError("run contains a non-regular entry")
    return names


def _verify(root: Path) -> tuple[dict, dict]:
    try:
        return _verify_checked(root)
    except (KeyError, AttributeError, IndexError, TypeError) as exc:
        raise SessionError("malformed run journal or receipt") from exc


def _verify_checked(root: Path) -> tuple[dict, dict]:
    if root.is_symlink() or not root.is_dir():
        raise SessionError("run must be a real directory")
    initial_files = _files(root)
    journal = strict_json(bounded_regular(root / "journal.json"))
    if not isinstance(journal, dict) or journal.get("schema") != SCHEMA or journal.get("kind") != "run":
        raise SessionError("run journal schema mismatch")
    plan_raw = bounded_regular(root / "plan.json")
    if sha(plan_raw) != journal.get("plan_sha256"):
        raise SessionError("plan bytes changed")
    plan = validate_plan(strict_json(plan_raw))
    original = journal.get("execution_root")
    if not isinstance(original, str) or not Path(original).is_absolute() or ".." in Path(original).parts:
        raise SessionError("run execution root is invalid")
    steps = journal.get("steps")
    if not isinstance(steps, list) or len(steps) > len(plan["steps"]):
        raise SessionError("run step roster changed")
    attempts = [row.get("attempt_id") for row in steps if isinstance(row, dict)]
    if len(attempts) != len(steps) or len(set(attempts)) != len(attempts):
        raise SessionError("run attempt identity changed or repeated")
    allowed = {"plan.json", "journal.json"}
    for request, row in zip(plan["steps"], steps):
        if not isinstance(row, dict) or row.get("id") != request["id"] or not isinstance(row.get("artifacts"), list):
            raise SessionError("run step identity changed")
        name = row["id"]
        if row.get("plan_request_sha256") != sha(encoded(request["args"])):
            raise SessionError("step plan input identity changed")
        request_receipt = row.get("request")
        if not isinstance(request_receipt, dict):
            raise SessionError("retained dispatch request is missing")
        request_path = f"steps/{name}/request.json"
        if request_receipt.get("path") != request_path:
            raise SessionError("dispatch request path changed")
        request_raw = bounded_regular(root / request_path)
        if sha(request_raw) != request_receipt.get("sha256") or len(request_raw) != request_receipt.get("bytes"):
            raise SessionError("dispatch request bytes changed")
        request_doc = strict_json(request_raw)
        allowed.add(request_path)
        if name != "range":
            if name == "http-target":
                target = row.get("target")
                if not isinstance(target, dict) or not isinstance(target.get("url"), str):
                    raise SessionError("local target request binding missing")
                bound = {"url": target["url"], "headers": {}}
            else:
                bound = _rebind(Path(original), name, request["args"]) if name in {"asset-recon", "stix-lookup", *READERS} else request["args"]
            if sha(encoded(bound)) != row.get("request_sha256"):
                raise SessionError("dispatched request differs from plan and staged inputs")
            arm_id, action, _ = ("http-probe", "probe", {}) if name == "http-target" else recipe(name)
            if request_doc != {"arm_id": arm_id, "action": action, "args": bound}:
                raise SessionError("retained request differs from admitted recipe")
        elif request_doc != {"kind": "synthetic-range", "seed": 123, "arm_ids": []}:
            raise SessionError("retained range request changed")
        artifact_dir = root / "steps" / name / "artifacts"
        if artifact_dir.is_symlink() or not artifact_dir.is_dir():
            raise SessionError("artifact directory changed")
        expected_sources = []
        def collect(value: Any) -> None:
            if isinstance(value, str) and value.startswith("fixture://"):
                expected_sources.append(value)
            elif isinstance(value, dict):
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)
        if name in {"asset-recon", "stix-lookup", *READERS}:
            collect(request["args"])
        inputs = row.get("inputs")
        if not isinstance(inputs, list) or any(not isinstance(entry, dict) for entry in inputs):
            raise SessionError("packaged input roster changed")
        actual_sources = [entry.get("source") for entry in inputs]
        for source in expected_sources:
            if source in actual_sources:
                actual_sources.remove(source)
            else:
                directory_entries = [item for item in actual_sources if isinstance(item, str) and item.startswith(source + "/")]
                if not directory_entries:
                    raise SessionError("packaged input directory is absent")
                for item in directory_entries:
                    actual_sources.remove(item)
        if actual_sources:
            raise SessionError("packaged input roster has unexpected sources")
        for entry in inputs:
            source = entry["source"]
            if not isinstance(source, str) or ".." in Path(source.removeprefix("fixture://")).parts:
                raise SessionError("staged input source path is unsafe")
            expected = f"targets/{name}/{source.removeprefix('fixture://')}"
            if entry.get("path") != expected:
                raise SessionError("staged input path changed")
            raw = bounded_regular(root / expected)
            if sha(raw) != entry.get("sha256") or len(raw) != entry.get("bytes"):
                raise SessionError("staged input bytes changed")
            allowed.add(expected)
        if name == "http-target":
            metadata, entry = row.get("target"), row.get("target_source")
            if not isinstance(metadata, dict) or not isinstance(entry, dict) or entry.get("path") != "targets/http-target/canary.json":
                raise SessionError("local target source receipt missing")
            raw = bounded_regular(root / entry["path"])
            if sha(raw) != entry.get("sha256") or sha(raw) != metadata.get("body_sha256") or len(raw) != entry.get("bytes"):
                raise SessionError("local target source bytes changed")
            allowed.add(entry["path"])
        if "producer_stderr" in row:
            entry = row["producer_stderr"]
            expected = f"steps/{name}/producer-stderr.txt"
            if entry.get("path") != expected:
                raise SessionError("producer stderr path changed")
            raw = bounded_regular(root / expected)
            if sha(raw) != entry.get("sha256") or len(raw) != entry.get("bytes"):
                raise SessionError("producer stderr bytes changed")
            allowed.add(expected)
        if "envelope" in row:
            entry = row["envelope"]
            expected = f"steps/{name}/envelope.json"
            if entry.get("path") != expected:
                raise SessionError("envelope path changed")
            raw = bounded_regular(root / expected)
            if sha(raw) != entry.get("sha256") or len(raw) != entry.get("bytes"):
                raise SessionError("envelope bytes changed")
            envelope = strict_json(raw)
            if envelope.get("attempt_id") != row.get("attempt_id"):
                raise SessionError("envelope attempt changed")
            if name == "range":
                capability_id = "fixture.range-observe"
            else:
                arm_id, action, _ = ("http-probe", "probe", {}) if name == "http-target" else recipe(name)
                profile = invoke_profile(arm_id, action)
                if profile is None:
                    raise SessionError("recipe admission unavailable during readback")
                capability_id = profile.capability_id
            if envelope.get("capability_id") != capability_id:
                raise SessionError("envelope capability does not match planned recipe")
            parsed = parse_execution_result(envelope)
            if parsed.status != row.get("dispatch_status"):
                raise SessionError("envelope status changed")
            allowed.add(expected)
            claims = envelope.get("artifacts", [])
            if len(claims) != len(row["artifacts"]):
                raise SessionError("artifact claim count changed")
            for claim, recorded in zip(claims, row["artifacts"]):
                receipt, report = _artifact(root, name, claim)
                if receipt != recorded:
                    raise SessionError("artifact receipt changed")
                allowed.add(receipt["path"])
                if row.get("assessment") != _assessment(name, report, row.get("target")):
                    raise SessionError("assessment differs from retained report")
            derived = "complete" if row.get("exit_code") == 0 and parsed.schema_ok and parsed.status == "complete" and len(claims) == 1 and "reason" not in row else "failed"
            if row.get("status") != derived:
                raise SessionError("step status differs from verified dispatch")
        elif row.get("status") != "failed" or row["artifacts"]:
            raise SessionError("missing envelope cannot claim success")
    if journal.get("state") == "closed":
        if len(steps) != len(plan["steps"]):
            raise SessionError("closed run is missing steps")
        derived = "complete" if all(row["status"] == "complete" for row in steps) else "failed"
        if journal.get("status") != derived:
            raise SessionError("run status differs from verified steps")
    elif journal.get("state") != "running" or journal.get("status") != "incomplete":
        raise SessionError("invalid run state")
    final_files = _files(root)
    if initial_files != final_files:
        raise SessionError("run file inventory changed during verification")
    unrecorded = final_files - allowed
    if unrecorded and journal["state"] == "closed":
        raise SessionError("closed run contains unrecorded files")
    journal["unverified_partial_files"] = len(unrecorded)
    return journal, plan


def verify_run(root: Path, *, detailed: bool = False) -> dict:
    journal, plan = _verify(root)
    rows = []
    for step in journal["steps"]:
        row = {"id": step["id"], "status": step["status"],
               "dispatch_status": step.get("dispatch_status"), "attempt_id": step["attempt_id"],
               "artifacts": step["artifacts"]}
        if detailed:
            row["assessment"] = step.get("assessment")
            row["reason"] = step.get("reason")
            if step["artifacts"]:
                claim = step["artifacts"][0]
                _, row["report"] = _artifact(root, step["id"],
                                               {"digest": "sha256:" + claim["sha256"],
                                                "kind": claim["kind"]})
            if step.get("target"):
                row["target"] = step["target"]
        rows.append(row)
    return {"schema": SCHEMA, "kind": "report" if detailed else "status",
            "verification": "retained plan, envelope, artifact hashes, artifact claims, assessments, and file inventory verified",
            "state": journal["state"], "status": journal["status"],
            "planned": len(plan["steps"]), "completed": len(rows), "steps": rows,
            "unverified_partial_files": journal["unverified_partial_files"],
            "limitations": journal["limitations"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m exercise")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inventory")
    planning = commands.add_parser("plan")
    planning.add_argument("--scenario", action="append", choices=LOCAL)
    planning.add_argument("--out", type=Path, help="exclusive editable plan file")
    running = commands.add_parser("run")
    running.add_argument("--plan", type=Path, help="bounded editable plan from plan --out")
    running.add_argument("--scenario", action="append", choices=LOCAL)
    running.add_argument("--out", type=Path, required=True, help="fresh private operator directory")
    for command in ("status", "report"):
        commands.add_parser(command).add_argument("run_dir", type=Path)
    packet = commands.add_parser("prepare")
    packet.add_argument("challenge")
    packet.add_argument("--out", type=Path, required=True)
    grading = commands.add_parser("grade")
    grading.add_argument("challenge")
    grading.add_argument("--found", type=Path, required=True)
    grading.add_argument("--out", type=Path, required=True)
    grading.add_argument("--packet", type=Path)
    ns = parser.parse_args(argv)
    try:
        if ns.command == "inventory":
            document = inventory()
        elif ns.command == "plan":
            document = make_plan(ns.scenario)
            if ns.out is not None:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(ns.out, flags, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(encoded(document))
        elif ns.command == "run":
            if ns.plan is not None and ns.scenario:
                raise SessionError("choose --plan or --scenario")
            plan, raw = read_plan(ns.plan) if ns.plan is not None else (make_plan(ns.scenario), None)
            document = run(ns.out, plan, plan_bytes=raw)
        elif ns.command in ("status", "report"):
            document = verify_run(ns.run_dir, detailed=ns.command == "report")
        elif ns.command == "prepare":
            document = prepare_challenge(ns.challenge, ns.out)
        else:
            document = grade_challenge(ns.challenge, ns.found, ns.out, ns.packet)
    except (SessionError, OperatorError, OSError, ValueError, TypeError) as exc:
        print(f"exercise: {exc}", file=sys.stderr)
        return 2
    print(encoded(document).decode("utf-8"), end="")
    if document.get("status") == "refused":
        return 2
    return 0 if document.get("status") in (None, "complete", "passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
