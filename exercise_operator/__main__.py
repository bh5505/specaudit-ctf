"""Installed-wheel, operator-only challenge inventory, packet, rehearsal and grading."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import secrets
import stat
import sys
import tempfile
from importlib.resources import files
from pathlib import Path

from extension.contract import Extension
from extension.dispatch import dispatch_range
from extension.encode import artifact_filename
from score.grading import GradingError, grade_files, load_findings_document

SCHEMA = "specaudit.ctf.exercise-operator.v1"
FIXTURES = {
    "telecom-aws-01-reachability": ("tf_s3_public_access",),
    "telecom-aws-02-iam-s3-misconfig": ("tf_iam_open", "tf_s3_public_access"),
    "telecom-aws-03-iam-privesc": ("tf_iam_assume_role", "tf_iam_external_trust"),
    "telecom-aws-04-network-exposure": ("tf_sg_open_ingress", "tf_s3_policy_blocked_trap"),
    "telecom-aws-05-logging-gaps": ("tf_cloudtrail_disabled", "tf_s3_no_access_logging"),
    "telecom-aws-06-chain-rehearsal": ("tf_chain_ingress_role", "tf_iam_open", "tf_s3_public_access"),
    "lab-knowledge-01-attack-mapping": ("tf_s3_public_access", "tf_cloudtrail_disabled", "tf_iam_open"),
}
INPUTS = ("main.tf", "assets.json", "connectivity.json", "sast.json")
MAX_SUBMISSION_BYTES = 1_048_576


class OperatorError(ValueError):
    """A refused operator request."""


def encoded(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def contracts() -> dict[str, tuple[dict, bytes]]:
    result = {}
    for item in files("exercise_operator").joinpath("contracts").iterdir():
        if not item.name.endswith(".json"):
            continue
        name = item.name.removesuffix(".json")
        raw = item.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Path(temporary) / "expected.json"
            snapshot.write_bytes(raw)
            try:
                doc = load_findings_document(snapshot, what="packaged expected contract")
            except GradingError as exc:
                raise OperatorError(str(exc)) from exc
        if doc["track"] != name:
            raise OperatorError(f"contract identity mismatch: {name}")
        result[name] = (doc, raw)
    if not result or set(FIXTURES) != {
        name for name, (doc, _) in result.items() if doc["lane"] == "fixture-backed"
    }:
        raise OperatorError("packaged challenge inventory and fixture mapping disagree")
    return result


def select(challenge: str) -> tuple[dict, bytes]:
    try:
        return contracts()[challenge]
    except KeyError as exc:
        raise OperatorError(f"unknown shipped challenge: {challenge}") from exc


def inventory() -> dict:
    rows = []
    for name, (doc, raw) in sorted(contracts().items()):
        lane = doc["lane"]
        rows.append({
            "id": name, "lane": lane, "declared_fixtures": doc.get("fixtures", []),
            "packet_fixtures": list(FIXTURES[name]) if name in FIXTURES else [],
            "offline_packet": lane == "fixture-backed",
            "standalone_grading": True, "contract_sha256": digest(raw),
        })
    return {
        "schema": SCHEMA, "command": "inventory", "challenges": rows,
        "limitations": "Live-service and planted-code lanes need separately controlled evidence. Standalone grading does not prove target testing.",
    }


def fresh_output(path: Path) -> Path:
    # Resolve an existing operator-chosen parent (including macOS /tmp), then
    # exclusively create a private fresh child. No existing output is reused.
    absolute = path.parent.resolve() / path.name
    if absolute.is_symlink():
        raise OperatorError("output path is a symlink")
    try:
        absolute.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise OperatorError("output directory must be fresh") from exc
    except OSError as exc:
        raise OperatorError(f"cannot create output directory: {exc}") from exc
    return absolute


def write(root: Path, relative: str, payload: bytes) -> dict:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(payload)
    return {"path": relative, "sha256": digest(payload), "bytes": len(payload)}


def packet_materials(challenge: str, doc: dict) -> list[tuple[str, bytes]]:
    source = files("extension.range")
    inputs = []
    for fixture in FIXTURES[challenge]:
        for filename in INPUTS:
            try:
                data = source.joinpath(fixture, "input", filename).read_bytes()
            except OSError as exc:
                raise OperatorError(f"missing shipped fixture input: {fixture}/{filename}") from exc
            inputs.append((f"evidence/{fixture}/{filename}", data))
    brief = (
        f"# {challenge}: synthetic evidence exercise\n\n"
        "Inspect the supplied evidence files. Report each defensible finding with "
        "a key/control from the shared public candidate vocabulary, severity "
        "(critical/high/medium/low/none), rationale, and traces_to citing observable "
        "evidence. Account for negative cases and uncertainty. Do not contact live "
        "targets or use real credentials.\n\n"
        "Copy findings-template.json outside this packet as your submission. The "
        "operator retains the grading contract separately. The shared vocabulary "
        "includes nonapplicable candidates; select only evidence-supported rows.\n\n"
        f"Track: {challenge}\nFixtures: {', '.join(FIXTURES[challenge])}\n"
        f"Seed: {doc.get('seed', 123)}\n"
    ).encode("utf-8")
    template = encoded({
        "track": challenge, "seed": doc.get("seed", 123),
        "fixtures": list(FIXTURES[challenge]), "total": 0, "findings": [],
    })
    vocabulary = files("exercise_operator").joinpath("vocabulary.json").read_bytes()
    return [("BRIEF.md", brief), ("findings-template.json", template),
            ("candidate-vocabulary.json", vocabulary), *inputs]


def packet_manifest(challenge: str, materials: list[tuple[str, bytes]]) -> dict:
    return {
        "schema": SCHEMA, "command": "prepare", "challenge": challenge,
        "status": "complete",
        "files": [
            {"path": name, "sha256": digest(data), "bytes": len(data)}
            for name, data in materials
        ],
        "limitations": "Exported packet only; the operator must enforce OS identity, filesystem isolation and access control.",
    }


def prepare(challenge: str, destination: Path) -> dict:
    doc, contract = select(challenge)
    if doc["lane"] != "fixture-backed":
        raise OperatorError(f"{challenge} is {doc['lane']}; offline packet preparation is unsupported")
    materials = packet_materials(challenge, doc)
    root = fresh_output(destination)
    entries = [write(root, name, data) for name, data in materials]
    write(root, "manifest.json", encoded(packet_manifest(challenge, materials)))
    return {
        "schema": SCHEMA, "command": "prepare", "challenge": challenge,
        "status": "complete", "packet": str(root),
        "files": len(entries), "operator_contract_sha256": digest(contract),
    }


def bounded_regular(path: Path) -> bytes:
    if not hasattr(os, "O_NONBLOCK") or not hasattr(os, "O_NOFOLLOW"):
        raise OperatorError("bounded nofollow file reads unavailable")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SUBMISSION_BYTES:
                raise OperatorError("input must be a bounded regular file")
            chunks = []
            remaining = MAX_SUBMISSION_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ) or remaining == 0:
                raise OperatorError("input changed or exceeds byte limit")
            return b"".join(chunks)
        finally:
            os.close(fd)
    except OSError as exc:
        raise OperatorError(f"input unreadable: {exc}") from exc


def strict_json(raw: bytes) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError("non-finite JSON number")

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON number")
        return number

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=invalid_constant, parse_float=finite_float)
        def check(node: object, depth: int = 0) -> None:
            if depth > 64:
                raise ValueError("JSON nesting limit exceeded")
            if isinstance(node, dict):
                for child in node.values():
                    check(child, depth + 1)
            elif isinstance(node, list):
                for child in node:
                    check(child, depth + 1)
        check(value)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise OperatorError(f"invalid submission JSON: {exc}") from exc
    return value


def rehearse(destination: Path) -> dict:
    root = fresh_output(destination)
    artifacts = root / "artifacts"
    artifacts.mkdir(mode=0o700)
    outcome = dispatch_range(
        Extension(), seed=123, arm_ids=[],
        attempt_id="attempt-" + secrets.token_hex(32), artifact_dir=str(artifacts),
    )
    entries = []
    report_error = None
    report_status = None
    if outcome.envelope is not None:
        entries.append(write(root, "range-envelope.json", encoded(outcome.envelope)))
        for claim in outcome.envelope.get("artifacts", []):
            if claim.get("kind") != "range-report":
                continue
            try:
                name = artifact_filename(claim["digest"])
                raw = bounded_regular(artifacts / name)
                if "sha256:" + digest(raw) != claim["digest"]:
                    raise OperatorError("range artifact digest mismatch")
                report = strict_json(raw)
                if not isinstance(report, dict) or not isinstance(report.get("fixtures"), list):
                    raise OperatorError("range artifact has no fixture roster")
                report_status = report.get("status")
                entries.append({"path": f"artifacts/{name}", "sha256": digest(raw), "bytes": len(raw)})
            except (OperatorError, OSError) as exc:
                report_error = str(exc)
    result = {
        "schema": SCHEMA, "command": "rehearse",
        "status": "complete" if outcome.exit_code == 0 and report_status == "complete" and report_error is None else "failed",
        "exit_code": outcome.exit_code, "files": entries,
        "range_report_status": report_status,
        "scope": "full shipped synthetic fixture roster; lifecycle-only; zero arms",
        "limitations": "The full range runs, including fixtures beyond any one challenge. A lifecycle match is not a learner finding or live-target validation.",
    }
    if outcome.stderr_line or report_error:
        result["reason"] = report_error or outcome.stderr_line
    write(root, "manifest.json", encoded(result))
    return result


def packet_binding(packet: Path, challenge: str) -> dict:
    try:
        root_info = packet.lstat()
    except OSError as exc:
        raise OperatorError(f"packet root unreadable: {exc}") from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise OperatorError("packet root must be a real directory")
    doc, _ = select(challenge)
    if doc["lane"] != "fixture-backed":
        raise OperatorError("packet binding requires a fixture-backed challenge")
    materials = packet_materials(challenge, doc)
    raw = bounded_regular(packet / "manifest.json")
    if raw != encoded(packet_manifest(challenge, materials)):
        raise OperatorError("packet manifest differs from packaged source")
    known = {name for name, _ in materials} | {"manifest.json"}
    pending = [packet]
    seen = set()
    visited = 0
    while pending:
        directory = pending.pop()
        if len(directory.relative_to(packet).parts) > 4:
            raise OperatorError("packet directory depth exceeded")
        try:
            with os.scandir(directory) as scan:
                for item in scan:
                    visited += 1
                    if visited > 64:
                        raise OperatorError("packet inventory limit exceeded")
                    relative = str(Path(item.path).relative_to(packet))
                    if item.is_symlink():
                        raise OperatorError("packet contains a symlink")
                    if item.is_dir(follow_symlinks=False):
                        pending.append(Path(item.path))
                    elif item.is_file(follow_symlinks=False):
                        seen.add(relative)
                    else:
                        raise OperatorError("packet contains a non-regular entry")
        except OSError as exc:
            raise OperatorError(f"packet unreadable: {exc}") from exc
    if seen != known:
        raise OperatorError("packet file inventory changed")
    for name, expected in materials:
        if bounded_regular(packet / name) != expected:
            raise OperatorError(f"packet entry changed: {name}")
    return {"manifest_sha256": digest(raw), "verified_files": len(materials),
            "source": "recomputed from packaged challenge and fixture bytes"}


def grade(challenge: str, found_path: Path, destination: Path, packet: Path | None = None) -> dict:
    doc, contract = select(challenge)
    binding = None
    if packet is not None:
        packet_root = packet.resolve()
        if found_path.resolve().is_relative_to(packet_root) or destination.resolve().is_relative_to(packet_root):
            raise OperatorError("submission and operator report must be outside the learner packet")
        binding = packet_binding(packet, challenge)
    found = bounded_regular(found_path)
    try:
        strict_json(found)
    except OperatorError as exc:
        preflight_error = str(exc)
    else:
        preflight_error = None
    with tempfile.TemporaryDirectory() as temporary:
        submission = Path(temporary) / "found.json"
        expected = Path(temporary) / "expected.json"
        submission.write_bytes(found)
        expected.write_bytes(contract)
        try:
            if preflight_error:
                raise GradingError(preflight_error)
            verdict = grade_files(submission, expected)
            status = "passed" if verdict["passed"] else "failed"
            reason = None
        except (GradingError, UnicodeError) as exc:
            verdict, status, reason = None, "refused", str(exc)
    root = fresh_output(destination)
    entries = [write(root, "submission.json", found)]
    if verdict is not None:
        entries.append(write(root, "grade.json", encoded(verdict)))
    result = {
        "schema": SCHEMA, "command": "grade", "challenge": challenge,
        "lane": doc["lane"], "status": status,
        "submission_sha256": digest(found), "contract_sha256": digest(contract),
        "packet_binding": binding, "files": entries,
        "limitations": "Exact finding-key coverage and owned fields only; seed, fixture identity, evidence truth, source authenticity and live execution are not verified.",
    }
    if reason is not None:
        result["reason"] = reason
    write(root, "manifest.json", encoded(result))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m exercise_operator")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inventory")
    packet = commands.add_parser("prepare")
    packet.add_argument("challenge")
    packet.add_argument("--out", type=Path, required=True)
    trial = commands.add_parser("rehearse")
    trial.add_argument("--out", type=Path, required=True)
    grading = commands.add_parser("grade")
    grading.add_argument("challenge")
    grading.add_argument("--found", type=Path, required=True)
    grading.add_argument("--out", type=Path, required=True)
    grading.add_argument("--packet", type=Path, help="verify an immutable prepared learner packet")
    ns = parser.parse_args(argv)
    try:
        if ns.command == "inventory":
            result = inventory()
        elif ns.command == "prepare":
            result = prepare(ns.challenge, ns.out)
        elif ns.command == "rehearse":
            result = rehearse(ns.out)
        else:
            result = grade(ns.challenge, ns.found, ns.out, ns.packet)
    except (OperatorError, OSError) as exc:
        print(f"exercise_operator: {exc}", file=sys.stderr)
        return 2
    print(encoded(result).decode("utf-8"), end="")
    if result.get("status") == "refused":
        return 2
    return 0 if result.get("status") in (None, "complete", "passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
