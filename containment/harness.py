"""Parent-side containment harness: acquire, dispatch, police, record.

``run_case`` is the unit of rehearsal. Hostile inputs are BLOCKED BEFORE
DISPATCH by ``reader_evidence.acquire`` (typed refusal reasons become the
``blocked`` outcome); admitted inputs are dispatched to a guarded child
(``python -m containment.worker``) whose audit-hook denials arrive on an
inherited pipe the parent reads. Outcomes:

* ``blocked`` -- the acquisition gate refused a hostile input (typed
  reason carried in ``CaseResult.reason``);
* ``positive`` -- arm result ok, zero child denials;
* ``refusal`` -- arm policy refused, zero child denials (a valid
  containment result: nothing escaped, nothing was faked);
* ``interruption`` -- the parent killed the child mid-run via
  ``stop_case``;
* ``cleanup-ok`` -- an admitted run left scratch byte-identical;
* ``held`` / ``control-ok`` -- canary children (enforced / control);
* failure outcomes (``child-denials``, ``canary-escaped``, ``arm-error``,
  ``timeout``, ``spawn-failure``, ``cleanup-dirty``, ``canary-leak``,
  ``gate-refused``) are never summarized as successes.

Ledger discipline: rows go to a containment-LOCAL attempt ledger file in
lane ``operator-rehearsal`` (subject ``containment:<arm>:<action>``),
NEVER to any evaluation ledger; the structured detail document lives
outside the ledger and is referenced by digest. Every recorded_at is
caller-supplied: this module never reads the clock.

On Windows the trusted acquisition gate itself is typed-refused
(``platform-unsupported``: no ``os.O_NOFOLLOW``), so admitted cases
proceed with ``gate={"refused": "platform-unsupported"}`` recorded
honestly; hostile lexical refusals (traversal, escape) still fire before
that gate. POSIX-only hostile classes (symlink-escape, device-file) are
the caller's skip decision, not hidden here.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence

from reader_evidence import AcquisitionError, AcquisitionRecord, acquire

from containment.fixtures import build_fixture
from containment.profile import OperatorProfile

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKER_MODULE = "containment.worker"
_RESULT_MARKER = "CONTAINMENT-RESULT "
_LEDGER_LANE = "operator-rehearsal"
_ASSISTANCE = "none"
_GATE_SUFFIXES = frozenset({".json", ".jsonl", ".yaml", ".yml", ".md", ".txt"})
_GATE_MAX_BYTES = 8 * 1024 * 1024
_DENIAL_PIPE_BYTES = 1 << 20
_KNOWN_EXIT_CODES = {0, 3, 4, 7}
_EXIT_CANARY_ESCAPED = 7
_FAILURE_OUTCOMES = frozenset({
    "child-denials", "canary-escaped", "arm-error", "timeout",
    "spawn-failure", "cleanup-dirty", "canary-leak", "gate-refused",
    "blocked-before-dispatch",
})


@dataclass(frozen=True)
class RosterEntry:
    """One frozen roster row: arm, action, and its path argument name.

    ``path_argument`` is None only for discovery actions (``list_tools``):
    discovery adds no path signal -- there is no input path to acquire or
    to deny -- so its smoke case skips the acquisition gate by design.
    """

    arm_id: str
    action: str
    path_argument: str | None


@dataclass(frozen=True)
class CaseResult:
    """One rehearsal case's outcome and its custody-relevant details."""

    outcome: str
    arm_id: str
    action: str
    variant: str
    reason: str | None = None
    gate: Mapping[str, Any] = field(default_factory=dict)
    denials: tuple[Mapping[str, Any], ...] = ()
    exit_code: int | None = None
    detail: Mapping[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.outcome in _FAILURE_OUTCOMES

    @property
    def attempt_class(self) -> str:
        """Ledger taxonomy class for this outcome."""
        if self.outcome == "interruption":
            return "interruption"
        if self.outcome in ("refusal", "blocked"):
            return "refusal"
        return "completion"

    @property
    def ledger_outcome(self) -> str | None:
        """Outcome string for the ledger row (None on interruption)."""
        if self.outcome == "interruption":
            return None
        if self.outcome == "blocked":
            return "blocked"
        if self.outcome == "refusal":
            return "benign"
        return self.outcome


@dataclass(frozen=True)
class GuardedRun:
    """Raw child outputs for one dispatch (pre-outcome-mapping)."""

    returncode: int | None
    result: Mapping[str, Any]
    stdout_text: str
    stderr_text: str
    denials: tuple[Mapping[str, Any], ...]


def _child_env(profile: OperatorProfile, denial_write_fd: int) -> dict[str, str]:
    env = os.environ.copy()
    # Interpreter-only PATH: the child must start, but never find host
    # tooling (mirrors the suite's hermetic-PATH promise).
    env["PATH"] = str(Path(sys.executable).parent)
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["PYTHONUTF8"] = "1"
    # No __pycache__ writes: imports of the checkout stay read-only.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["CONTAINMENT_PROFILE_JSON"] = profile.to_json()
    if os.name == "nt":
        # pass_fds is not supported on Windows; the handle VALUE is
        # inherited intact and re-opened as an fd in the child.
        import msvcrt

        os.set_inheritable(denial_write_fd, True)
        env["CONTAINMENT_DENIAL_HANDLE"] = str(int(msvcrt.get_osfhandle(denial_write_fd)))
    else:
        env["CONTAINMENT_DENIAL_FD"] = str(denial_write_fd)
    return env


def _spawn_worker(
    profile: OperatorProfile,
    job: Mapping[str, Any],
    *,
    denial_write_fd: int,
    stdin_payload: bytes | None = None,
    close_stdin: bool = True,
) -> subprocess.Popen:
    """Spawn the guarded child; the parent's pipe-write copy is closed
    before returning so the child holds the only writer. The mcp-server
    job passes ``close_stdin=False``: stdin is the MCP transport and
    stays with the caller after the job line."""

    def _job_line() -> bytes:
        return (json.dumps(dict(job), sort_keys=True) + "\n").encode("utf-8")

    popen_kwargs: dict[str, Any] = dict(
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(REPO_ROOT), env=_child_env(profile, denial_write_fd),
    )
    if os.name == "nt":
        popen_kwargs["close_fds"] = False
    else:
        popen_kwargs["pass_fds"] = (denial_write_fd,)
    proc = subprocess.Popen(
        [sys.executable, "-m", WORKER_MODULE], **popen_kwargs
    )
    try:
        if stdin_payload is None:
            stdin_payload = _job_line()
        else:
            stdin_payload = _job_line() + stdin_payload
        proc.stdin.write(stdin_payload)
        proc.stdin.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        if close_stdin:
            with contextlib.suppress(OSError):
                proc.stdin.close()
    with contextlib.suppress(OSError):
        os.close(denial_write_fd)
    return proc


def _drain_denials(read_fd: int) -> tuple[Mapping[str, Any], ...]:
    """Read the denial pipe to EOF; the child (post-close/exit) holds no
    writer, so this terminates. Oversized pipes are truncated honestly."""
    records: list[Mapping[str, Any]] = []
    total = 0
    try:
        while total <= _DENIAL_PIPE_BYTES:
            chunk = os.read(read_fd, 65_536)
            if not chunk:
                break
            total += len(chunk)
            records.extend(_parse_denial_lines(chunk))
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            os.close(read_fd)
    return tuple(records)


def _parse_denial_lines(chunk: bytes) -> list[Mapping[str, Any]]:
    records = []
    for line in chunk.decode("utf-8", errors="replace").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            row = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(row)
    return records


def _parse_result_line(stdout_text: str) -> Mapping[str, Any]:
    for line in reversed(stdout_text.splitlines()):
        if line.startswith(_RESULT_MARKER):
            try:
                row = json.loads(line[len(_RESULT_MARKER):])
                if isinstance(row, dict):
                    return row
            except json.JSONDecodeError:
                break
    return {}


def stop_case(proc: subprocess.Popen) -> None:
    """Operator stop: kill the guarded child mid-run (interrupt case)."""
    if proc.poll() is None:
        proc.kill()


def snapshot_scratch(root: Path) -> dict[str, str]:
    """Deterministic byte-state snapshot of scratch ({rel: sha256}).

    Cross-platform walk; on POSIX, ``reader_evidence.acquire_directory``
    is the custody-grade equivalent. Symlinks are refused, so a link
    planted in scratch fails the case rather than escaping the snapshot.
    """
    resolved = Path(os.path.realpath(root))
    snapshot: dict[str, str] = {}

    def walk(directory: Path) -> None:
        with os.scandir(directory) as scan:
            children = sorted(scan, key=lambda entry: entry.name)
        for child in children:
            if child.is_symlink():
                raise ValueError(f"scratch snapshot refuses symlinks: {child.path}")
            if child.is_dir(follow_symlinks=False):
                walk(Path(child.path))
                continue
            if not child.is_file(follow_symlinks=False):
                raise ValueError(f"scratch snapshot refuses non-regular entries: {child.path}")
            data = Path(child.path).read_bytes()
            relative = Path(child.path).relative_to(resolved).as_posix()
            snapshot[relative] = "sha256:" + hashlib.sha256(data).hexdigest()

    walk(resolved)
    return snapshot


@dataclass(frozen=True)
class GateOutcome:
    """The pre-dispatch acquisition gate's verdict for one case."""

    record: AcquisitionRecord | None
    refused: str | None


def _gate_acquire(profile: OperatorProfile, path_value: str) -> GateOutcome:
    """Run the trusted acquisition gate; typed refusal or bound record.

    On Windows the platform gate (``os.O_NOFOLLOW``) types
    ``platform-unsupported`` AFTER the lexical and inspection refusals;
    admitted-case callers proceed on that one reason, hostile-case
    callers treat every ``AcquisitionError`` as the expected block.
    """
    try:
        record = acquire(
            Path(path_value),
            approved_root=Path(profile.approved_root),
            allowed_suffixes=_GATE_SUFFIXES,
            max_bytes=_GATE_MAX_BYTES,
            acquired_at=datetime(1970, 1, 1),  # caller-supplied convention
        )
    except AcquisitionError as exc:
        return GateOutcome(None, exc.reason)
    return GateOutcome(record, None)


def _gate_acquire_input(profile: OperatorProfile, path_value: str) -> GateOutcome:
    """Gate one admitted case's input path.

    The file gate applies to regular files; a directory-kind input (the
    one directory arm) is admitted to dispatch ungated here -- the file
    suffix gate would refuse it for having no suffix -- and stays covered
    by the enforcer and the arm's own directory discipline.
    """
    if Path(path_value).is_dir():
        return GateOutcome(None, None)
    return _gate_acquire(profile, path_value)


def _canary_leak(profile: OperatorProfile, *texts: str) -> str | None:
    for canary in profile.canaries:
        for text in texts:
            if canary in text:
                return canary
    return None


def run_case(
    profile: OperatorProfile,
    *,
    arm_id: str,
    action: str,
    payload: Mapping[str, Any],
    hostile: str | None = None,
    variant: str = "inroot",
    mode: str = "invoke",
    kill_after: float = 0.5,
    child_timeout: float = 120.0,
) -> CaseResult:
    """Rehearse one case end to end and classify its outcome.

    ``hostile`` names an input-hostility class applied to the case's own
    path argument; the typed acquisition refusal (if any) becomes the
    ``blocked`` outcome and NO child is spawned. ``mode="interrupt"``
    spawns a ``sleep-invoke`` job and kills it mid-run via ``stop_case``;
    ``mode="cleanup-watch"`` snapshots scratch before and after an
    admitted run. ``profile.canaries`` are scanned against child output;
    any appearance is the ``canary-leak`` failure.
    """
    if hostile is not None:
        path_value = payload.get(_hostile_payload_key(payload, arm_id))
        if not isinstance(path_value, str) or not path_value:
            return CaseResult(
                "gate-refused", arm_id, action, variant,
                reason="hostile-case-has-no-path",
            )
        gate = _gate_acquire(profile, path_value)
        if gate.refused is not None:
            return CaseResult(
                "blocked", arm_id, action, variant, reason=gate.refused,
                gate={"refused": gate.refused},
                detail={"hostile": hostile, "path": path_value},
            )
        return CaseResult(
            "gate-refused", arm_id, action, variant,
            reason=f"hostile-input-admitted:{hostile}",
            gate={"record": _gate_record_dict(gate.record)},
            detail={"hostile": hostile, "path": path_value},
        )

    path_key = _hostile_payload_key(payload, arm_id)
    gate = GateOutcome(None, None)
    if action != "list_tools" and isinstance(payload.get(path_key), str):
        gate = _gate_acquire_input(profile, payload[path_key])
        if gate.refused is not None and gate.refused != "platform-unsupported":
            return CaseResult(
                "gate-refused", arm_id, action, variant, reason=gate.refused,
                gate={"refused": gate.refused},
            )

    before_scratch: dict[str, str] | None = None
    if mode == "cleanup-watch":
        before_scratch = snapshot_scratch(Path(profile.scratch_root))

    job: dict[str, Any] = {
        "kind": "invoke-arm",
        "arm_id": arm_id,
        "action": action,
        "payload": dict(payload),
    }
    if mode == "interrupt":
        job["kind"] = "sleep-invoke"
        job["delay"] = 600.0

    denial_read, denial_write = os.pipe()
    try:
        proc = _spawn_worker(profile, job, denial_write_fd=denial_write)
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.close(denial_read)
        return CaseResult(
            "spawn-failure", arm_id, action, variant, reason=type(exc).__name__,
            detail={"error": str(exc)},
        )
    try:
        if mode == "interrupt":
            time.sleep(kill_after)
            stop_case(proc)
            # communicate (not wait): the child's stdout/stderr are pipes
            # and must be drained or a chatty child deadlocks on a full
            # pipe buffer.
            stdout_bytes, stderr_bytes = proc.communicate(timeout=30.0)
        else:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=child_timeout)
    except subprocess.TimeoutExpired:
        stop_case(proc)
        stdout_bytes, stderr_bytes = proc.communicate(timeout=30.0)
        return CaseResult(
            "timeout", arm_id, action, variant, reason="child-timeout",
            denials=_drain_denials(denial_read),
            exit_code=proc.returncode,
            detail={"stdout_tail": _tail(stdout_bytes.decode("utf-8", "replace")),
                    "stderr_tail": _tail(stderr_bytes.decode("utf-8", "replace"))},
        )
    stdout_text = stdout_bytes.decode("utf-8", errors="replace")
    stderr_text = stderr_bytes.decode("utf-8", errors="replace")
    denials = _drain_denials(denial_read)
    result = _parse_result_line(stdout_text)

    leak = _canary_leak(profile, stdout_text, stderr_text)
    if leak is not None:
        return CaseResult(
            "canary-leak", arm_id, action, variant, reason=f"canary:{leak[:32]}",
            denials=denials, exit_code=proc.returncode,
            detail={"stdout_tail": _tail(stdout_text)},
        )

    if mode == "interrupt":
        interrupted = proc.returncode is not None and proc.returncode not in _KNOWN_EXIT_CODES
        if interrupted and not denials and result.get("status") != "ok":
            return CaseResult(
                "interruption", arm_id, action, variant, reason="stopped-mid-run",
                gate=_gate_dict(gate), denials=denials, exit_code=proc.returncode,
                detail={"stdout_tail": _tail(stdout_text)},
            )
        return CaseResult(
            "spawn-failure", arm_id, action, variant,
            reason="interrupt-case-completed-instead",
            gate=_gate_dict(gate), denials=denials, exit_code=proc.returncode,
            detail={"stdout_tail": _tail(stdout_text)},
        )

    run_outcome = _classify_dispatch(proc.returncode, result, denials)
    if mode == "cleanup-watch":
        if run_outcome not in ("positive", "refusal"):
            return CaseResult(
                run_outcome, arm_id, action, variant,
                reason=None if run_outcome != "child-denials" else "denials-before-cleanup",
                gate=_gate_dict(gate), denials=denials, exit_code=proc.returncode,
                detail={"stdout_tail": _tail(stdout_text)},
            )
        after_scratch = snapshot_scratch(Path(profile.scratch_root))
        if after_scratch != before_scratch:
            return CaseResult(
                "cleanup-dirty", arm_id, action, variant,
                gate=_gate_dict(gate), denials=denials, exit_code=proc.returncode,
                detail={"before": sorted(before_scratch), "after": sorted(after_scratch)},
            )
        return CaseResult(
            "cleanup-ok", arm_id, action, variant,
            gate=_gate_dict(gate), denials=denials, exit_code=proc.returncode,
            detail={"stdout_tail": _tail(stdout_text)},
        )
    return CaseResult(
        run_outcome, arm_id, action, variant,
        reason=None if run_outcome in ("positive", "refusal") else "see-detail",
        gate=_gate_dict(gate), denials=denials, exit_code=proc.returncode,
        detail={"stdout_tail": _tail(stdout_text), "stderr_tail": _tail(stderr_text)},
    )


def run_canary_case(
    profile: OperatorProfile, *, enforced: bool, child_timeout: float = 60.0
) -> CaseResult:
    """The canary child (enforced: probes must all be denied) or the
    control child (``enforced=False``, no hook: the same probes must
    escape policy via plain OS behavior, proving denials come from the
    enforcer and not from host hardening)."""
    job = {"kind": "canary", "enforced": enforced}
    denial_read, denial_write = os.pipe()
    try:
        proc = _spawn_worker(
            profile, job, denial_write_fd=denial_write, stdin_payload=b""
        )
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.close(denial_read)
        return CaseResult(
            "spawn-failure", "containment", "canary",
            "enforced" if enforced else "control", reason=type(exc).__name__,
        )
    try:
        stdout_bytes, stderr_bytes = proc.communicate(timeout=child_timeout)
    except subprocess.TimeoutExpired:
        stop_case(proc)
        stdout_bytes, stderr_bytes = proc.communicate(timeout=30.0)
        return CaseResult(
            "timeout", "containment", "canary",
            "enforced" if enforced else "control", reason="child-timeout",
            denials=_drain_denials(denial_read), exit_code=proc.returncode,
        )
    stdout_text = stdout_bytes.decode("utf-8", errors="replace")
    stderr_text = stderr_bytes.decode("utf-8", errors="replace")
    denials = _drain_denials(denial_read)
    result = _parse_result_line(stdout_text)
    variant = "enforced" if enforced else "control"
    if proc.returncode == _EXIT_CANARY_ESCAPED or result.get("status") == "escaped":
        return CaseResult(
            "canary-escaped", "containment", "canary", variant,
            denials=denials, exit_code=proc.returncode,
            detail={"attempts": result.get("attempts", [])},
        )
    expected_status = "held" if enforced else "control"
    if proc.returncode == 0 and result.get("status") == expected_status:
        return CaseResult(
            "held" if enforced else "control-ok", "containment", "canary", variant,
            denials=denials, exit_code=proc.returncode,
            detail={"attempts": result.get("attempts", [])},
        )
    return CaseResult(
        "spawn-failure", "containment", "canary", variant,
        reason="unexpected-canary-child-result",
        denials=denials, exit_code=proc.returncode,
        detail={"stdout_tail": _tail(stdout_text), "stderr_tail": _tail(stderr_text)},
    )


def _classify_dispatch(
    returncode: int | None, result: Mapping[str, Any],
    denials: Sequence[Mapping[str, Any]],
) -> str:
    if denials:
        return "child-denials"
    if returncode == 0 and result.get("status") == "ok" and result.get("ok") is True:
        return "positive"
    if returncode == 0 and result.get("status") == "refused":
        return "refusal"
    if returncode == 3:
        return "blocked-before-dispatch"
    if returncode == 4:
        return "arm-error"
    return "spawn-failure"


def _hostile_payload_key(payload: Mapping[str, Any], arm_id: str) -> str:
    """The payload's path argument: the single string-valued path-like key
    is found structurally (arm payloads carry exactly one path argument).
    """
    for key, value in payload.items():
        if isinstance(value, str) and (":" in value or "\\" in value or "/" in value):
            return key
    return ""


def _gate_record_dict(record: AcquisitionRecord | None) -> dict[str, Any] | None:
    if record is None:
        return None
    return {
        "logical_path": record.logical_path,
        "size_bytes": record.size_bytes,
        "sha256": record.sha256,
        "suffix": record.suffix,
    }


def _gate_dict(gate: GateOutcome) -> dict[str, Any]:
    if gate.refused is not None:
        return {"refused": gate.refused}
    record = _gate_record_dict(gate.record)
    return {"record": record} if record is not None else {}


def _tail(text: str, limit: int = 2_000) -> str:
    return text[-limit:]


# --- Containment-local attempt ledger ------------------------------------

def record_attempt(
    rows: Sequence[Mapping[str, Any]],
    case: CaseResult,
    *,
    ledger_path: Path,
    recorded_at: datetime,
) -> tuple[tuple[dict, ...], str]:
    """Append one containment-LOCAL ledger row + outside detail document.

    Lane ``operator-rehearsal``, subject ``containment:<arm>:<action>``,
    deterministic attempt id ``containment.<arm>.<action>.<variant>``
    (re-runs are legitimate retries: same identity triple). Classes map:
    refusal outcomes -> ``refusal``; interruption -> ``interruption``
    (no outcome string); positive/cleanup-ok and every failure outcome ->
    ``completion`` with the outcome as its outcome string, so the honest
    denominator includes failures. NEVER append to evaluation ledgers.
    Returns (new_rows, new_head).
    """
    import attempt_ledger.ledger as ledger

    detail_path = _detail_path(ledger_path, case)
    detail = {
        "schema": "specaudit.ctf.containment-case-detail.v1",
        "arm_id": case.arm_id,
        "action": case.action,
        "variant": case.variant,
        "outcome": case.outcome,
        "ledger_class": case.attempt_class,
        "ledger_outcome": case.ledger_outcome,
        "reason": case.reason,
        "gate": dict(case.gate),
        "denials": [dict(row) for row in case.denials],
        "exit_code": case.exit_code,
        "detail": dict(case.detail),
    }
    detail_bytes = json.dumps(detail, sort_keys=True, separators=(",", ":")).encode("utf-8")
    detail_path.parent.mkdir(parents=True, exist_ok=True)
    detail_path.write_bytes(detail_bytes)
    attempt_class, outcome = _ledger_class(case)
    new_rows, head = ledger.append_row(rows, {
        "attempt_id": _attempt_id(case),
        "lane": _LEDGER_LANE,
        "subject": f"containment:{case.arm_id}:{case.action}",
        "attempt_class": attempt_class,
        "outcome": outcome,
        "assistance": _ASSISTANCE,
        "detail_digest": "sha256:" + hashlib.sha256(detail_bytes).hexdigest(),
        "recorded_at": recorded_at,
    })
    return new_rows, head


def _attempt_id(case: CaseResult) -> str:
    candidate = f"containment.{case.arm_id}.{case.action}.{case.variant}"
    # The ledger bounds ids to 128 chars of [a-z0-9._-]; arm ids/actions
    # are already kebab/lowercase, so only length can overflow.
    digest8 = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:8]
    if len(candidate) > 127 or any(
        ch not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for ch in candidate
    ):
        candidate = f"containment.hashed.{digest8}"
    return candidate


def _ledger_class(case: CaseResult) -> tuple[str, str | None]:
    return case.attempt_class, case.ledger_outcome


def _detail_path(ledger_path: Path, case: CaseResult) -> Path:
    return ledger_path.parent / f"{ledger_path.stem}-details" / f"{_attempt_id(case)}.json"


# --- The frozen roster matrix ---------------------------------------------

HOSTILE_CLASSES = ("traversal", "absolute-out-of-root", "symlink-escape",
                   "device-file")
POSIX_ONLY_HOSTILE = frozenset({"symlink-escape", "device-file"})
RENAME_INTO_ROOT_IS_ENFORCER_LAYER = (
    "rename-into-root is policed at the audit-hook layer (the acquisition "
    "gate is read-only by construction), so it appears in the canary and "
    "raise_for_event coverage, not as an acquire-level hostile class."
)


def _hostile_path(profile: OperatorProfile, hostile: str) -> str:
    approved = Path(profile.approved_root)
    if hostile == "traversal":
        return str(approved / "climbing" / ".." / ".." / "escaped.json")
    if hostile == "absolute-out-of-root":
        return str(Path(profile.scratch_root) / "outside-feed.json")
    if hostile == "symlink-escape":
        return str(approved / "link.json")
    if hostile == "device-file":
        return str(approved / "device.json")
    raise ValueError(f"unknown hostile class: {hostile!r}")


def _materialize_hostile_fixture(
    profile: OperatorProfile, hostile: str, content_canary: str
) -> None:
    """Create the outside files a hostile input points at (the traversal
    and escape refusals are lexical and need no target; the symlink and
    fifo fixtures only exist on POSIX)."""
    if hostile == "absolute-out-of-root":
        outside = Path(profile.scratch_root) / "outside-feed.json"
        outside.parent.mkdir(parents=True, exist_ok=True)
        outside.write_text(json.dumps([{"canary": content_canary}]), encoding="utf-8")
    elif hostile == "symlink-escape":
        link = Path(profile.approved_root) / "link.json"
        target = Path(profile.scratch_root) / "outside-feed.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps([{"canary": content_canary}]), encoding="utf-8")
        if link.exists() or link.is_symlink():
            link.unlink()
        os.symlink(target, link)
    elif hostile == "device-file":
        fifo = Path(profile.approved_root) / "device.json"
        if fifo.exists():
            fifo.unlink()
        os.mkfifo(fifo)
    # traversal: no fixture (lexically refused before any inspection).


def run_matrix(
    profile: OperatorProfile,
    roster: Sequence[RosterEntry],
    fixtures_root: Path,
    *,
    recorded_at: datetime,
    ledger_path: Path | None = None,
    hostile_classes: Sequence[str] = HOSTILE_CLASSES,
    include_canaries: bool = True,
    interrupt_first: bool = True,
    cleanup_first: bool = True,
    child_timeout: float = 120.0,
    kill_after: float = 0.5,
) -> dict[str, Any]:
    """Run the explicit roster and return the JSON summary.

    The PACKAGE never imports ``safety.check``; the caller supplies the
    frozen roster (tests pass literals derived from
    ``safety.check.ARM_BASELINES`` at test time). Fixtures materialize
    under ``fixtures_root``, which must lie inside the approved root.
    The summary counts every case: failures are never dropped, and the
    win32 label is ``partial`` because POSIX-only hostile classes skip.
    """
    import attempt_ledger.ledger as ledger

    approved = Path(os.path.realpath(profile.approved_root))
    fixtures_root = Path(os.path.realpath(fixtures_root))
    if not (fixtures_root == approved or approved in fixtures_root.parents):
        raise ValueError("fixtures_root must lie inside the approved root")
    scratch = Path(profile.scratch_root)
    scratch.mkdir(parents=True, exist_ok=True)
    approved.mkdir(parents=True, exist_ok=True)

    cases: list[CaseResult] = []
    skipped: list[dict[str, str]] = []
    rows: tuple[dict, ...] = ()
    head: str | None = None
    if ledger_path is not None:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        if ledger_path.exists():
            # Extend the existing containment-local chain; a corrupt or
            # tampered chain fails the run (fail closed), never silently
            # rewrites.
            loaded = tuple(
                json.loads(line) for line in
                ledger_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
            check = ledger.verify_ledger(loaded)
            if not check.ok:
                raise ValueError(
                    f"existing containment ledger does not verify: {check.reasons}")
            rows = loaded

    def record(case: CaseResult) -> CaseResult:
        cases.append(case)
        if ledger_path is not None:
            nonlocal rows, head
            rows, head = record_attempt(
                rows, case, ledger_path=ledger_path, recorded_at=recorded_at
            )
        return case

    fixtures: dict[str, tuple[str, dict[str, dict[str, Any]]]] = {}

    def fixture_for(arm_id: str) -> tuple[str, dict[str, dict[str, Any]]]:
        if arm_id not in fixtures:
            fixtures[arm_id] = build_fixture(arm_id, approved)
        return fixtures[arm_id]

    for entry in roster:
        if entry.path_argument is None:
            # Discovery smoke: no path signal exists to acquire or deny.
            record(run_case(
                profile, arm_id=entry.arm_id, action=entry.action,
                payload={}, variant="list-tools", child_timeout=child_timeout,
            ))
            continue
        input_path, args_by_action = fixture_for(entry.arm_id)
        payload = args_by_action.get(entry.action)
        if payload is None:
            skipped.append({
                "case": f"{entry.arm_id}:{entry.action}",
                "reason": "no-fixture-args-for-action",
            })
            continue
        record(run_case(
            profile, arm_id=entry.arm_id, action=entry.action,
            payload=payload, variant="inroot", child_timeout=child_timeout,
        ))

    first_data = next((entry for entry in roster if entry.path_argument is not None),
                      None)
    if first_data is not None:
        input_path, args_by_action = fixture_for(first_data.arm_id)
        action = first_data.action
        payload = dict(args_by_action[action])
        path_key = _hostile_payload_key(payload, first_data.arm_id)
        for hostile in hostile_classes:
            if os.name == "nt" and hostile in POSIX_ONLY_HOSTILE:
                skipped.append({
                    "case": f"{first_data.arm_id}:{action}:hostile-{hostile}",
                    "reason": "posix-only (symlink/fifo fixtures need POSIX)",
                })
                continue
            hostile_payload = dict(payload)
            hostile_payload[path_key] = _hostile_path(profile, hostile)
            _materialize_hostile_fixture(profile, hostile, content_canary=(
                profile.canaries[0] if profile.canaries else "containment-probe"))
            record(run_case(
                profile, arm_id=first_data.arm_id, action=action,
                payload=hostile_payload, hostile=hostile, variant=f"hostile-{hostile}",
            ))
        if cleanup_first:
            record(run_case(
                profile, arm_id=first_data.arm_id, action=action,
                payload=payload, variant="cleanup", mode="cleanup-watch",
                child_timeout=child_timeout,
            ))
        if interrupt_first:
            record(run_case(
                profile, arm_id=first_data.arm_id, action=action,
                payload=payload, variant="interrupt", mode="interrupt",
                kill_after=kill_after, child_timeout=child_timeout,
            ))

    if include_canaries:
        record(run_canary_case(profile, enforced=True))
        record(run_canary_case(profile, enforced=False))

    counts: dict[str, int] = {}
    per_arm: dict[str, dict[str, str]] = {}
    all_denials: list[Mapping[str, Any]] = []
    cases_with_denials: list[str] = []
    failures: list[dict[str, str]] = []
    for case in cases:
        counts[case.outcome] = counts.get(case.outcome, 0) + 1
        per_arm.setdefault(case.arm_id, {})[f"{case.action}:{case.variant}"] = (
            case.outcome
        )
        all_denials.extend(case.denials)
        if case.denials:
            cases_with_denials.append(f"{case.arm_id}:{case.action}:{case.variant}")
        if case.failed:
            failures.append({
                "case": f"{case.arm_id}:{case.action}:{case.variant}",
                "outcome": case.outcome,
                "reason": case.reason or "",
            })
    summary = {
        "schema": "specaudit.ctf.containment-matrix.v1",
        "platform": {
            "system": os.name,
            "label": "partial" if os.name == "nt" else "full",
            "partial_reason": (
                "symlink-escape and device-file hostile classes require POSIX"
                if os.name == "nt" else None
            ),
        },
        "counts": dict(sorted(counts.items())),
        "per_arm": {arm: dict(sorted(actions.items()))
                    for arm, actions in sorted(per_arm.items())},
        "denials": [dict(row) for row in all_denials],
        "cases_with_denials": cases_with_denials,
        "failures": failures,
        "skipped": skipped,
        "cases": len(cases),
    }
    if ledger_path is not None:
        ledger_path.write_text(
            "".join(
                json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                for row in rows
            ),
            encoding="utf-8",
        )
        summary["ledger"] = {
            "path": str(ledger_path),
            "rows": len(rows),
            "head": head,
            "lane": _LEDGER_LANE,
        }
    return summary
