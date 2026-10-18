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


# Fixed runtime values owned by this harness for every guarded worker
# child (U-SAFE.b). The set is deliberately closed: thread caps are
# deterministic single-thread values, and the startup/encoding/
# breakpoint keys are neutralized here rather than inherited.
_FIXED_RUNTIME_ENV = {
    "PYTHONUTF8": "1",
    "PYTHONDONTWRITEBYTECODE": "1",  # no __pycache__ writes: checkout imports stay read-only
    "PYTHONNOUSERSITE": "1",  # no ~/.local user-site imports
    "PYTHONSAFEPATH": "1",  # no cwd/script-dir on sys.path; the checkout arrives via PYTHONPATH only
    "PYTHONIOENCODING": "utf-8",
    "PYTHONCOERCECLOCALE": "0",
    "PYTHONBREAKPOINT": "0",  # breakpoint() hook disabled
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
}

# Single documented non-secret OS bootstrap key copied (by
# case-insensitive name, emitted as one canonical key) on Windows only,
# where the interpreter needs the system directory for side-by-side
# assemblies. The worker argv[0] is an absolute interpreter path spawned
# with shell=False, so no shell or extension-list lookup (WINDIR,
# COMSPEC, PATHEXT) is needed; the worker has no justified ambient temp
# dependency, so TEMP/TMP are dropped like all other ambient keys.
# Values pass through verbatim and are never logged. Everything else
# ambient -- cloud/provider credentials, trace keys, profiles, proxies,
# Python startup/config, loader injection -- is dropped. Windows was not
# executed for this unit (POSIX host); no native Windows execution is
# claimed.
_WINDOWS_BOOTSTRAP_KEYS = frozenset({
    "systemroot",
})
# Canonical emission key for the single Windows bootstrap passthrough.
_WINDOWS_SYSTEMROOT_KEY = "SystemRoot"


def _worker_interpreter() -> str:
    """Absolute path of the current interpreter (the worker argv[0])."""
    return os.path.abspath(sys.executable)


def _child_env(profile: OperatorProfile, denial_write_fd: int) -> dict[str, str]:
    """Minimal fixed environment for a guarded worker child (U-SAFE.b).

    Starts from nothing ambient -- no ``os.environ`` inheritance, no
    secret-name denylist, no prefix filter, no caller override. Audit
    hooks cannot stop a child from reading its own environment, so
    secrets must never be transported there in the first place. Every
    key is either generated per spawn (profile JSON, denial fd/handle)
    or a fixed runtime value owned above. Suppressed by absence:
    PYTHONSTARTUP, PYTHONHOME, PYTHONWARNINGS, PYTHONMALLOC and other
    Python startup/config, proxy (``*_PROXY``), loader-injection
    (``LD_PRELOAD``, ``LD_LIBRARY_PATH``, ``DYLD_*``), cloud/provider
    credentials, profiles, and all other ambient keys.
    """
    env = dict(_FIXED_RUNTIME_ENV)
    # Interpreter-only PATH: the child must start, but never find host
    # tooling (mirrors the suite's hermetic-PATH promise).
    env["PATH"] = str(Path(_worker_interpreter()).parent)
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["CONTAINMENT_PROFILE_JSON"] = profile.to_json()
    if os.name == "nt":
        # pass_fds is not supported on Windows; the handle VALUE is
        # inherited intact and re-opened as an fd in the child.
        import msvcrt

        os.set_inheritable(denial_write_fd, True)
        env["CONTAINMENT_DENIAL_HANDLE"] = str(int(msvcrt.get_osfhandle(denial_write_fd)))
        for key, value in os.environ.items():
            if key.lower() in _WINDOWS_BOOTSTRAP_KEYS:
                env.setdefault(_WINDOWS_SYSTEMROOT_KEY, value)
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
        [_worker_interpreter(), "-m", WORKER_MODULE], **popen_kwargs
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

# Strict complete-matrix coverage: explicit expected/executed/skipped/
# missing/duplicate cells. The package never imports safety.check; the
# caller supplies the frozen roster and this module derives the expected
# cells from that supplied roster BEFORE execution (never re-derived from
# the actually executed cells). A caller-supplied subset can only prove
# that subset, never universal SAFE acceptance: the summary labels scope
# and the supplied roster count/digest explicitly.
_STRICT_SCOPE = "strict-supplied-roster"
_REHEARSAL_SCOPE = "partial-rehearsal"


def _expected_outcomes_for_variant(variant: str) -> frozenset:
    """Legal outcomes for one cell variant (positive/refusal preserved)."""
    if variant == "list-tools":
        return frozenset({"positive", "refusal"})
    if variant == "inroot":
        return frozenset({"positive", "refusal"})
    if variant.startswith("hostile-"):
        return frozenset({"blocked"})
    if variant == "cleanup":
        return frozenset({"cleanup-ok"})
    if variant == "interrupt":
        return frozenset({"interruption"})
    if variant == "enforced":
        return frozenset({"held"})
    if variant == "control":
        return frozenset({"control-ok"})
    return frozenset()


def _cell_key(arm_id: str, action: str, variant: str) -> str:
    return f"{arm_id}:{action}:{variant}"


def roster_digest(roster: Sequence[RosterEntry]) -> str:
    """Stable digest of the SUPPLIED roster (order-insensitive)."""
    rows = sorted(
        (
            {"arm_id": entry.arm_id, "action": entry.action,
             "path_argument": entry.path_argument}
            for entry in roster
        ),
        key=lambda row: (
            row["arm_id"], row["action"], row["path_argument"] or ""),
    )
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def expected_cells(
    roster: Sequence[RosterEntry],
    hostile_classes: Sequence[str] = HOSTILE_CLASSES,
    include_canaries: bool = True,
    cleanup_first: bool = True,
    interrupt_first: bool = True,
    strict: bool = False,
) -> list[tuple[str, str, str]]:
    """Expected (arm_id, action, variant) cells derived BEFORE execution.

    Legacy (strict=False): one inroot/list-tools cell per roster entry,
    plus the four hostile classes + cleanup + interrupt for the FIRST data
    entry only (the small rehearsal); the caller flags select both the
    expectation and the execution there. Strict (strict=True): the
    MANDATORY controls -- the standard four hostile classes, cleanup,
    interruption, and both canaries -- for EVERY supplied data action
    plus the discovery/canary cells, independently of the
    execution-selection flags. Suppressing execution still leaves those
    cells expected, so the omission surfaces as missing/incomplete.
    With the canonical 14-reader/38-data roster and the default
    four hostile classes plus cleanup plus interrupt, strict POSIX
    expectation is 38*7+14+2 = 282 cells.
    """
    if strict:
        hostile_classes = HOSTILE_CLASSES
        include_canaries = True
        cleanup_first = True
        interrupt_first = True
    cells: list[tuple[str, str, str]] = []
    for entry in roster:
        if entry.path_argument is None:
            cells.append((entry.arm_id, entry.action, "list-tools"))
        elif not strict:
            cells.append((entry.arm_id, entry.action, "inroot"))
        else:
            cells.append((entry.arm_id, entry.action, "inroot"))
            for hostile in hostile_classes:
                cells.append(
                    (entry.arm_id, entry.action, f"hostile-{hostile}"))
            if cleanup_first:
                cells.append((entry.arm_id, entry.action, "cleanup"))
            if interrupt_first:
                cells.append((entry.arm_id, entry.action, "interrupt"))
    if not strict:
        first_data = next(
            (entry for entry in roster if entry.path_argument is not None),
            None,
        )
        if first_data is not None:
            for hostile in hostile_classes:
                cells.append((
                    first_data.arm_id, first_data.action,
                    f"hostile-{hostile}"))
            if cleanup_first:
                cells.append(
                    (first_data.arm_id, first_data.action, "cleanup"))
            if interrupt_first:
                cells.append(
                    (first_data.arm_id, first_data.action, "interrupt"))
    if include_canaries:
        cells.append(("containment", "canary", "enforced"))
        cells.append(("containment", "canary", "control"))
    return cells


def _duplicate_roster_keys(
    roster: Sequence[RosterEntry],
) -> list[str]:
    seen: dict[str, int] = {}
    for entry in roster:
        key = f"{entry.arm_id}:{entry.action}"
        seen[key] = seen.get(key, 0) + 1
    return sorted(key for key, count in seen.items() if count > 1)


def check_coverage(
    expected: Sequence[tuple[str, str, str]],
    cases: Sequence[CaseResult],
    skipped: Sequence[Mapping[str, Any]],
    duplicate_roster: Sequence[str],
) -> dict[str, Any]:
    """Pure scheduling-coverage check (no children, no fixtures).

    Compares the BEFORE-execution ``expected`` cells against the
    actually executed ``cases``. Fails closed (``complete=False``) on
    missing/extra cells, duplicate roster or result cells, unexpected
    outcomes for a variant, and any skip (skips count as unevidenced).
    Used by ``run_matrix`` and directly by scheduling tests with
    monkeypatched fake runners confined to tests; empirical containment
    still needs the real matrix.
    """
    expected_keys = [_cell_key(a, b, v) for (a, b, v) in expected]
    expected_set = set(expected_keys)
    executed_keys = [_cell_key(c.arm_id, c.action, c.variant) for c in cases]
    executed_set = set(executed_keys)
    missing = list(dict.fromkeys(k for k in expected_keys if k not in executed_set))
    extra = sorted(k for k in executed_set if k not in expected_set)
    seen_counts: dict[str, int] = {}
    for key in executed_keys:
        seen_counts[key] = seen_counts.get(key, 0) + 1
    duplicate_results = sorted(
        key for key, count in seen_counts.items() if count > 1)
    unexpected: list[dict[str, str]] = []
    for case in cases:
        allowed = _expected_outcomes_for_variant(case.variant)
        if case.outcome not in allowed:
            unexpected.append({
                "cell": _cell_key(case.arm_id, case.action, case.variant),
                "outcome": case.outcome,
                "expected": ",".join(sorted(allowed)) if allowed else "",
            })
    unexpected.sort(key=lambda row: row["cell"])
    reasons: list[str] = []
    if list(duplicate_roster):
        reasons.append(
            "duplicate-supplied-roster:" + ",".join(sorted(duplicate_roster)))
    if missing:
        reasons.append(f"missing-cells:{len(missing)}")
    if extra:
        reasons.append(f"extra-cells:{len(extra)}")
    if duplicate_results:
        reasons.append("duplicate-result-cells:" + ",".join(duplicate_results))
    if unexpected:
        reasons.append(f"unexpected-outcomes:{len(unexpected)}")
    if list(skipped):
        reasons.append(f"skipped-cells:{len(list(skipped))}")
    complete = not (
        missing or extra or list(duplicate_roster) or duplicate_results
        or unexpected or list(skipped)
    )
    return {
        "expected": len(expected_keys),
        "executed": len(executed_keys),
        "skipped": len(list(skipped)),
        "missing": missing,
        "extra": extra,
        "duplicate_roster": sorted(duplicate_roster),
        "duplicate_results": duplicate_results,
        "unexpected": unexpected,
        "complete": complete,
        "reasons": reasons,
    }
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
    strict: bool = False,
) -> dict[str, Any]:
    """Run the explicit roster and return the JSON summary.

    The PACKAGE never imports ``safety.check``; the caller supplies the
    frozen roster (tests pass literals derived from
    ``safety.check.ARM_BASELINES`` at test time). Fixtures materialize
    under ``fixtures_root``, which must lie inside the approved root.
    The summary counts every case: failures are never dropped.

    ``strict=False`` (default) keeps the legacy small rehearsal: one
    inroot/list-tools cell per roster entry plus hostile/cleanup/
    interruption for the FIRST data entry only, with scope
    ``partial-rehearsal``. ``strict=True`` requires the MANDATORY
    controls -- the standard four hostile classes, cleanup,
    interruption, and both canaries -- for EVERY supplied data action
    plus the discovery/canary cells (strict complete-matrix mode),
    reusing the same fixtures, acquisition gate, enforcement, and
    ledger. The execution-selection flags (``hostile_classes``,
    ``include_canaries``, ``cleanup_first``, ``interrupt_first``) only
    select which runs execute; omitted runs stay expected and surface
    as missing/incomplete with a ``partial`` platform label and a
    nonzero strict CLI exit even with zero runtime failures. Strict
    completeness fails closed on absent fixture args, omitted execution
    cells, duplicate roster or result cells, truncated or missing worker
    results, dirty cleanup, unexpected outcomes, and skips (skips count
    as unevidenced). The ``platform`` label reports ``full`` only for a
    strict run with complete coverage on POSIX; every other run reports
    ``partial`` with an explicit reason -- never ``full`` simply because
    ``os.name`` is POSIX.
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

    # Expected cells are derived BEFORE execution from the SUPPLIED roster
    # only (never re-derived from the actually executed cells). In strict
    # mode the expectation carries the mandatory controls independently
    # of the execution-selection flags below.
    _expected = expected_cells(
        roster, hostile_classes, include_canaries,
        cleanup_first, interrupt_first, strict,
    )
    _duplicate_roster = _duplicate_roster_keys(roster)

    fixtures: dict[str, tuple[str, dict[str, dict[str, Any]]]] = {}

    def fixture_for(arm_id: str) -> tuple[str, dict[str, dict[str, Any]]]:
        if arm_id not in fixtures:
            fixtures[arm_id] = build_fixture(arm_id, approved)
        return fixtures[arm_id]

    def _run_hostile(
        arm_id: str, action: str, payload: Mapping[str, Any], hostile: str,
    ) -> None:
        path_key = _hostile_payload_key(payload, arm_id)
        if os.name == "nt" and hostile in POSIX_ONLY_HOSTILE:
            skipped.append({
                "case": _cell_key(arm_id, action, f"hostile-{hostile}"),
                "reason": "posix-only (symlink/fifo fixtures need POSIX)",
            })
            return
        hostile_payload = dict(payload)
        hostile_payload[path_key] = _hostile_path(profile, hostile)
        _materialize_hostile_fixture(profile, hostile, content_canary=(
            profile.canaries[0] if profile.canaries else "containment-probe"))
        record(run_case(
            profile, arm_id=arm_id, action=action,
            payload=hostile_payload, hostile=hostile,
            variant=f"hostile-{hostile}",
        ))

    if not strict:
        for entry in roster:
            if entry.path_argument is None:
                # Discovery smoke: no path signal exists to acquire or deny.
                record(run_case(
                    profile, arm_id=entry.arm_id, action=entry.action,
                    payload={}, variant="list-tools",
                    child_timeout=child_timeout,
                ))
                continue
            _input_path, args_by_action = fixture_for(entry.arm_id)
            payload = args_by_action.get(entry.action)
            if payload is None:
                skipped.append({
                    "case": f"{entry.arm_id}:{entry.action}",
                    "reason": "no-fixture-args-for-action",
                })
                continue
            record(run_case(
                profile, arm_id=entry.arm_id, action=entry.action,
                payload=payload, variant="inroot",
                child_timeout=child_timeout,
            ))

        first_data = next(
            (entry for entry in roster if entry.path_argument is not None),
            None)
        if first_data is not None:
            _input_path, args_by_action = fixture_for(first_data.arm_id)
            action = first_data.action
            payload = dict(args_by_action[action])
            for hostile in hostile_classes:
                _run_hostile(first_data.arm_id, action, payload, hostile)
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
    else:
        for entry in roster:
            if entry.path_argument is None:
                record(run_case(
                    profile, arm_id=entry.arm_id, action=entry.action,
                    payload={}, variant="list-tools",
                    child_timeout=child_timeout,
                ))
                continue
            _input_path, args_by_action = fixture_for(entry.arm_id)
            payload = args_by_action.get(entry.action)
            if payload is None:
                for (_e_arm, _e_action, _e_variant) in _expected:
                    if _e_arm == entry.arm_id and _e_action == entry.action:
                        skipped.append({
                            "case": _cell_key(
                                _e_arm, _e_action, _e_variant),
                            "reason": "no-fixture-args-for-action",
                        })
                continue
            record(run_case(
                profile, arm_id=entry.arm_id, action=entry.action,
                payload=payload, variant="inroot",
                child_timeout=child_timeout,
            ))
            for hostile in hostile_classes:
                _run_hostile(entry.arm_id, entry.action, payload, hostile)
            if cleanup_first:
                record(run_case(
                    profile, arm_id=entry.arm_id, action=entry.action,
                    payload=payload, variant="cleanup", mode="cleanup-watch",
                    child_timeout=child_timeout,
                ))
            if interrupt_first:
                record(run_case(
                    profile, arm_id=entry.arm_id, action=entry.action,
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
    _coverage = check_coverage(
        _expected, cases, skipped, _duplicate_roster)
    _missing = _coverage["missing"]
    _extra = _coverage["extra"]
    _duplicate_results = _coverage["duplicate_results"]
    _unexpected = _coverage["unexpected"]
    _reasons = _coverage["reasons"]
    _complete = _coverage["complete"]
    _expected_keys = [_cell_key(a, b, v) for (a, b, v) in _expected]
    _executed_set = {
        _cell_key(c.arm_id, c.action, c.variant) for c in cases}
    _data_actions = sum(1 for entry in roster if entry.path_argument is not None)
    _discovery = sum(1 for entry in roster if entry.path_argument is None)
    completeness = {
        "scope": _STRICT_SCOPE if strict else _REHEARSAL_SCOPE,
        "strict": strict,
        "supplied_roster": {
            "entries": len(roster),
            "data_actions": _data_actions,
            "discovery": _discovery,
            "digest": roster_digest(roster),
        },
        "expected": _coverage["expected"],
        "executed": _coverage["executed"],
        "skipped": _coverage["skipped"],
        "missing": _missing,
        "extra": _extra,
        "duplicate_roster": _coverage["duplicate_roster"],
        "duplicate_results": _duplicate_results,
        "unexpected": _unexpected,
        "complete": _complete,
        "reasons": _reasons,
    }
    if strict and _complete and os.name != "nt":
        _label = "full"
        _partial_reason = None
    elif not strict:
        _label = "partial"
        _partial_reason = (
            "legacy rehearsal covers hostile/cleanup/interruption for the "
            "first data action only; use strict=True for the complete matrix"
        )
    elif os.name == "nt":
        _label = "partial"
        _partial_reason = (
            "symlink-escape and device-file hostile classes require POSIX"
        )
    else:
        _label = "partial"
        _partial_reason = (
            "; ".join(_reasons) if _reasons else "incomplete coverage")
    summary = {
        "schema": "specaudit.ctf.containment-matrix.v1",
        "platform": {
            "system": os.name,
            "label": _label,
            "partial_reason": _partial_reason,
        },
        "completeness": completeness,
        "expected_cells": [
            {"arm_id": a, "action": b, "variant": v}
            for (a, b, v) in _expected
        ],
        "executed_cells": sorted(_executed_set),
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
