"""PEP 578 audit-hook enforcement plane for guarded child interpreters.

Threat model, stated honestly
-----------------------------

This module contains repo code run under hostile inputs at the Python
audit-hook level (PEP 578, ``sys.addaudithook``). It is NOT an OS sandbox.
The operator's E2/E3 OS sandbox remains the real boundary. Residual
bypasses that this plane cannot see or stop:

* C-extension internal I/O that never raises an audited event;
* raw syscalls issued via ctypes/cffi or hand-built machine code;
* file descriptors inherited from the parent (they are already open);
* processes that outlive this interpreter (post-exec re-execution).

What it does prove, empirically, for the repo's Python-level arms: a
``sys.addaudithook`` hook installed before target code runs cannot be
removed or replaced from inside the process (the no-cooperation property:
PEP 578 provides no API to drop or reorder an installed hook), and the
policed events below are denied with ``PermissionError`` plus one JSON
denial record per denial on an inherited pipe the child can only append
to.

Policed events and policy (fail closed)
---------------------------------------

* ``open`` (file, mode, flags): denied when the mode/flags indicate WRITE
  (writes are denied everywhere, including scratch: the contained arms are
  read-only), and denied for ANY open -- read or write -- whose resolved
  absolute path lies outside the allowlist (approved_root, scratch_root,
  the interpreter/runtime tree when ``allow_python_runtime`` is set, and
  the os.devnull-style essentials such as the denial pipe's companions).
  Paths resolve through ``os.path.realpath`` on the event argument.
* ``socket.connect`` / ``socket.bind`` / ``socket.getaddrinfo``: denied.
* ``subprocess.Popen`` / ``os.system`` / ``os.exec`` / ``os.posix_spawn`` /
  ``os.fork``: denied.
* ``os.rename`` / ``os.replace`` / ``os.link`` / ``os.symlink`` /
  ``os.remove`` / ``os.rmdir`` / ``os.chmod`` / ``os.chown`` /
  ``shutil.copyfile`` / ``shutil.rmtree``: denied when any target endpoint
  resolves outside scratch_root. open()-level writes being denied
  everywhere, scratch_root is where file-mutation verbs between already
  existing scratch files remain arguable at all.
* a path-relative ``dir_fd`` argument that the plane cannot resolve denies
  the event (fail closed).

Every denial raises ``PermissionError`` with a structured message AND
appends one JSON line ``{"event", "path"?, "mode"?, "ts_seq"}`` to the
inherited denial pipe. The parent reads the pipe; the child can only
append. ``ts_seq`` is a process-local sequence number, not a timestamp:
the library never reads the clock.

No network, no subprocess (this module never spawns anything), no clock
reads.
"""
from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

_WRITE_FLAGS = (
    getattr(os, "O_WRONLY", 0)
    | getattr(os, "O_RDWR", 0)
    | getattr(os, "O_APPEND", 0)
    | getattr(os, "O_CREAT", 0)
    | getattr(os, "O_TRUNC", 0)
)
_WRITE_MODE_CHARS = frozenset("wax+")

_OPEN = "open"
_SOCKET_EVENTS = frozenset({
    "socket.connect", "socket.bind", "socket.getaddrinfo",
})
_PROCESS_EVENTS = frozenset({
    "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.fork",
})
# Two-endpoint mutation verbs: every endpoint must resolve inside scratch.
_TWO_ENDPOINT_EVENTS = frozenset({
    "os.rename", "os.replace", "os.link", "os.symlink", "shutil.copyfile",
})
# Single-endpoint mutation verbs.
_ONE_ENDPOINT_EVENTS = frozenset({
    "os.remove", "os.rmdir", "os.chmod", "os.chown", "shutil.rmtree",
})
POLICED_EVENTS = frozenset(
    {_OPEN} | _SOCKET_EVENTS | _PROCESS_EVENTS
    | _TWO_ENDPOINT_EVENTS | _ONE_ENDPOINT_EVENTS
)

# Audit-event argument positions of the path endpoints per mutation verb.
# The trailing ``dir_fd`` position (when present) is checked for a
# caller-supplied fd, which this plane cannot resolve -> fail closed.
_ENDPOINT_SLOTS: dict[str, tuple[int, ...]] = {
    "os.rename": (0, 1),
    "os.replace": (0, 1),
    "os.link": (0, 1),
    "os.symlink": (0, 1),
    "shutil.copyfile": (0, 1),
    "os.remove": (0,),
    "os.rmdir": (0,),
    "os.chmod": (0,),
    "os.chown": (0,),
    "shutil.rmtree": (0,),
}
_DIR_FD_SLOT: dict[str, int] = {
    "os.rename": 2,
    "os.replace": 2,
    "os.link": 2,
    "os.symlink": 2,
    "os.remove": 1,
    "os.rmdir": 1,
    "os.chmod": 2,
    "os.chown": 3,
}

_RESULT_JSON_SEP = (",", ":")

# Repository package directories the guarded jobs may import. Anything else
# in the repository (challenges, exercise_operator contracts, docs, tests)
# stays outside the read allowlist by design.
_REPO_PACKAGE_DIRS = ("containment", "extension", "reader_evidence", "attempt_ledger")


class EnforcerError(RuntimeError):
    """Raised when the plane cannot be installed as requested."""


def _as_text(value: Any) -> str | None:
    """Best-effort text of an audit-event path argument."""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return os.fsdecode(value)
    try:
        return os.fspath(value)
    except TypeError:
        return None


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def resolve_path(value: Any) -> str | None:
    """Resolved absolute path of an event argument, or None if unusable.

    ``os.path.realpath`` raises no policed audit events, so the hook's own
    resolution cannot recurse into itself.
    """
    text = _as_text(value)
    if text is None or not text.strip():
        return None
    try:
        return _norm(os.path.realpath(text))
    except OSError:
        return _norm(text)


def _inside(candidate: str, root: str) -> bool:
    return candidate == root or candidate.startswith(root + os.sep)


def runtime_roots() -> tuple[str, ...]:
    """Resolved read allowlist for the child's own imports and runtime.

    The interpreter trees (``sys.prefix`` and friends) plus — in a checkout
    layout — ONLY the specific repository package directories the guarded
    jobs import (``containment`` itself, ``extension``, ``reader_evidence``,
    ``attempt_ledger``). Deliberately NOT the whole repository tree: that
    would re-expose instructor-held material (``challenges/*/instructor``,
    operator contracts) to the guarded child in a checkout layout. In an
    installed wheel layout the package roots live inside the interpreter
    tree and add nothing.
    """
    repo_root = Path(__file__).resolve().parents[1]
    candidates = {
        str(sys.prefix),
        str(sys.base_prefix),
        str(sys.exec_prefix),
        str(sys.base_exec_prefix),
        *(str(repo_root / name) for name in _REPO_PACKAGE_DIRS),
    }
    normalized = {_norm(item) for item in candidates}
    # Keep only maximal roots; a root subsumed by another never matches.
    maximal = sorted(
        root for root in normalized
        if not any(other != root and _inside(root, other) for other in normalized)
    )
    return tuple(maximal)


def _devnull_roots() -> tuple[str, ...]:
    """os.devnull-style essentials (the denial pipe needs no open path,
    but the interpreter may legitimately touch the null device)."""
    normalized = {_norm(os.devnull)}
    resolved = resolve_path(os.devnull)
    if resolved is not None:
        normalized.add(resolved)
    return tuple(normalized)


def allow_roots(profile: Mapping[str, Any]) -> tuple[str, ...]:
    """The profile's resolved read allowlist (approved, scratch, runtime)."""
    roots = [
        resolve_path(profile.get("approved_root")),
        resolve_path(profile.get("scratch_root")),
    ]
    normalized = {_norm(root) for root in roots if root is not None}
    if profile.get("allow_python_runtime") is True:
        normalized.update(runtime_roots())
    normalized.update(_devnull_roots())
    maximal = sorted(
        root for root in normalized
        if not any(other != root and _inside(root, other) for other in normalized)
    )
    return tuple(maximal)


def _write_intent(mode: Any, flags: Any) -> bool:
    """Whether an ``open`` event's mode/flags indicate write capability."""
    if isinstance(mode, str):
        return bool(_WRITE_MODE_CHARS & set(mode))
    if mode is None and isinstance(flags, int):
        return bool(flags & _WRITE_FLAGS)
    # Unknown mode/flags shapes fail closed.
    return True


def _dir_fd_supplied(args: Sequence[Any], event: str) -> bool:
    slot = _DIR_FD_SLOT.get(event)
    if slot is None or slot >= len(args):
        return False
    value = args[slot]
    return value is not None and value != -1


def decide(
    event: str, args: Sequence[Any], roots: tuple[str, ...], *,
    scratch_root: str,
) -> tuple[bool, str | None, str | None, str]:
    """Pure policy core: would this event be denied?

    Returns ``(denied, primary_path, mode, rule)``. ``primary_path`` and
    ``mode`` feed the denial record; ``rule`` is a stable short code.
    """
    if event == _OPEN:
        resolved = resolve_path(args[0]) if args else None
        mode = args[1] if len(args) > 1 else None
        if resolved is None:
            return True, None, _mode_text(mode), "open-unresolvable"
        if _write_intent(mode, args[2] if len(args) > 2 else None):
            return True, resolved, _mode_text(mode), "write-open-denied"
        if not any(_inside(resolved, root) for root in roots):
            return True, resolved, _mode_text(mode), "outside-allowlist"
        return False, resolved, _mode_text(mode), ""
    if event in _SOCKET_EVENTS or event in _PROCESS_EVENTS:
        return True, None, None, "event-denied"
    if event in _TWO_ENDPOINT_EVENTS or event in _ONE_ENDPOINT_EVENTS:
        slots = _ENDPOINT_SLOTS[event]
        if _dir_fd_supplied(args, event):
            return True, None, None, "dir-fd-unresolvable"
        endpoints = [resolve_path(args[slot]) for slot in slots if slot < len(args)]
        if any(endpoint is None for endpoint in endpoints):
            return True, None, None, "mutation-path-unresolvable"
        escaped = [
            endpoint for endpoint in endpoints
            if not _inside(endpoint, _norm(scratch_root))
        ]
        if escaped:
            return True, escaped[0], None, "mutation-outside-scratch"
        return False, endpoints[0], None, ""
    # Unknown policed-looking events fail closed only if listed; anything
    # else is out of the plane's contract and allowed.
    return False, None, None, ""


def _mode_text(mode: Any) -> str | None:
    if isinstance(mode, str):
        return mode
    if mode is None:
        return None
    return str(mode)


def raise_for_event(event: str, args: Sequence[Any], profile: Mapping[str, Any]) -> None:
    """Pure helper: raise PermissionError exactly when the hook would.

    Recomputes the profile's allowlist per call; tests use it to pin the
    policy without spawning children. ``profile`` is the JSON-shaped
    profile dict (see ``OperatorProfile.to_dict``).
    """
    roots = allow_roots(profile)
    denied, path, mode, rule = decide(
        event, args, roots, scratch_root=str(profile.get("scratch_root", ""))
    )
    if denied:
        raise PermissionError(_denial_message(event, path, mode, rule, profile))


def _denial_message(event: str, path: str | None, mode: str | None,
                    rule: str, profile: Mapping[str, Any]) -> str:
    return (
        f"containment-denied event={event} rule={rule} path={path!r} mode={mode!r} "
        f"approved_root={profile.get('approved_root')!r} "
        f"scratch_root={profile.get('scratch_root')!r}"
    )


def denial_record(event: str, path: str | None, mode: str | None,
                  ts_seq: int) -> dict[str, Any]:
    """One JSON-serializable denial record (no timestamps, only a seq no)."""
    record: dict[str, Any] = {"event": event, "ts_seq": ts_seq}
    if path is not None:
        record["path"] = path
    if mode is not None:
        record["mode"] = mode
    return record


def _emit(denial_fd: int, record: Mapping[str, Any]) -> None:
    """Append one denial line; best-effort (the raise still happens)."""
    try:
        line = json.dumps(
            dict(record), sort_keys=True, separators=_RESULT_JSON_SEP,
            ensure_ascii=True,
        ).encode("ascii") + b"\n"
        os.write(denial_fd, line)
    except OSError:
        pass


def install(profile: Mapping[str, Any], denial_fd: int | None = None) -> None:
    """Install the audit hook in this (child) process. Irreversible.

    ``profile`` is the JSON-shaped profile dict; ``denial_fd`` is the
    inherited denial pipe's write end (raw fd on POSIX, an
    ``msvcrt.open_osfhandle`` fd on Windows). Called at child startup
    BEFORE any target code runs; PEP 578 provides no in-process way to
    remove the hook afterwards (the no-cooperation property).
    """
    if not isinstance(profile, Mapping):
        raise EnforcerError("profile must be a mapping")
    roots = allow_roots(profile)
    scratch = _norm(str(profile.get("scratch_root", "")))
    if not scratch:
        raise EnforcerError("profile scratch_root is required")
    seq = itertools.count(1)

    def _hook(event: str, args: tuple[Any, ...]) -> None:
        # Cheap first-line filter: the hook fires for every audited event
        # in the process, including those raised by this closure's own
        # helpers (os.stat inside realpath etc.), which are not policed.
        if event not in POLICED_EVENTS:
            return
        denied, path, mode, rule = decide(event, args, roots, scratch_root=scratch)
        if not denied:
            return
        if denial_fd is not None:
            _emit(denial_fd, denial_record(event, path, mode, next(seq)))
        raise PermissionError(_denial_message(event, path, mode, rule, profile))

    sys.addaudithook(_hook)
