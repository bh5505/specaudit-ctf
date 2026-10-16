"""Trusted-side input acquisition for reader evidence (EVID-01).

The approved root is resolved strictly, traversal is refused lexically, the
final component is refused when it is a symlink, and bytes are read through a
no-follow descriptor whose identity is compared before and after the read. A
content hash binds acquired bytes; it does not authenticate origin, and the
recorded locator is not identity. No network, no subprocess, no clock reads:
callers supply every timestamp.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import errno
import hashlib
import os
from pathlib import Path
import stat

_READ_CHUNK = 65_536


class AcquisitionError(ValueError):
    """Typed acquisition refusal; ``reason`` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class AcquisitionRecord:
    """Bound bytes acquired from inside the operator-approved root."""

    logical_path: str
    resolved_path: str
    size_bytes: int
    sha256: str
    suffix: str
    acquired_at: datetime


@dataclass(frozen=True)
class DirectoryManifest:
    """Deterministic bounded inventory of one directory under the root.

    Entries are {relative_path, size_bytes, sha256} dicts sorted by relative
    posix path; empty subdirectories are invisible to both walk passes.
    """

    resolved_path: str
    entries: tuple[dict, ...]
    total_bytes: int
    acquired_at: datetime


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _identity(snapshot: os.stat_result) -> tuple:
    """Device, inode, size, and nanosecond times: the governance identity set."""
    return (snapshot.st_dev, snapshot.st_ino, snapshot.st_size,
            snapshot.st_mtime_ns, snapshot.st_ctime_ns)


def _inside(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents


def _resolve_root(approved_root: Path) -> Path:
    """Resolve the approved root strictly; the real path is the only boundary."""
    try:
        root = Path(approved_root).resolve(strict=True)
    except OSError as exc:
        raise AcquisitionError("missing-path",
                               f"approved root cannot be resolved: {approved_root}") from exc
    if not root.is_dir():
        raise AcquisitionError("root-escape", f"approved root is not a directory: {root}")
    return root


def _file_candidate(given: Path, root: Path) -> Path:
    """Lexically resolve ``.``/``..`` and require containment in the root.

    A ``..`` that climbs outside the root is traversal; any other outside path
    is an escape; one that stays inside is admitted.
    """
    candidate = given if given.is_absolute() else root / given
    candidate = Path(os.path.normpath(str(candidate)))
    if _inside(candidate, root):
        return candidate
    if ".." in given.parts:
        raise AcquisitionError("traversal-refused",
                               f"path climbs outside the approved root: {given}")
    raise AcquisitionError("root-escape", f"path is outside the approved root: {given}")


def _check_parent(candidate: Path, root: Path) -> None:
    """Parents are admitted by resolved containment, not per-hop lstat. The
    root itself needs no parent admission; its parent lies outside by
    definition."""
    if candidate == root:
        return
    parent = candidate.parent
    if not parent.exists():
        raise AcquisitionError("missing-path", f"parent directory does not exist: {parent}")
    if not _inside(Path(os.path.realpath(parent)), root):
        raise AcquisitionError("root-escape",
                               f"parent resolves outside the approved root: {parent}")


def _check_final(candidate: Path) -> None:
    """lstat the final component: no symlinks, regular files only."""
    try:
        final = os.lstat(candidate)
    except FileNotFoundError:
        raise AcquisitionError("missing-path", f"path does not exist: {candidate}") from None
    except OSError as exc:
        raise AcquisitionError("missing-path", f"path cannot be inspected: {candidate}") from exc
    if stat.S_ISLNK(final.st_mode):
        raise AcquisitionError("symlink-refused", f"final component is a symlink: {candidate}")
    if not stat.S_ISREG(final.st_mode):
        raise AcquisitionError("not-regular", f"path is not a regular file: {candidate}")


def _read_flags() -> int:
    """Binary-safe, close-on-exec, no-follow open flags.

    ``os.O_NOFOLLOW`` is load-bearing: without it the platform cannot refuse a
    final-component symlink swap between lstat and open, so acquisition is
    refused instead of weakened. POSIX reads are binary by default; Windows
    supplies ``O_BINARY``.
    """
    if not hasattr(os, "O_NOFOLLOW"):
        raise AcquisitionError(
            "platform-unsupported",
            "trusted acquisition requires os.O_NOFOLLOW; this platform cannot "
            "refuse final-component symlink substitution at open time")
    return (os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0))


def _open_bounded(path: Path, *, label: str, max_bytes: int) -> bytes:
    """Open with no-follow flags; one bounded, identity-checked read."""
    try:
        fd = os.open(path, _read_flags())
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise AcquisitionError("symlink-refused",
                                   f"final component is a symlink: {path}") from exc
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            raise AcquisitionError("missing-path", f"path does not exist: {path}") from exc
        raise
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise AcquisitionError("not-regular", f"{label} is not a regular file")
        if before.st_size > max_bytes:
            raise AcquisitionError("oversized", f"{label} exceeds the {max_bytes}-byte cap")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(_READ_CHUNK, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise AcquisitionError("oversized", f"{label} exceeds the {max_bytes}-byte cap")
        after = os.fstat(fd)
        if _identity(before) != _identity(after) or total != after.st_size:
            raise AcquisitionError("changed-while-read", f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def acquire(path: Path, *, approved_root: Path, allowed_suffixes: frozenset[str],
            max_bytes: int, acquired_at: datetime) -> AcquisitionRecord:
    """Acquire bounded regular-file bytes from inside the approved root.

    Typed refusals: missing-path, symlink-refused, not-regular, oversized,
    suffix-refused, root-escape, traversal-refused, platform-unsupported,
    changed-while-read. The suffix gate runs before open; lstat checks run
    before the platform gate, so hosts without ``O_NOFOLLOW`` still refuse
    lexically and by inspection.
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    suffixes = frozenset(s if s.startswith(".") else "." + s
                         for s in (suffix.lower() for suffix in allowed_suffixes))
    if not suffixes:
        raise ValueError("allowed_suffixes must not be empty")
    given = Path(path)
    suffix = given.suffix.lower()
    if suffix not in suffixes:
        raise AcquisitionError("suffix-refused", f"suffix {suffix!r} is not approved")
    root = _resolve_root(approved_root)
    candidate = _file_candidate(given, root)
    _check_parent(candidate, root)
    _check_final(candidate)
    data = _open_bounded(candidate, label="acquisition", max_bytes=max_bytes)
    return AcquisitionRecord(
        logical_path=str(given), resolved_path=str(Path(os.path.realpath(candidate))),
        size_bytes=len(data), sha256=_digest(data), suffix=suffix, acquired_at=acquired_at)


def verify_unchanged(record: AcquisitionRecord, *, approved_root: Path) -> None:
    """Repeat the descriptor-discipline read and compare size and digest.

    A successor shorter than the record is ``truncated``; growth past the
    recorded size or any byte difference is ``digest-mismatch``; mutation
    inside the read window is ``changed-while-read``. Containment, symlink,
    and regular-file checks re-run exactly as in acquire.
    """
    root = _resolve_root(approved_root)
    resolved = Path(record.resolved_path)
    if ".." in resolved.parts:
        raise AcquisitionError("traversal-refused",
                               f"recorded locator contains traversal: {resolved}")
    candidate = Path(os.path.normpath(str(resolved)))
    if not _inside(candidate, root):
        raise AcquisitionError("root-escape",
                               f"recorded locator is outside the approved root: {resolved}")
    _check_parent(candidate, root)
    _check_final(candidate)
    try:
        data = _open_bounded(candidate, label="verification", max_bytes=record.size_bytes)
    except AcquisitionError as exc:
        if exc.reason == "oversized":
            raise AcquisitionError(
                "digest-mismatch",
                f"input grew past the recorded {record.size_bytes} bytes: {resolved}") from exc
        raise
    if len(data) < record.size_bytes:
        raise AcquisitionError("truncated",
                               f"input is shorter than the recorded bytes: {resolved}")
    if _digest(data) != record.sha256:
        raise AcquisitionError("digest-mismatch",
                               f"input bytes differ from the recorded digest: {resolved}")


def _directory_candidate(path: Path, root: Path) -> Path:
    """Containment and lstat checks for a manifest root directory."""
    candidate = _file_candidate(path, root)
    _check_parent(candidate, root)
    try:
        final = os.lstat(candidate)
    except OSError:
        raise AcquisitionError("missing-path", f"path does not exist: {candidate}") from None
    if stat.S_ISLNK(final.st_mode):
        raise AcquisitionError("symlink-refused", f"final component is a symlink: {candidate}")
    if not stat.S_ISDIR(final.st_mode):
        raise AcquisitionError("not-regular", f"manifest root is not a directory: {candidate}")
    return candidate


def _walk_directory(root: Path, *, max_entries: int, max_total_bytes: int,
                    max_depth: int) -> tuple[list[dict], int]:
    """Deterministic sorted walk, shared by manifest acquire and verify."""
    entries: list[dict] = []
    total = 0

    def walk(directory: Path, depth: int) -> None:
        nonlocal total
        if depth > max_depth:
            raise AcquisitionError("depth-cap-exceeded",
                                   f"directory nesting exceeds {max_depth}: {directory}")
        try:
            with os.scandir(directory) as scan:
                children = sorted(scan, key=lambda entry: entry.name)
        except OSError as exc:
            raise AcquisitionError("missing-path",
                                   f"directory cannot be listed: {directory}") from exc
        for child in children:
            if child.is_symlink():
                raise AcquisitionError("symlink-refused", f"entry is a symlink: {child.path}")
            if child.is_dir(follow_symlinks=False):
                walk(Path(child.path), depth + 1)
                continue
            if not child.is_file(follow_symlinks=False):
                raise AcquisitionError("not-regular",
                                       f"entry is not a regular file or directory: {child.path}")
            if len(entries) >= max_entries:
                raise AcquisitionError("entry-cap-exceeded",
                                       f"manifest exceeds {max_entries} entries")
            relative = Path(child.path).relative_to(root).as_posix()
            try:
                data = _open_bounded(Path(child.path), label=f"manifest entry {relative}",
                                     max_bytes=max_total_bytes)
            except AcquisitionError as exc:
                if exc.reason == "oversized":
                    raise AcquisitionError(
                        "byte-cap-exceeded",
                        f"manifest entry exceeds the {max_total_bytes}-byte cap: "
                        f"{relative}") from exc
                raise
            entries.append({"relative_path": relative, "size_bytes": len(data),
                            "sha256": _digest(data)})
            total += len(data)
            if total > max_total_bytes:
                raise AcquisitionError("byte-cap-exceeded",
                                       f"manifest exceeds {max_total_bytes} total bytes")

    walk(root, 0)
    entries.sort(key=lambda entry: entry["relative_path"])
    return entries, total


def acquire_directory(path: Path, *, approved_root: Path, max_entries: int,
                      max_total_bytes: int, max_depth: int,
                      acquired_at: datetime) -> DirectoryManifest:
    """Inventory a directory under the approved root without following links.

    Symlinks are refused anywhere, files are read through the shared bounded
    descriptor discipline, and the entry, byte, and depth caps fail closed
    (``max_depth`` bounds subdirectory nesting below the root, so 0 admits
    only a flat directory). Per-directory names and the final list both sort,
    so mtimes and insertion order never leak into the manifest.
    """
    if min(max_entries, max_total_bytes, max_depth + 1) <= 0:
        raise ValueError("manifest caps must be positive")
    candidate = _directory_candidate(Path(path), _resolve_root(approved_root))
    entries, total = _walk_directory(candidate, max_entries=max_entries,
                                     max_total_bytes=max_total_bytes, max_depth=max_depth)
    return DirectoryManifest(str(Path(os.path.realpath(candidate))), tuple(entries), total,
                             acquired_at)


def verify_directory_unchanged(manifest: DirectoryManifest, *, approved_root: Path) -> None:
    """Re-walk the manifest root and require byte-exact equality.

    Re-walk bounds derive from the manifest plus small fixed spares, so a
    grown tree is refused as a named ``digest-mismatch`` (added, removed, or
    changed entry) instead of consuming unbounded resources; pathological
    excess trips a cap and is remapped to digest-mismatch.
    """
    candidate = _directory_candidate(Path(manifest.resolved_path), _resolve_root(approved_root))
    recorded_depth = max((len(name.split("/")) for name in
                          (entry["relative_path"] for entry in manifest.entries)), default=1)
    try:
        walked, total = _walk_directory(candidate, max_entries=len(manifest.entries) + 16,
                                        max_total_bytes=manifest.total_bytes * 2 + 65_536,
                                        max_depth=recorded_depth + 1)
    except AcquisitionError as exc:
        if exc.reason in ("entry-cap-exceeded", "byte-cap-exceeded", "depth-cap-exceeded",
                          "oversized"):
            raise AcquisitionError("digest-mismatch",
                                   f"manifest tree changed beyond its recorded shape: {exc}") from exc
        raise
    recorded = {entry["relative_path"]: entry for entry in manifest.entries}
    seen = {entry["relative_path"]: entry for entry in walked}
    for name in sorted(recorded.keys() | seen.keys()):
        if name not in seen:
            raise AcquisitionError("digest-mismatch", f"manifest entry removed: {name}")
        if name not in recorded:
            raise AcquisitionError("digest-mismatch", f"manifest entry added: {name}")
        if recorded[name] != seen[name]:
            raise AcquisitionError("digest-mismatch", f"manifest entry changed: {name}")
    if total != manifest.total_bytes:
        raise AcquisitionError("digest-mismatch",
                               f"manifest total bytes moved to {total}: {candidate}")
