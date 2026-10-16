"""Canonical SHA-256 tree digest for a producer/runtime bundle.

This is a byte-for-byte Python port of the private Rust consumer's
``hash_producer_bundle`` implementation (not vendored here). The builder and
the validator MUST agree on this digest
without either side trusting the other's implementation, so the algorithm
is pinned here in prose as well as in code:

1. Walk the tree from ``root``. Refuse (raise :class:`TreeHashError`) on
   any symlink, hardlink (a regular file whose ``st_nlink != 1``), device,
   fifo, socket, or other non-regular/non-directory entry; on any entry
   name that is not valid UTF-8, is empty, exceeds 255 bytes, is ``.`` or
   ``..``, contains ``/``, ``\\``, a NUL byte, or a control character; on
   any directory or file with a write bit set for owner/group/other; on
   depth beyond 32; on more than 65,536 entries; on a file over
   256 MiB or a tree over 512 MiB in aggregate.
2. Collect one entry per directory (except the root itself) and one entry
   per regular file, each keyed by its ``/``-joined relative path.
3. Sort all entries by that path as a sequence of Unicode code points
   (Python's default string ordering and Rust's ``str::cmp`` agree here
   because both compare valid UTF-8 by code point).
4. Hash, in that sorted order: a domain-separator prefix, then for each
   entry a one-byte kind tag (``d`` or ``f``), the path's byte length as
   an 8-byte little-endian integer, the path bytes, and — for files only —
   the file's byte length as an 8-byte little-endian integer followed by
   the raw SHA-256 of the file's bytes.

The digest is rendered as ``sha256:<64 lowercase hex>``.
"""

from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path

BUNDLE_TREE_DOMAIN = b"specaudit.ctf.producer-tree.v1"

MAX_BUNDLE_ENTRIES = 65_536
MAX_BUNDLE_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_FILE_BYTES = 256 * 1024 * 1024
MAX_BUNDLE_DEPTH = 32
MAX_BUNDLE_NAME_BYTES = 255

_KIND_DIR = 0x64  # b'd'
_KIND_FILE = 0x66  # b'f'


class TreeHashError(ValueError):
    """The tree does not qualify for a canonical digest."""


@dataclass(frozen=True)
class _Entry:
    path: str
    kind: int
    size: int
    content_sha256: bytes


def _validate_name(name: str) -> str:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise TreeHashError(f"entry name is not valid UTF-8: {name!r}") from exc
    if (
        not name
        or len(encoded) > MAX_BUNDLE_NAME_BYTES
        or name in (".", "..")
        or "/" in name
        or "\\" in name
        or "\0" in name
        or any(unicodedata.category(ch) == "Cc" for ch in name)
    ):
        raise TreeHashError(f"rejected entry name: {name!r}")
    return name


def _mode_has_write(mode: int) -> bool:
    return bool(mode & 0o222)


def _walk(
    abs_path: Path,
    rel_parts: tuple[str, ...],
    depth: int,
    entries: list[_Entry],
    seen_files: set[tuple[int, int]],
    total_bytes: list[int],
) -> None:
    if depth > MAX_BUNDLE_DEPTH:
        raise TreeHashError("bundle exceeds max depth")
    top = os.lstat(abs_path)
    if stat.S_ISLNK(top.st_mode):
        raise TreeHashError(f"symlink is not permitted: {abs_path}")
    if not stat.S_ISDIR(top.st_mode):
        raise TreeHashError(f"not a directory: {abs_path}")
    if _mode_has_write(top.st_mode):
        raise TreeHashError(f"directory has a write bit set: {abs_path}")

    if rel_parts:
        if len(entries) >= MAX_BUNDLE_ENTRIES:
            raise TreeHashError("bundle exceeds max entry count")
        entries.append(_Entry("/".join(rel_parts), _KIND_DIR, 0, b"\x00" * 32))

    children = sorted(os.listdir(abs_path))
    for name in children:
        validated = _validate_name(name)
        child_abs = abs_path / validated
        child_rel = rel_parts + (validated,)
        if len(entries) >= MAX_BUNDLE_ENTRIES:
            raise TreeHashError("bundle exceeds max entry count")
        child_stat = os.lstat(child_abs)
        if stat.S_ISLNK(child_stat.st_mode):
            raise TreeHashError(f"symlink is not permitted: {child_abs}")
        if stat.S_ISDIR(child_stat.st_mode):
            _walk(child_abs, child_rel, depth + 1, entries, seen_files, total_bytes)
            continue
        if not stat.S_ISREG(child_stat.st_mode):
            raise TreeHashError(f"non-regular entry is not permitted: {child_abs}")
        if _mode_has_write(child_stat.st_mode):
            raise TreeHashError(f"file has a write bit set: {child_abs}")
        if child_stat.st_nlink != 1:
            raise TreeHashError(f"hardlinked file is not permitted: {child_abs}")
        identity = (child_stat.st_dev, child_stat.st_ino)
        if identity in seen_files:
            raise TreeHashError(f"duplicate file identity: {child_abs}")
        seen_files.add(identity)
        size = child_stat.st_size
        if size > MAX_BUNDLE_FILE_BYTES:
            raise TreeHashError(f"file exceeds max size: {child_abs}")
        total_bytes[0] += size
        if total_bytes[0] > MAX_BUNDLE_BYTES:
            raise TreeHashError("bundle exceeds max aggregate size")
        digest = _hash_file(child_abs, expected_size=size)
        entries.append(_Entry("/".join(child_rel), _KIND_FILE, size, digest))


def _hash_file(path: Path, *, expected_size: int) -> bytes:
    hasher = hashlib.sha256()
    total = 0
    # O_NOFOLLOW is the same no-follow-on-reopen discipline the Rust
    # verifier applies; a symlink swapped in after the lstat above raises
    # ELOOP here instead of silently following it.
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size != expected_size:
                raise TreeHashError(f"file identity/type changed while opening: {path}")
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BUNDLE_FILE_BYTES:
                    raise TreeHashError(f"file exceeds max size while reading: {path}")
                hasher.update(chunk)
    except OSError as exc:
        raise TreeHashError(f"unreadable file: {path}: {exc}") from exc
    if total != expected_size:
        raise TreeHashError(f"file size changed while hashing: {path}")
    return hasher.digest()


def hash_producer_bundle(root: str | Path) -> str:
    """Return ``sha256:<hex>`` for the canonical tree at ``root``.

    Raises :class:`TreeHashError` on anything the Rust verifier would also
    refuse (symlinks, hardlinks, write bits, oversize, bad names, ...) so a
    bundle that fails to hash here would also fail validator admission.
    """
    root_path = Path(root)
    if not root_path.is_absolute():
        raise TreeHashError("bundle root must be an absolute path")
    entries: list[_Entry] = []
    seen_files: set[tuple[int, int]] = set()
    total_bytes = [0]
    _walk(root_path, (), 0, entries, seen_files, total_bytes)
    entries.sort(key=lambda entry: entry.path)
    hasher = hashlib.sha256()
    hasher.update(BUNDLE_TREE_DOMAIN)
    hasher.update(b"\x00")
    previous: str | None = None
    for entry in entries:
        if previous == entry.path:
            raise TreeHashError(f"duplicate path in sorted entries: {entry.path}")
        previous = entry.path
        hasher.update(bytes((entry.kind,)))
        path_bytes = entry.path.encode("utf-8")
        hasher.update(len(path_bytes).to_bytes(8, "little"))
        hasher.update(path_bytes)
        if entry.kind == _KIND_FILE:
            hasher.update(entry.size.to_bytes(8, "little"))
            hasher.update(entry.content_sha256)
    return f"sha256:{hasher.hexdigest()}"


def hash_file(path: str | Path) -> str:
    """Return ``sha256:<hex>`` of one file's raw bytes (the launcher pin)."""
    path = Path(path)
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            hasher.update(chunk)
    return f"sha256:{hasher.hexdigest()}"
