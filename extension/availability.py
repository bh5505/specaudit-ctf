"""Host profile and arm-availability report (read-only, Kali-aware).

The CTF suite is OS-agnostic Python; a host such as Kali contributes
*binaries and endpoints*, which is exactly what this module reports.
Kali detection follows the distribution's own canonical file
(`/etc/os-release` with `ID=kali`) — there is no `/etc/kali-release`.
Nothing here dispatches, invokes, or consults a scope.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Any

OS_RELEASE_CANDIDATES = ("/etc/os-release", "/usr/lib/os-release")
SCOPE_SUFFIX = "_DISPATCH_SCOPE"


def _parse_os_release(path: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return fields
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip().strip('"')
    return fields


def host_profile(*os_release_paths: str) -> dict[str, Any]:
    """Return a read-only host profile.

    On Linux hosts the os-release fields are parsed from the first
    readable candidate (override the candidates for tests). `is_kali` is
    the canonical `ID=kali` check. Note: multi-line quoted continuations
    (freedesktop spec) are not joined — none of the fields read here
    (ID/VERSION_ID/PRETTY_NAME) use them.
    """
    candidates = os_release_paths or OS_RELEASE_CANDIDATES
    release = {}
    for candidate in candidates:
        release = _parse_os_release(candidate)
        if release:
            break
    profile: dict[str, Any] = {
        "platform": platform.system(),
        "is_kali": release.get("ID") == "kali",
    }
    for key in ("ID", "VERSION_ID", "PRETTY_NAME"):
        if key in release:
            profile[f"os_{key.lower()}"] = release[key]
    return profile


def armed_scopes(environ: dict[str, str] | None = None) -> list[str]:
    """Names of the dispatch-scope env vars currently set (names only)."""
    environ = environ if environ is not None else os.environ
    return sorted(
        key
        for key in environ
        if key.endswith(SCOPE_SUFFIX) and environ[key].strip()
    )


def build_report(
    extension: Any,
    *,
    environ: dict[str, str] | None = None,
    os_release_paths: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Assemble the full availability report."""
    return {
        "host": host_profile(*os_release_paths),
        "armed_scopes": armed_scopes(environ),
        "arms": extension.availability(),
    }
