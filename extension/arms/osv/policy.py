"""Exact-allowlist rules for the osv advisory arm.

Two clearly separated layers share this policy:

  * the offline snapshot layer (``reader.py``) reads a caller-supplied,
    versioned local OSV-shaped snapshot — no network, ever;
  * the live layer (``api.py``) issues bounded read-only queries against the
    fixed official host below.

The arm is keyed by package coordinate (ecosystem + name) or commit, never by
CVE string alone: an alias is not record identity, the OSV id is.
"""

from __future__ import annotations

import re
from pathlib import Path

ARM_ID = "osv"

ALLOWED_ACTIONS = frozenset({"read_snapshot", "get_advisory", "query_package", "query_commit"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000

# --- Snapshot layer bounds ---------------------------------------------------
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_SNAPSHOT_RECORDS = 10_000
MAX_RECORD_BYTES = 256 * 1024
MAX_TEXT = 16_384
MAX_DOCUMENT_NODES = 50_000
MAX_DOCUMENT_DEPTH = 64
SNAPSHOT_SUFFIXES = (".json",)
DEMO_SNAPSHOT_NAME = "demo-osv-snapshot.json"

# The only accepted snapshot container version; anything else (including a
# future or past marker) is refused rather than best-effort parsed.
SNAPSHOT_SCHEMA = "specaudit-ctf.osv-snapshot/1"

# --- Live layer bounds (campaign design caps) --------------------------------
# The endpoint is fixed: nothing caller-selectable about scheme, host, or
# path. Queries are read-only POSTs to the official v1 query API.
OSV_API_HOST = "https://api.osv.dev"
OSV_QUERY_PATH = "/v1/query"
OSV_ADVISORY_BASE_URL = "https://osv.dev/vulnerability/"
USER_AGENT = "specaudit-ctf-osv-arm/1.0"

LIVE_TIMEOUT_SECONDS = 10.0
MAX_PAGES = 10
MAX_LIVE_RECORDS = 100
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
EVIDENCE_BODY_BYTES = 512
_READ_CHUNK = 64 * 1024

# --- Argument validation ------------------------------------------------------
ARG_KEYS: dict[str, frozenset[str]] = {
    "read_snapshot": frozenset({"snapshot"}),
    "get_advisory": frozenset({"snapshot", "id"}),
    "query_package": frozenset({"ecosystem", "name", "version", "purl"}),
    "query_commit": frozenset({"commit"}),
}

_MAX_ARG_TEXT = 4096
_PURL_RE = re.compile(r"^pkg:[A-Za-z0-9._-]+/[^@\s]+(@[^@\s]+)?$")
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")

CAVEATS = (
    "snapshot actions are offline reads over a caller-supplied local "
    "OSV-shaped snapshot; live actions are read-only queries against the "
    "fixed official API host " + OSV_API_HOST,
    "advisory context only: a match for a package coordinate or commit is "
    "not a finding, a grade, or a security verdict for any code",
    "aliases (including CVE aliases) are not record identity; the OSV id is",
    "withdrawn records stay flagged as withdrawn and are never flattened "
    "into unqualified results",
    "this listing describes the interface only and makes no claim about "
    "snapshot coverage or live service availability",
    "the client caps pagination (10 pages, 100 records, 2 MiB per response, "
    "10 s overall), follows every page token, never retries, and refuses "
    "redirects and environment proxies",
)

INPUT_HINT = (
    "pass args.snapshot (path to a local .json snapshot) to read_snapshot, "
    "plus args.id for get_advisory; pass args.ecosystem + args.name + "
    "args.version, or args.purl (+ args.version for an unversioned purl) to "
    "query_package, or args.commit (40-hex) to query_commit"
)

SNAPSHOT_LIMITATIONS = (
    "offline frozen snapshot: records reflect snapshot_time only; the live "
    "service may carry newer modified values",
    "all records are CTF-owned synthetic OSV-shaped data; no verbatim "
    "upstream OSV records are retained in this repository",
    "coordinate range matching compares dotted-numeric versions; versions "
    "that are not dotted-numeric match only via explicit versions lists",
)

LIVE_LIMITATIONS = (
    "live advisory context only: results are contextual and cannot change a "
    "challenge grade or assert code safety",
    "aliases (including CVE aliases) are not record identity; the OSV id is",
)


def snapshot_refusal(
    raw: object, *, max_bytes: int = MAX_SNAPSHOT_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local snapshot path (local file, not URL)."""
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local snapshot path in args.snapshot"
    text = raw.strip()
    if "://" in text:
        return None, "args.snapshot must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.snapshot contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, f"args.snapshot is not an existing file: {text}"
    if path.suffix.lower() not in SNAPSHOT_SUFFIXES:
        return None, f"args.snapshot must name a .json file, got suffix {path.suffix!r}"
    try:
        size = path.stat().st_size
    except OSError:
        return None, "args.snapshot could not be read"
    if size > max_bytes:
        return None, (
            f"args.snapshot exceeds the {max_bytes} byte read cap ({size} bytes); "
            "supply a smaller snapshot"
        )
    return path, None


def advisory_id_refusal(raw: object) -> str | None:
    """Validate the exact OSV id argument for get_advisory."""
    problem = _bounded_text_refusal(raw, "args.id")
    if problem:
        return problem
    assert isinstance(raw, str)
    if raw != raw.strip():
        return "args.id must not carry surrounding whitespace"
    return None


def args_refusal(action: str, payload: dict) -> str | None:
    """Refuse unknown or missing caller arguments per action.

    query_package accepts exactly one coordinate form: ecosystem+name+version,
    unversioned purl+version, or a versioned purl alone. Mixing purl with
    name/ecosystem, or version with a versioned purl, is refused — the OSV
    query API documents these combinations as errors.
    """
    if any(not isinstance(key, str) for key in payload):
        return "caller argument names must be strings"
    allowed = ARG_KEYS.get(action)
    if allowed is None:
        return f"action {action!r} is not on the read allowlist"
    extra = sorted(set(payload) - allowed)
    if extra:
        return (
            f"osv {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )

    if action in ("read_snapshot", "get_advisory"):
        if "snapshot" not in payload:
            return "this action requires a local snapshot path in args.snapshot"
        if action == "get_advisory":
            if "id" not in payload:
                return "get_advisory requires args.id (the exact OSV advisory id)"
            return advisory_id_refusal(payload["id"])
        return None

    if action == "query_commit":
        if "commit" not in payload:
            return "query_commit requires args.commit (a 40-hex commit hash)"
        value = payload["commit"]
        if not isinstance(value, str) or not _COMMIT_RE.fullmatch(value.strip()):
            return "args.commit must be a 40-character hexadecimal commit hash"
        if value != value.strip():
            return "args.commit must not carry surrounding whitespace"
        return None

    has_coordinate = any(key in payload for key in ("ecosystem", "name"))
    has_purl = "purl" in payload
    if has_purl and has_coordinate:
        return "args.purl must not be combined with args.ecosystem or args.name"
    if has_coordinate:
        missing = sorted({"ecosystem", "name", "version"} - set(payload))
        if missing:
            return (
                "query_package by coordinate requires args.ecosystem, args.name "
                f"and args.version (missing: {', '.join(missing)})"
            )
        for key in ("ecosystem", "name", "version"):
            problem = _bounded_text_refusal(payload[key], f"args.{key}")
            if problem:
                return problem
        return None
    if has_purl:
        problem = _bounded_text_refusal(payload["purl"], "args.purl")
        if problem:
            return problem
        purl = payload["purl"].strip()
        if not _PURL_RE.fullmatch(purl):
            return (
                "args.purl must look like pkg:type/name[@version] "
                "(basic purl syntax)"
            )
        versioned = "@" in purl
        if versioned and "version" in payload:
            return "args.version must not accompany a versioned purl"
        if not versioned and "version" not in payload:
            return "an unversioned args.purl requires args.version"
        if "version" in payload:
            problem = _bounded_text_refusal(payload["version"], "args.version")
            if problem:
                return problem
        return None
    return (
        "query_package requires one coordinate form: args.ecosystem + "
        "args.name + args.version, or args.purl (with args.version when the "
        "purl is unversioned)"
    )


def _bounded_text_refusal(raw: object, label: str) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return f"{label} must be a non-empty string"
    if any(ord(ch) < 0x20 for ch in raw):
        return f"{label} contains control characters"
    if len(raw) > _MAX_ARG_TEXT:
        return f"{label} exceeds the {_MAX_ARG_TEXT} character bound"
    return None


def demo_snapshot_path() -> Path:
    return Path(__file__).resolve().parent / "data" / DEMO_SNAPSHOT_NAME
