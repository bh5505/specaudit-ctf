"""Exact-argv rules for the idwolf offline report reader."""

from __future__ import annotations

from pathlib import Path

ARM_ID = "idwolf"

# Read tier: exact lookups over a local IDWolf analyzer JSONL export.
# There is no dispatch tier: the arm is an in-process bounded local-file
# reader with no subprocess, no collector, and no network on any tier.
ALLOWED_ACTIONS = frozenset({"summary", "list_findings", "finding"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})

MAX_OUTPUT_CHARS = 200_000
MAX_REPORT_BYTES = 8 * 1024 * 1024  # 8 MiB
MAX_LINE_BYTES = 64 * 1024  # 64 KiB per JSONL line
MAX_RECORDS = 5_000
MAX_FINDINGS = 200  # per listing page
REPORT_SUFFIXES = (".jsonl",)

# Evidence entries name at most this many offending runs; beyond it the
# evidence list is truncated with a flag instead of failing the output cap.
MAX_EVIDENCE_RUNS = 20

# Per-action caller-argument contracts (everything else is refused).
ARG_KEYS: dict[str, frozenset[str]] = {
    "summary": frozenset({"report"}),
    "list_findings": frozenset({"report", "limit", "severity", "source_kind"}),
    "finding": frozenset({"report", "run_id", "finding_id"}),
}

SEVERITIES = ("Critical", "High", "Medium", "Low")
SOURCE_KINDS = ("ad", "entra")
KNOWN_TOOL_VERSIONS = frozenset({"1.2"})

CAVEATS = (
    "offline reads over an operator-supplied local IDWolf analyzer JSONL export",
    "list_tools is an interface listing and makes no claim about source coverage",
    "completeness requires each summary's coverage and finding counts to match "
    "its exported rows; a successful parse never attests that all checks ran "
    "or that the tenant or domain is secure",
    "score_reliable=false questions the score, not the coverage; alone it does "
    "not make a run partial",
    "default views omit detail, object_dn, and tenant_id; the exact finding "
    "action returns the full documented row",
    "no shared writes; this is a read-only in-process evidence arm",
)

INPUT_HINT = (
    "pass args.report (path to a local IDWolf analyzer export in JSONL); "
    "list_findings takes optional limit/severity/source_kind filters and the "
    "finding action takes run_id plus finding_id"
)


def report_refusal(
    raw: object, *, max_bytes: int = MAX_REPORT_BYTES
) -> tuple[Path | None, str | None]:
    """Validate a caller-supplied local report path.

    Input contract: the report must be an existing local .jsonl file; URLs
    and control characters are refused, expanduser is honored.  Returns
    (path, None) or (None, refusal).
    """
    if not isinstance(raw, str) or not raw.strip():
        return None, "this action requires a local IDWolf report path in args.report"
    text = raw.strip()
    if "://" in text:
        return None, "args.report must be a local file, not a URL"
    if any(ord(ch) < 0x20 for ch in text):
        return None, "args.report contains control characters"
    path = Path(text).expanduser()
    if not path.is_file():
        return None, "args.report is not an existing file"
    if path.suffix.lower() not in REPORT_SUFFIXES:
        return None, (
            f"args.report must be a .jsonl analyzer export, got suffix {path.suffix!r}"
        )
    try:
        size = path.stat().st_size
    except OSError:
        return None, "args.report could not be read"
    if size > max_bytes:
        return None, (
            f"args.report exceeds the {max_bytes} byte read cap "
            f"({size} bytes); supply a smaller export"
        )
    return path, None


def demo_report_paths() -> tuple[Path, ...]:
    """Shipped synthetic reader-demo reports, in stable order."""
    data = Path(__file__).resolve().parent / "data"
    return (
        data / "demo-idwolf-ad.jsonl",
        data / "demo-idwolf-entra.jsonl",
        data / "demo-idwolf-partial.jsonl",
    )


def args_refusal(action: str, payload: dict) -> str | None:
    """Refuse unknown or missing caller arguments per action."""
    if any(not isinstance(key, str) for key in payload):
        return "caller argument names must be strings"
    allowed = ARG_KEYS.get(action)
    if allowed is None:
        return f"action {action!r} is not on the read allowlist"
    extra = sorted(set(payload) - allowed)
    if extra:
        return (
            f"idwolf {action} takes only args."
            + ", args.".join(sorted(allowed))
            + f" (unexpected: {', '.join(extra)})"
        )
    if "report" not in payload:
        return "this action requires a local IDWolf report path in args.report"
    if action == "list_findings":
        result = limit_refusal(payload.get("limit"))
        if isinstance(result, str):
            return result
        severity = payload.get("severity")
        if severity is not None and (
            not isinstance(severity, str) or severity.strip() not in SEVERITIES
        ):
            return "args.severity must be one of " + ", ".join(SEVERITIES)
        source_kind = payload.get("source_kind")
        if source_kind is not None and (
            not isinstance(source_kind, str) or source_kind.strip() not in SOURCE_KINDS
        ):
            return "args.source_kind must be one of " + ", ".join(SOURCE_KINDS)
    if action == "finding":
        for key in ("run_id", "finding_id"):
            value = payload.get(key)
            if not isinstance(value, str) or not value.strip():
                return f"finding requires args.{key}"
    return None


def limit_refusal(raw: object) -> int | str:
    """Validate and return the listing limit (1..MAX_FINDINGS) or a refusal."""
    if raw is None:
        return MAX_FINDINGS
    if not isinstance(raw, int) or isinstance(raw, bool):
        return f"args.limit must be an integer (1-{MAX_FINDINGS})"
    if raw < 1 or raw > MAX_FINDINGS:
        return f"args.limit must be between 1 and {MAX_FINDINGS}"
    return raw
