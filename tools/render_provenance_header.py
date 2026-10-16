"""Durable self-refreshing provenance header renderer (G5).

Idempotently renders/replaces a PROVENANCE block between sentinel markers in a
markdown report: generation stamp, run-id, sha256 digests of every cited
receipt, and the HEAD of each tracked repo. The generation stamp derives from
the receipts' max mtime (not wall clock), so two consecutive runs produce
byte-identical output -- the idempotence contract.

Generic replacement for the session-scoped G5 renderer: the receipts list and
report path are CLI-driven rather than hardcoded to a single session tree.

Core `render_provenance_block()` is pure-stdlib; CLI reads a receipts manifest
(a JSON array of file paths) and updates the target markdown.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BEGIN = "<!-- PROVENANCE-BEGIN -->"
END = "<!-- PROVENANCE-END -->"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _git_head(repo: str) -> str:
    try:
        out = subprocess.run(["git", "-C", repo, "rev-parse", "--short=9", "HEAD"],
                             capture_output=True, text=True)
        return out.stdout.strip() or "unavailable"
    except Exception:
        return "unavailable"


def render_provenance_block(receipts: list[Path], run_id: str,
                            repo_heads: list[tuple[str, str]]) -> str:
    """Build the sentinel-delimited provenance block (deterministic on mtime)."""
    digests = [(str(p), _sha256(p) if p.exists() else "MISSING") for p in receipts]
    existing = [p for p in receipts if p.exists()]
    ts_src = max((p.stat().st_mtime for p in existing), default=0)
    stamp = datetime.fromtimestamp(ts_src, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") \
        if existing else "no-receipts"
    lines = [
        BEGIN,
        f"<!-- rendered by render_provenance_header.py; deterministic on artifact mtimes -->",
        f"- run-id pinned: `{run_id}`",
        f"- generation stamp (max receipt mtime): {stamp}",
        "- receipts:",
    ] + [f"  - `{rel}` -> `{d}`" for rel, d in digests] + [
        *[f"- {label} HEAD: `{_git_head(repo)}`" for label, repo in repo_heads],
        END,
    ]
    return "\n".join(lines) + "\n"


def inject_block(markdown: str, block: str) -> str:
    """Replace the existing PROVENANCE block, or insert after the STATUS line."""
    if BEGIN in markdown:
        pre, rest = markdown.split(BEGIN, 1)
        _, post = rest.split(END, 1)
        return pre + block.rstrip("\n") + post
    pos = markdown.find("**STATUS:")
    if pos == -1:
        return markdown.rstrip("\n") + "\n\n" + block
    end_of_line = markdown.find("\n", pos)
    return markdown[:end_of_line] + "\n\n" + block.rstrip("\n") + markdown[end_of_line:]


def main() -> int:
    ap = argparse.ArgumentParser(description="render provenance header into a report")
    ap.add_argument("--report", required=True, help="markdown report to update")
    ap.add_argument("--receipts", required=True, help="json array of receipt file paths")
    ap.add_argument("--run-id", required=True, help="pinned run identifier")
    ap.add_argument("--repo", action="append", default=[],
                    help="label=path of a tracked repo to pin HEAD (repeatable)")
    a = ap.parse_args()

    receipts = [Path(p) for p in json.load(open(a.receipts, encoding="utf-8"))]
    repo_heads = []
    for item in a.repo:
        label, path = item.split("=", 1)
        repo_heads.append((label, path))
    block = render_provenance_block(receipts, a.run_id, repo_heads)
    report = Path(a.report)
    new_text = inject_block(report.read_text(encoding="utf-8"), block)
    report.write_text(new_text, encoding="utf-8")
    print(f"rendered provenance header ({len(receipts)} receipts) -> {a.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
