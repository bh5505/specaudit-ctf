"""Hermetic tests for tools/render_provenance_header.py (G5 durable)."""
from pathlib import Path

from tools.render_provenance_header import (
    inject_block,
    render_provenance_block,
)


def test_block_has_sentinels_and_digests(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello", encoding="utf-8")
    block = render_provenance_block([f], "gw-asmvm-20260902", [("pack", "/nonexist")])
    assert "<!-- PROVENANCE-BEGIN -->" in block
    assert "<!-- PROVENANCE-END -->" in block
    assert "gw-asmvm-20260902" in block
    assert "hello" and "2cf24dba5fb0a30e" in block  # sha256("hello")[:16] prefix
    assert "HEAD:" in block


def test_block_deterministic_between_runs(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("data", encoding="utf-8")
    b1 = render_provenance_block([f], "run-1", [])
    b2 = render_provenance_block([f], "run-1", [])
    assert b1 == b2  # stamp from mtime, not wall clock


def test_missing_receipt_flagged(tmp_path):
    block = render_provenance_block([tmp_path / "missing.json"], "run-2", [])
    assert "MISSING" in block
    assert "no-receipts" in block


def test_inject_block_replaces_existing(tmp_path):
    report = tmp_path / "r.md"
    report.write_text("a<!-- PROVENANCE-BEGIN -->old<!-- PROVENANCE-END -->z",
                      encoding="utf-8")
    block = render_provenance_block([], "run-3", [])
    out = inject_block(report.read_text(encoding="utf-8"), block)
    assert "old" not in out
    assert "<!-- PROVENANCE-BEGIN -->" in out


def test_inject_block_inserts_after_status(tmp_path):
    report = tmp_path / "r.md"
    report.write_text("# R\n\n**STATUS: DRAFT\n\nbody", encoding="utf-8")
    block = render_provenance_block([], "run-4", [])
    out = inject_block(report.read_text(encoding="utf-8"), block)
    assert out.index("<!-- PROVENANCE-BEGIN -->") > out.index("**STATUS: DRAFT")
