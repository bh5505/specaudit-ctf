"""Verdict-vocabulary drift guard — hermetic tests.

The live repository must pass the guard (schemas and code agree
today); synthetic drift must fail closed, naming both sides. The
cross-schema duplicate checks (safety_class / side_effects copied
into both schemas) must catch the two schema copies drifting apart,
not just schema-vs-code drift.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import score.drift as drift_mod
from score.drift import _check, _duplicate_check, _schema_enum, drift_check

ROOT = Path(__file__).resolve().parent.parent
EXECUTION_SCHEMA = ROOT / "extension" / "schema" / "execution-result.v1.schema.json"
MANIFEST_SCHEMA = ROOT / "extension" / "schema" / "capability.manifest.v1.schema.json"

_ALL_DOMAINS = {
    "status_domain",
    "side_effects_domain",
    "safety_class_domain",
    "tier_domain",
    "kind_domain",
    "protocols_domain",
    "cleanup_proof_domain",
    "safety_class_schema_dup",
    "side_effects_schema_dup",
}


def test_live_repository_has_no_drift() -> None:
    report = drift_check()
    assert report["ok"] is True, report
    assert set(report["checks"]) == _ALL_DOMAINS
    for name, check in report["checks"].items():
        assert check["ok"] is True, (name, check["detail"])


def test_live_schema_duplicates_are_checked_not_assumed() -> None:
    # The duplicate checks read real enums from BOTH schema files on
    # the live tree (an accidentally-renamed pointer would otherwise
    # silently downgrade to comparing against nothing).
    for pointer in ("/definitions/safety_class", "/definitions/side_effects/items"):
        assert _schema_enum(EXECUTION_SCHEMA, pointer) is not None, pointer
        assert _schema_enum(MANIFEST_SCHEMA, pointer) is not None, pointer


def test_schema_duplicate_drift_fails_closed_naming_both_sides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exec_side = tmp_path / "execution-result.v1.schema.json"
    manifest_side = tmp_path / "capability.manifest.v1.schema.json"
    exec_side.write_text(
        json.dumps(
            {"definitions": {"safety_class": {"type": "string", "enum": ["R0", "R1"]}}}
        ),
        encoding="utf-8",
    )
    manifest_side.write_text(
        json.dumps(
            {"definitions": {"safety_class": {"type": "string", "enum": ["R0", "R9"]}}}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(drift_mod, "_EXECUTION_SCHEMA", exec_side)
    monkeypatch.setattr(drift_mod, "_MANIFEST_SCHEMA", manifest_side)
    check = _duplicate_check("/definitions/safety_class")
    assert check["ok"] is False
    assert check["schema_only"] == ["R9"]
    assert check["code_only"] == ["R1"]
    assert "execution-result schema" in check["detail"]


def test_unreadable_reference_side_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_side = tmp_path / "capability.manifest.v1.schema.json"
    manifest_side.write_text(
        json.dumps(
            {"definitions": {"safety_class": {"type": "string", "enum": ["R0"]}}}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(drift_mod, "_EXECUTION_SCHEMA", tmp_path / "missing.json")
    monkeypatch.setattr(drift_mod, "_MANIFEST_SCHEMA", manifest_side)
    check = _duplicate_check("/definitions/safety_class")
    assert check["ok"] is False
    assert "reference enum unreadable" in check["detail"]
    assert check["schema_only"] == [] and check["code_only"] == []


def test_drift_fails_closed_naming_both_sides() -> None:
    # Schema side has a value the code lost...
    check = _check(
        EXECUTION_SCHEMA,
        "/properties/status",
        ["complete", "degraded"],
    )
    assert check["ok"] is False
    assert check["schema_only"] == ["failed"]
    # ...and the mirror: the code enforces a value the schema lacks.
    mirror = _check(
        EXECUTION_SCHEMA,
        "/properties/status",
        ["complete", "degraded", "failed", "sideways"],
    )
    assert mirror["ok"] is False
    assert mirror["code_only"] == ["sideways"]


def test_unreadable_schema_side_fails_closed(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    check = _check(missing, "/properties/status", ["complete"])
    assert check["ok"] is False
    assert "unreadable" in check["detail"]
    assert "nope.json" in check["detail"]


def test_valid_json_without_enum_at_pointer_returns_none(tmp_path: Path) -> None:
    no_enum = tmp_path / "no_enum.json"
    no_enum.write_text(
        '{"properties": {"status": {"type": "string"}}}', encoding="utf-8"
    )
    assert _schema_enum(no_enum, "/properties/status") is None


def test_cli_exit_codes(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    ok = subprocess.run(
        [sys.executable, "-m", "score.drift"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert ok.returncode == 0
    assert '"ok": true' in ok.stdout

    # Forced failure path: main() must still print JSON and exit 1.
    import score.drift as drift_mod

    monkeypatch.setattr(
        drift_mod, "drift_check", lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    code = drift_mod.main()
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["ok"] is False
    assert "RuntimeError" in report["error"]
