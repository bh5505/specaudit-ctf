"""Synthetic range fixtures: data in to exposure / path / impact out."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

import pytest

from extension.contract import (
    CATALOG_KIND_ARM,
    Catalog,
    CatalogEntry,
    Extension,
    Result,
    default_extension,
)
from extension.envelopes import RESULT_SCHEMA_ID
from extension.range import (
    ARM_ACTION,
    DEFAULT_SEED,
    FIXTURE_CHAIN_INGRESS_ROLE,
    FIXTURE_CLOUDTRAIL_DISABLED,
    FIXTURE_IAM_ASSUME_ROLE,
    FIXTURE_IAM_EXTERNAL_TRUST,
    FIXTURE_IAM_OPEN,
    FIXTURE_S3_NO_ACCESS_LOGGING,
    FIXTURE_S3_POLICY_BLOCKED,
    FIXTURE_S3_PUBLIC,
    FIXTURE_S3_UNENCRYPTED,
    FIXTURE_SG_OPEN_INGRESS,
    SCHEMA_ID,
    RangeError,
    default_range_root,
    run_range,
)
from extension.range.__main__ import main
from extension.range.runner import (
    _document_status,
    _fixture_status,
    _load_expected,
    derive_lifecycle,
)

ROOT = Path(__file__).resolve().parents[1]
RANGE_ROOT = ROOT / "extension" / "range"
CURATED_ARM_ID = "burp-mcp"
FIXTURE_ARM_ID = "probe-cli"
RANGE_SCHEMA_V3 = "range.lifecycle.v3"
_ALL_FIXTURES = (
    FIXTURE_S3_PUBLIC,
    FIXTURE_IAM_OPEN,
    FIXTURE_IAM_ASSUME_ROLE,
    FIXTURE_IAM_EXTERNAL_TRUST,
    FIXTURE_SG_OPEN_INGRESS,
    FIXTURE_CLOUDTRAIL_DISABLED,
    FIXTURE_S3_NO_ACCESS_LOGGING,
    FIXTURE_S3_POLICY_BLOCKED,
    FIXTURE_S3_UNENCRYPTED,
    FIXTURE_CHAIN_INGRESS_ROLE,
)
_RANGE_STATUSES = {"complete", "degraded", "failed"}
_COVERAGE_KEYS = ("attempted", "complete", "skipped", "error")


def _assert_v3_status(row: dict[str, Any], expected: str) -> None:
    assert SCHEMA_ID == RANGE_SCHEMA_V3
    if "schema" in row:
        assert row["schema"] == RANGE_SCHEMA_V3
    assert expected in _RANGE_STATUSES
    assert row["status"] == expected
    assert row["ok"] is (expected == "complete")
    coverage = row["coverage"]
    for key in _COVERAGE_KEYS:
        assert isinstance(coverage[key], list)
        assert coverage[key] == list(dict.fromkeys(coverage[key]))


def _assert_fixture_v3(row: dict[str, Any], expected: str) -> None:
    assert expected in _RANGE_STATUSES
    assert row["status"] == expected
    assert row["ok"] is (expected == "complete")
    coverage = row["coverage"]
    for key in _COVERAGE_KEYS:
        assert isinstance(coverage[key], list)
    attempted = [item["arm_id"] for item in row["arms"]]
    assert coverage["attempted"] == attempted
    assert coverage["complete"] == [
        item["arm_id"] for item in row["arms"] if item["status"] == "ok"
    ]
    assert coverage["skipped"] == [
        item["arm_id"] for item in row["arms"] if item["status"] == "skipped"
    ]
    assert coverage["error"] == [
        item["arm_id"] for item in row["arms"] if item["status"] == "error"
    ]


def _mismatch_range_root(tmp_path: Path, *, also_match: bool = False) -> Path:
    broken_id = "tf_mismatch"
    src = RANGE_ROOT / FIXTURE_S3_PUBLIC
    dst = tmp_path / broken_id
    shutil.copytree(src, dst)
    expected = json.loads((dst / "expected.json").read_text(encoding="utf-8"))
    expected["exposure"]["summary"] = "deliberately wrong"
    (dst / "expected.json").write_text(json.dumps(expected), encoding="utf-8")
    fixtures = [broken_id]
    if also_match:
        match_id = FIXTURE_IAM_OPEN
        shutil.copytree(RANGE_ROOT / match_id, tmp_path / match_id)
        fixtures.append(match_id)
    (tmp_path / "manifest.json").write_text(
        json.dumps({"version": 1, "live_aws": False, "fixtures": fixtures}),
        encoding="utf-8",
    )
    return tmp_path


def apply_no_curated_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    # Hermetic: no endpoint envs, and no PATH-discovered CLI binaries
    # even when the host machine really has them installed.
    monkeypatch.delenv("BURP_MCP_ENDPOINT", raising=False)
    monkeypatch.delenv("SEMGREP_MCP_ENDPOINT", raising=False)
    monkeypatch.delenv("CHECKOV_BIN", raising=False)
    monkeypatch.delenv("PROWLER_MCP_ENDPOINT", raising=False)
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setattr(
        "extension.arms.checkov.arm.resolve_binary", lambda: None
    )
    monkeypatch.delenv("GARAK_BIN", raising=False)
    monkeypatch.delenv("GARAK_TARGET", raising=False)
    monkeypatch.setattr(
        "extension.arms.garak.arm.resolve_binary", lambda: None
    )
    monkeypatch.delenv("ZAP_API_ENDPOINT", raising=False)
    monkeypatch.delenv("WAPITI_BIN", raising=False)
    monkeypatch.setattr(
        "extension.arms.wapiti.arm.resolve_binary", lambda: None
    )
    monkeypatch.delenv("COMMIX_BIN", raising=False)
    monkeypatch.setattr(
        "extension.arms.commix.arm.resolve_binary", lambda: None
    )
    monkeypatch.delenv("MITREATTACK_BIN", raising=False)
    monkeypatch.setattr(
        "extension.arms.mitreattack.arm.resolve_binary", lambda: None
    )
    monkeypatch.delenv("VULS_BIN", raising=False)
    monkeypatch.setattr(
        "extension.arms.vuls.arm.resolve_binary", lambda: None
    )
    for mod in ("stratus", "osmedeus", "zdns", "pagefetch"):
        monkeypatch.setattr(
            f"extension.arms.{mod}.arm.resolve_binary", lambda: None
        )
        monkeypatch.delenv(
            {"stratus": "STRATUS_BIN", "osmedeus": "OSMEDEUS_BIN",
             "zdns": "ZDNS_BIN", "pagefetch": "PAGE_FETCH_BIN"}[mod],
            raising=False,
        )
    monkeypatch.delenv("CALDERA_ENDPOINT", raising=False)
    monkeypatch.delenv("CALDERA_API_KEY", raising=False)
    monkeypatch.delenv("GTI_MCP_ENDPOINT", raising=False)
    monkeypatch.delenv("METASPLOIT_MCP_ENDPOINT", raising=False)
    for mod in (
        "routersploit",
        "sniper",
        "zgrab2",
        "darkmoon",
        "pyrit",
        "deepsec",
        "vvah",
        "aideepsast",
        "agentwiz",
    ):
        monkeypatch.setattr(
            f"extension.arms.{mod}.arm.resolve_binary", lambda: None
        )
    for env in (
        "ROUTERSPLOIT_BIN",
        "ROUTERSPLOIT_DISPATCH_SCOPE",
        "SNIPER_BIN",
        "SNIPER_DISPATCH_SCOPE",
        "ZGRAB2_BIN",
        "ZGRAB2_DISPATCH_SCOPE",
        "DARK_MOON_BIN",
        "DARK_MOON_DISPATCH_SCOPE",
        "PYRIT_BIN",
        "PYRIT_DISPATCH_SCOPE",
        "DEEPSEC_BIN",
        "DEEPSEC_SCAN_ROOT",
        "DEEPSEC_DISPATCH_SCOPE",
        "VVAH_BIN",
        "VVAH_SCAN_ROOT",
        "VVAH_DISPATCH_SCOPE",
        "VVAH_ALLOW_REMEDIATE",
        "AI_DEEP_SAST_BIN",
        "AI_DEEP_SAST_DEEPSCAN_BIN",
        "AI_DEEP_SAST_SCAN_ROOT",
        "AI_DEEP_SAST_DISPATCH_SCOPE",
        "AGENT_WIZ_BIN",
        "AGENT_WIZ_SCAN_ROOT",
        "AGENT_WIZ_DISPATCH_SCOPE",
        "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(env, raising=False)


@pytest.fixture
def no_curated_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    apply_no_curated_tools(monkeypatch)


class FakeCliTransport:
    protocol = "cli"

    def __init__(
        self,
        *,
        installed_ids: set[str] | None = None,
        result: Result | None = None,
    ) -> None:
        self.installed_ids = set(installed_ids or ())
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.result = result

    def installed(self, spec: Any) -> bool:
        return spec.id in self.installed_ids

    def invoke(
        self, spec: Any, action: str, args: Mapping[str, Any]
    ) -> Result:
        payload = dict(args)
        self.calls.append((spec.id, action, payload))
        if self.result is not None:
            return self.result
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output={"echo": payload},
            error=None,
        )


class RaisingTransport(FakeCliTransport):
    def invoke(
        self, spec: Any, action: str, args: Mapping[str, Any]
    ) -> Result:
        raise RuntimeError("transport boom")


def _entry(
    entry_id: str,
    *,
    kind: str = "arm",
    protocols: tuple[str, ...] = ("cli",),
    curated: bool = False,
    tier: str = "research",
    notes: str = "Range fixture row.",
    held_reason: str | None = None,
) -> CatalogEntry:
    return CatalogEntry(
        id=entry_id,
        kind=kind,
        protocols=protocols,
        curated=curated,
        notes=notes,
        tier=tier,
        held_reason=held_reason,
    )


def _catalog() -> Catalog:
    return Catalog(
        [
            _entry(FIXTURE_ARM_ID, curated=True),
            _entry(CURATED_ARM_ID, protocols=("mcp", "http"), curated=True),
        ]
    )


def _single_arm_extension(
    *,
    installed: set[str] | None = None,
    result: Result | None = None,
    transport: FakeCliTransport | None = None,
) -> tuple[Extension, FakeCliTransport]:
    fake = transport or FakeCliTransport(installed_ids=installed, result=result)
    catalog = Catalog([_entry(FIXTURE_ARM_ID, curated=True)])
    ext = Extension(
        catalog=catalog,
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    return ext, fake


def _expected(fixture_id: str) -> dict[str, Any]:
    path = RANGE_ROOT / fixture_id / "expected.json"
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    assert isinstance(data, dict)
    return data


def test_named_terraform_fixtures_exist() -> None:
    assert default_range_root() == RANGE_ROOT
    manifest = json.loads((RANGE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["live_aws"] is False
    assert manifest["seed"] == DEFAULT_SEED
    assert manifest["fixtures"] == list(_ALL_FIXTURES)
    for fixture_id in _ALL_FIXTURES:
        fixture_dir = RANGE_ROOT / fixture_id
        assert (fixture_dir / "input" / "assets.json").is_file()
        assert (fixture_dir / "input" / "connectivity.json").is_file()
        assert (fixture_dir / "input" / "sast.json").is_file()
        assert (fixture_dir / "input" / "main.tf").is_file()
        assert (fixture_dir / "expected.json").is_file()
        terraform = (fixture_dir / "input" / "main.tf").read_text(encoding="utf-8")
        assert "provider" not in terraform
        assert "access_key" not in terraform.lower()
        assert "secret_key" not in terraform.lower()


def test_range_fixtures_ship_in_non_editable_install(tmp_path: Path) -> None:
    """Non-editable install must ship extension.range fixtures next to the package."""
    prefix = tmp_path / "prefix"
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            ".",
            "--target",
            str(prefix),
            "--quiet",
        ],
        cwd=ROOT,
    )
    probe = tmp_path / "probe_range.py"
    probe.write_text(
        "from importlib import resources\n"
        "from extension.range import default_range_root\n"
        "root = default_range_root()\n"
        "assert (root / 'manifest.json').is_file(), root\n"
        "assert (root / 'tf_iam_open' / 'input' / 'main.tf').is_file()\n"
        "assert (root / 'tf_s3_public_access' / 'input' / 'main.tf').is_file()\n"
        "pkg = resources.files('extension.range')\n"
        "assert (pkg / 'manifest.json').is_file()\n"
        "assert (pkg / 'tf_iam_open' / 'input' / 'main.tf').is_file()\n"
        "assert (pkg / 'tf_s3_public_access' / 'input' / 'main.tf').is_file()\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(prefix)
    env["PYTHONNOUSERSITE"] = "1"
    subprocess.check_call([sys.executable, str(probe)], cwd=tmp_path, env=env)


def test_run_range_matches_expected_exposure_path_impact() -> None:
    document = run_range(arm_ids=())
    _assert_v3_status(document, "complete")
    assert document["seed"] == DEFAULT_SEED
    assert document["live_aws"] is False
    assert document["coverage"] == {
        "attempted": [],
        "complete": [],
        "skipped": [],
        "error": [],
    }
    by_id = {row["id"] for row in document["fixtures"]}
    assert by_id == set(_ALL_FIXTURES)
    for row in document["fixtures"]:
        expected = _expected(row["id"])
        _assert_fixture_v3(row, "complete")
        assert row["matched_expected"] is True
        assert row["exposure"] == expected["exposure"]
        assert row["path"] == expected["path"]
        assert row["impact"] == expected["impact"]
        assert row["exposures"] == expected["exposures"]
        assert row["chains"] == expected["chains"]
        assert row["arms"] == []


def test_run_range_is_seed_stable() -> None:
    first = run_range()
    second = run_range()
    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["seed"] == DEFAULT_SEED
    stamped = run_range(seed=DEFAULT_SEED, arm_ids=())
    again = run_range(seed=DEFAULT_SEED, arm_ids=())
    assert stamped == again


def test_uninstalled_curated_arm_is_skipped_held_is_error(
    no_curated_tools: None,
) -> None:
    document = run_range()
    entries = default_extension().list_entries()
    curated_ids = [
        entry.id
        for entry in entries
        if entry.kind == CATALOG_KIND_ARM and entry.curated
    ]
    held_ids = [
        entry.id
        for entry in entries
        if entry.kind == CATALOG_KIND_ARM and entry.curated and entry.tier == "held"
    ]
    skipped_ids = [arm_id for arm_id in curated_ids if arm_id not in held_ids]
    assert len(curated_ids) == 28
    assert CURATED_ARM_ID in curated_ids
    # Research tier since the doc-21 dossier (2026-09-03): no endpoint
    # configured, so the arm is skipped as not-installed like other
    # uninstalled curated arms - not a held error row.
    assert CURATED_ARM_ID in skipped_ids
    assert CURATED_ARM_ID not in held_ids
    # attack-stix-data is a pure in-process arm: its handler is always
    # installed, so the range's observe probe is an evaluated refusal
    # (error row), not a skip. Every other curated arm stays skipped.
    always_installed = "attack-stix-data"
    skipped_ids = [arm_id for arm_id in skipped_ids if arm_id != always_installed]
    error_ids = held_ids + [always_installed]
    # RED lock: matching lifecycle plus one unavailable auto-discovered
    # arm must not report complete / ok=true.
    _assert_v3_status(document, "degraded")
    assert document["coverage"]["attempted"] == curated_ids
    assert document["coverage"]["skipped"] == skipped_ids
    assert document["coverage"]["complete"] == []
    assert document["coverage"]["error"] == error_ids
    for row in document["fixtures"]:
        _assert_fixture_v3(row, "degraded")
        assert row["matched_expected"] is True
        by_id = {item["arm_id"]: item for item in row["arms"]}
        assert set(by_id) == set(curated_ids)
        for arm_id in skipped_ids:
            assert by_id[arm_id]["status"] == "skipped"
            assert by_id[arm_id]["reason"] == "not installed"
        for arm_id in held_ids:
            assert by_id[arm_id]["status"] == "error"
            err = by_id[arm_id].get("error") or ""
            assert "held" in err.lower()
            # Catalog policy text must not be keyword-mangled ("token").
            assert "[redacted]" not in err
            assert "token passthrough" in err.lower()
        observe_row = by_id[always_installed]
        assert observe_row["status"] == "error"
        assert "not on the allowlist" in (observe_row.get("error") or "")


def test_held_reason_redacted_when_notes_leak_secrets() -> None:
    entry = _entry(
        "held-mcp",
        protocols=("cli",),
        curated=True,
        tier="held",
        notes="operator pasted token=abc password=xyz",
        held_reason="HTTP MCP is held; no token passthrough.",
    )
    fake = FakeCliTransport(installed_ids={"held-mcp"})
    ext = Extension(
        catalog=Catalog([entry]),
        transports={"cli": fake},
        arms={"held-mcp": fake},
    )
    document = run_range(extension=ext, arm_ids=["held-mcp"])
    _assert_v3_status(document, "failed")
    err = document["fixtures"][0]["arms"][0]["error"]
    assert "[redacted]" in err
    assert "token" not in err.lower()
    assert "password" not in err.lower()
    assert fake.calls == []


def test_auto_discovered_missing_arm_is_degraded() -> None:
    ext, _fake = _single_arm_extension(installed=set())
    document = run_range(extension=ext)
    _assert_v3_status(document, "degraded")
    for row in document["fixtures"]:
        _assert_fixture_v3(row, "degraded")
        assert row["matched_expected"] is True
        assert row["arms"][0]["status"] == "skipped"
        assert row["coverage"]["skipped"] == [FIXTURE_ARM_ID]


def test_explicit_missing_arm_is_failed() -> None:
    ext, _fake = _single_arm_extension(installed=set())
    document = run_range(extension=ext, arm_ids=[FIXTURE_ARM_ID])
    _assert_v3_status(document, "failed")
    for row in document["fixtures"]:
        _assert_fixture_v3(row, "failed")
        assert row["matched_expected"] is True
        assert row["arms"][0]["status"] == "skipped"
        assert row["coverage"]["skipped"] == [FIXTURE_ARM_ID]


def test_explicit_empty_arm_ids_lifecycle_match_is_complete() -> None:
    document = run_range(arm_ids=())
    _assert_v3_status(document, "complete")
    for row in document["fixtures"]:
        _assert_fixture_v3(row, "complete")
        assert row["matched_expected"] is True
        assert row["arms"] == []


def test_installed_curated_arm_is_invoked() -> None:
    fake = FakeCliTransport(installed_ids={FIXTURE_ARM_ID})
    ext = Extension(
        catalog=_catalog(),
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    document = run_range(extension=ext, arm_ids=[FIXTURE_ARM_ID])
    _assert_v3_status(document, "complete")
    assert document["coverage"]["complete"] == [FIXTURE_ARM_ID]
    assert fake.calls == [
        (FIXTURE_ARM_ID, ARM_ACTION, {"fixture_id": fixture_id, "seed": DEFAULT_SEED})
        for fixture_id in _ALL_FIXTURES
    ]
    for row in document["fixtures"]:
        _assert_fixture_v3(row, "complete")
        assert row["arms"] == [
            {
                "arm_id": FIXTURE_ARM_ID,
                "action": ARM_ACTION,
                "status": "ok",
                "output": {
                    "echo": {"fixture_id": row["id"], "seed": DEFAULT_SEED}
                },
                "error": None,
            }
        ]


def test_failed_arm_result_is_never_complete() -> None:
    ext, _fake = _single_arm_extension(
        installed={FIXTURE_ARM_ID},
        result=Result(
            ok=False,
            arm_id=FIXTURE_ARM_ID,
            action=ARM_ACTION,
            output=None,
            error="arm declined",
        ),
    )
    document = run_range(extension=ext, arm_ids=[FIXTURE_ARM_ID])
    _assert_v3_status(document, "failed")
    for row in document["fixtures"]:
        _assert_fixture_v3(row, "failed")
        assert row["matched_expected"] is True
        assert row["arms"][0]["status"] == "error"
        assert row["arms"][0]["error"] == "arm declined"
        assert row["coverage"]["error"] == [FIXTURE_ARM_ID]


def test_arm_transport_error_is_never_complete() -> None:
    fake = RaisingTransport(installed_ids={FIXTURE_ARM_ID})
    ext, _ = _single_arm_extension(transport=fake)
    document = run_range(extension=ext, arm_ids=[FIXTURE_ARM_ID])
    _assert_v3_status(document, "failed")
    for row in document["fixtures"]:
        _assert_fixture_v3(row, "failed")
        assert row["matched_expected"] is True
        assert row["arms"][0]["status"] == "error"
        assert "transport boom" in row["arms"][0]["error"]


def test_optional_arm_exception_is_degraded_not_complete() -> None:
    fake = RaisingTransport(installed_ids={FIXTURE_ARM_ID})
    ext, _ = _single_arm_extension(transport=fake)
    document = run_range(extension=ext)
    _assert_v3_status(document, "degraded")
    for row in document["fixtures"]:
        _assert_fixture_v3(row, "degraded")
        assert row["matched_expected"] is True
        assert row["arms"][0]["status"] == "error"


def test_lifecycle_mismatch_is_failed(tmp_path: Path) -> None:
    root = _mismatch_range_root(tmp_path)
    document = run_range(range_root=root, arm_ids=())
    _assert_v3_status(document, "failed")
    row = document["fixtures"][0]
    _assert_fixture_v3(row, "failed")
    assert row["matched_expected"] is False
    assert row["arms"] == []


def test_lifecycle_mismatch_beats_optional_arm_skip(tmp_path: Path) -> None:
    ext, _fake = _single_arm_extension(installed=set())
    root = _mismatch_range_root(tmp_path)
    document = run_range(range_root=root, extension=ext)
    _assert_v3_status(document, "failed")
    row = document["fixtures"][0]
    _assert_fixture_v3(row, "failed")
    assert row["matched_expected"] is False
    assert row["arms"][0]["status"] == "skipped"


def test_document_roll_up_failed_beats_complete(tmp_path: Path) -> None:
    root = _mismatch_range_root(tmp_path, also_match=True)
    document = run_range(range_root=root, arm_ids=())
    _assert_v3_status(document, "failed")
    by_id = {row["id"]: row for row in document["fixtures"]}
    _assert_fixture_v3(by_id["tf_mismatch"], "failed")
    assert by_id["tf_mismatch"]["matched_expected"] is False
    _assert_fixture_v3(by_id[FIXTURE_IAM_OPEN], "complete")
    assert by_id[FIXTURE_IAM_OPEN]["matched_expected"] is True


@pytest.mark.parametrize("required", (False, True))
@pytest.mark.parametrize(
    "arms",
    (
        [{"arm_id": FIXTURE_ARM_ID}],
        [{"arm_id": FIXTURE_ARM_ID, "status": None}],
        [{"arm_id": FIXTURE_ARM_ID, "status": "unknown"}],
        [{"arm_id": FIXTURE_ARM_ID, "status": "complete"}],
        [{"arm_id": FIXTURE_ARM_ID, "status": "OK"}],
        [{"arm_id": FIXTURE_ARM_ID, "status": ""}],
        [
            {"arm_id": FIXTURE_ARM_ID, "status": "ok"},
            {"arm_id": "other-cli", "status": "mystery"},
        ],
    ),
)
def test_unknown_arm_status_is_failed_never_complete(
    required: bool, arms: list[dict[str, Any]]
) -> None:
    status = _fixture_status(matched=True, arms=arms, required=required)
    assert status == "failed"
    assert status != "complete"


def test_unknown_arm_status_run_range_is_failed_never_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unknown_arms(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        return [
            {
                "arm_id": FIXTURE_ARM_ID,
                "action": ARM_ACTION,
                "status": "unknown",
            }
        ]

    monkeypatch.setattr("extension.range.runner._invoke_arms", _unknown_arms)
    ext, _fake = _single_arm_extension(installed={FIXTURE_ARM_ID})
    document = run_range(extension=ext)
    _assert_v3_status(document, "failed")
    for row in document["fixtures"]:
        assert row["status"] == "failed"
        assert row["ok"] is False
        assert row["matched_expected"] is True
        assert row["arms"][0]["status"] == "unknown"


def test_document_status_degraded_beats_complete() -> None:
    assert (
        _document_status([{"status": "degraded"}, {"status": "complete"}])
        == "degraded"
    )
    assert (
        _document_status([{"status": "complete"}, {"status": "degraded"}])
        == "degraded"
    )


def test_document_roll_up_degraded_beats_complete() -> None:
    class MixedTransport(FakeCliTransport):
        def invoke(
            self, spec: Any, action: str, args: Mapping[str, Any]
        ) -> Result:
            payload = dict(args)
            self.calls.append((spec.id, action, payload))
            if payload.get("fixture_id") == FIXTURE_S3_PUBLIC:
                raise RuntimeError("optional boom")
            return Result(
                ok=True,
                arm_id=spec.id,
                action=action,
                output={"echo": payload},
                error=None,
            )

    fake = MixedTransport(installed_ids={FIXTURE_ARM_ID})
    ext = Extension(
        catalog=Catalog([_entry(FIXTURE_ARM_ID, curated=True)]),
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    document = run_range(extension=ext)
    _assert_v3_status(document, "degraded")
    by_id = {row["id"]: row for row in document["fixtures"]}
    _assert_fixture_v3(by_id[FIXTURE_S3_PUBLIC], "degraded")
    _assert_fixture_v3(by_id[FIXTURE_IAM_OPEN], "complete")
    assert by_id[FIXTURE_S3_PUBLIC]["arms"][0]["status"] == "error"
    assert by_id[FIXTURE_IAM_OPEN]["arms"][0]["status"] == "ok"


def test_result_document_is_mode_b_loadable(tmp_path: Path) -> None:
    document = run_range(arm_ids=())
    path = tmp_path / "range-result.json"
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    loaded = json.loads(path.read_text(encoding="utf-8"))
    _assert_v3_status(loaded, "complete")
    assert loaded["live_aws"] is False
    for row in loaded["fixtures"]:
        assert set(row) >= {
            "id",
            "ok",
            "status",
            "matched_expected",
            "coverage",
            "exposure",
            "path",
            "impact",
        }
        assert isinstance(row["exposure"], dict)
        assert isinstance(row["path"], list)
        assert isinstance(row["impact"], dict)


def test_derive_lifecycle_matches_fixture_expected() -> None:
    for fixture_id in _ALL_FIXTURES:
        input_dir = RANGE_ROOT / fixture_id / "input"
        assets = json.loads((input_dir / "assets.json").read_text(encoding="utf-8"))
        connectivity = json.loads(
            (input_dir / "connectivity.json").read_text(encoding="utf-8")
        )
        sast = json.loads((input_dir / "sast.json").read_text(encoding="utf-8"))
        derived = derive_lifecycle(assets, connectivity, sast)
        assert set(derived) == {
            "exposure",
            "path",
            "impact",
            "exposures",
            "chains",
        }
        assert derived == _expected(fixture_id)


def _assets(*rows: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "asset-config", "assets": list(rows)}


def test_derive_lifecycle_rejects_empty_and_duplicate_assets() -> None:
    with pytest.raises(RangeError, match="non-empty"):
        derive_lifecycle(_assets(), {"edges": []}, {"findings": []})
    duplicate = _assets(
        {"id": "a", "type": "aws_s3_bucket", "name": "a"},
        {"id": "a", "type": "aws_s3_bucket", "name": "b"},
    )
    with pytest.raises(RangeError, match="duplicate asset id"):
        derive_lifecycle(duplicate, {"edges": [{"from": "x", "to": "a"}]}, {"findings": []})


def _one(asset: dict[str, Any], port_edge: bool = False) -> dict[str, Any]:
    """Derive a single-asset document with one matching edge and finding."""
    asset_id = asset["id"]
    edge = {"from": "any-principal", "to": asset_id, "via": "tcp/22", "auth": "none"}
    if not port_edge:
        edge = {"from": "any-principal", "to": asset_id, "via": "s3:GetObject", "auth": "none"}
    return derive_lifecycle(
        _assets(asset),
        {"kind": "connectivity", "edges": [edge]},
        {
            "kind": "sast",
            "findings": [{"asset_id": asset_id, "severity": "high", "rule_id": "t"}],
        },
    )


@pytest.mark.parametrize(
    ("asset", "kind", "impact_kind"),
    [
        (
            {"id": "b", "type": "aws_s3_bucket", "name": "n", "acl": "public-read", "public_access_block": False},
            "public_storage",
            "data_disclosure",
        ),
        (
            {"id": "p", "type": "aws_iam_policy", "name": "n", "action": "*", "resource": "*"},
            "open_identity",
            "privilege_escalation",
        ),
        (
            {"id": "r", "type": "aws_iam_role", "name": "n", "assumable": True, "admin": True},
            "assumable_role",
            "privilege_escalation",
        ),
        (
            {"id": "t", "type": "aws_iam_role", "name": "n", "external_trust": True, "mfa_required": False},
            "open_trust",
            "identity_compromise",
        ),
        (
            {
                "id": "g",
                "type": "aws_security_group",
                "name": "n",
                "direction": "ingress",
                "from_port": 22,
                "to_port": 22,
                "cidr": "0.0.0.0/0",
            },
            "open_ingress",
            "remote_service_exposure",
        ),
        (
            {"id": "c", "type": "aws_cloudtrail", "name": "n", "enabled": False},
            "monitoring_gap",
            "detection_gap",
        ),
        (
            {
                "id": "l",
                "type": "aws_s3_bucket",
                "name": "n",
                "acl": "private",
                "public_access_block": True,
                "policy_allows_anonymous": False,
                "access_logging": False,
                "encryption_enabled": True,
            },
            "logging_gap",
            "detection_gap",
        ),
        (
            {
                "id": "u",
                "type": "aws_s3_bucket",
                "name": "n",
                "acl": "private",
                "public_access_block": True,
                "policy_allows_anonymous": False,
                "access_logging": True,
                "encryption_enabled": False,
            },
            "unencrypted_storage",
            "data_at_rest_exposure",
        ),
    ],
)
def test_derive_lifecycle_exposure_kinds(
    asset: dict[str, Any], kind: str, impact_kind: str
) -> None:
    derived = _one(asset)
    assert derived["exposure"]["kind"] == kind
    assert derived["impact"]["kind"] == impact_kind
    assert len(derived["exposures"]) == 1
    row = derived["exposures"][0]
    assert row["kind"] == kind
    assert row["path"] == derived["path"]
    assert row["impact"] == derived["impact"]
    assert derived["chains"] == []


def test_derive_lifecycle_blocked_policy_trap() -> None:
    """Block public access neutralizes an anonymous-read policy."""
    blocked = _one(
        {
            "id": "x",
            "type": "aws_s3_bucket",
            "name": "n",
            "acl": "private",
            "public_access_block": True,
            "policy_allows_anonymous": True,
            "access_logging": True,
            "encryption_enabled": True,
        }
    )
    assert blocked["exposure"]["kind"] == "blocked_public_policy"
    assert blocked["impact"]["kind"] == "blocked"
    assert blocked["exposure"]["severity"] == "high"  # from the planted finding

    # Same bucket without the block: the identical policy IS public.
    unblocked = _one(
        {
            "id": "x",
            "type": "aws_s3_bucket",
            "name": "n",
            "acl": "private",
            "public_access_block": False,
            "policy_allows_anonymous": True,
            "access_logging": True,
            "encryption_enabled": True,
        }
    )
    assert unblocked["exposure"]["kind"] == "public_storage"


def test_derive_lifecycle_chain_predicate() -> None:
    """Exactly one rule: world-open ingress + assumable role chains."""
    derived = derive_lifecycle(
        _assets(
            {
                "id": "sg",
                "type": "aws_security_group",
                "name": "g",
                "direction": "ingress",
                "from_port": 22,
                "to_port": 22,
                "cidr": "0.0.0.0/0",
            },
            {"id": "role", "type": "aws_iam_role", "name": "r", "assumable": True},
        ),
        {
            "kind": "connectivity",
            "edges": [
                {"from": "internet", "to": "sg", "via": "tcp/22", "auth": "none"},
                {"from": "sg", "to": "role", "via": "sts:AssumeRole", "auth": "principal"},
            ],
        },
        {"kind": "sast", "findings": []},
    )
    assert len(derived["chains"]) == 1
    chain = derived["chains"][0]
    assert chain["kind"] == "internet_to_identity"
    assert chain["ingress_asset"] == "sg"
    assert chain["role_asset"] == "role"

    # Neither half alone chains.
    solo = _one(
        {"id": "role", "type": "aws_iam_role", "name": "r", "assumable": True}
    )
    assert solo["chains"] == []


def test_derive_lifecycle_ingress_port_sensitivity() -> None:
    """World-open ingress on ordinary service ports is not the finding."""
    with pytest.raises(RangeError, match="no exposure derived"):
        _one(
            {
                "id": "web",
                "type": "aws_security_group",
                "name": "n",
                "direction": "ingress",
                "from_port": 443,
                "to_port": 443,
                "cidr": "0.0.0.0/0",
            },
            port_edge=True,
        )


def test_derive_lifecycle_ingress_port_type_guard() -> None:
    """Non-int ports never match sensitive ports (no float truncation)."""
    for bad_ports in (
        {"from_port": 22.0, "to_port": 22},
        {"from_port": 22, "to_port": 22.0},
        {"from_port": True, "to_port": 22},
    ):
        with pytest.raises(RangeError, match="no exposure derived"):
            _one(
                {
                    "id": "web",
                    "type": "aws_security_group",
                    "name": "n",
                    "direction": "ingress",
                    "cidr": "0.0.0.0/0",
                    **bad_ports,
                },
                port_edge=True,
            )


def test_derive_lifecycle_primary_is_highest_severity() -> None:
    derived = derive_lifecycle(
        _assets(
            {"id": "low", "type": "aws_cloudtrail", "name": "a", "enabled": False},
            {"id": "high", "type": "aws_cloudtrail", "name": "b", "enabled": False},
        ),
        {
            "kind": "connectivity",
            "edges": [
                {"from": "x", "to": "low", "via": "v", "auth": "none"},
                {"from": "x", "to": "high", "via": "v", "auth": "none"},
            ],
        },
        {
            "kind": "sast",
            "findings": [
                {"asset_id": "low", "severity": "low", "rule_id": "t"},
                {"asset_id": "high", "severity": "critical", "rule_id": "t"},
            ],
        },
    )
    assert derived["exposure"]["asset_id"] == "high"
    assert derived["impact"]["asset_id"] == "high"
    assert [row["asset_id"] for row in derived["exposures"]] == ["low", "high"]


def test_expected_must_mirror_derived_keys() -> None:
    # The shipped fixtures mirror exactly.
    assert set(_load_expected(RANGE_ROOT / FIXTURE_S3_PUBLIC / "expected.json")) == {
        "exposure",
        "path",
        "impact",
        "exposures",
        "chains",
    }
    with tempfile.TemporaryDirectory() as tmp:
        missing = Path(tmp) / "expected.json"
        missing.write_text(json.dumps({"exposure": {}, "path": []}), encoding="utf-8")
        with pytest.raises(RangeError, match="mirror the derived document"):
            _load_expected(missing)
        stale = Path(tmp) / "stale.json"
        stale.write_text(
            json.dumps({"exposure": {}, "path": [], "impact": {}, "exposures": [], "chains": [], "legacy": True}),
            encoding="utf-8",
        )
        with pytest.raises(RangeError, match="mirror the derived document"):
            _load_expected(stale)


def test_range_scope_matches_manifest() -> None:
    """Drift guard: the encoder's capability grant names every fixture.

    The sealed runtime cannot read the manifest at import time, so the
    grant is a static tuple in encode.py; this test is the lockstep.
    """
    from extension.encode import RANGE_SCOPE, _RANGE_SCOPE_BY_FIXTURE

    manifest = json.loads((RANGE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert sorted(_RANGE_SCOPE_BY_FIXTURE) == sorted(manifest["fixtures"])
    assert [uri.rsplit("/", 1)[-1] for uri in RANGE_SCOPE] == list(
        manifest["fixtures"]
    )
    for fixture_id, uri in _RANGE_SCOPE_BY_FIXTURE.items():
        assert uri == f"file:///extension/range/{fixture_id}"


def test_derive_lifecycle_primary_tie_breaks_by_asset_order() -> None:
    derived = derive_lifecycle(
        _assets(
            {"id": "first", "type": "aws_cloudtrail", "name": "a", "enabled": False},
            {"id": "second", "type": "aws_cloudtrail", "name": "b", "enabled": False},
        ),
        {
            "kind": "connectivity",
            "edges": [
                {"from": "x", "to": "first", "via": "v", "auth": "none"},
                {"from": "x", "to": "second", "via": "v", "auth": "none"},
            ],
        },
        {
            "kind": "sast",
            "findings": [
                {"asset_id": "first", "severity": "high", "rule_id": "t"},
                {"asset_id": "second", "severity": "high", "rule_id": "t"},
            ],
        },
    )
    assert derived["exposure"]["asset_id"] == "first"


def test_derive_lifecycle_blocked_public_acl_is_neutralized_too() -> None:
    """Block public access neutralizes ACLs the same as policies."""
    derived = _one(
        {
            "id": "x",
            "type": "aws_s3_bucket",
            "name": "n",
            "acl": "public-read",
            "public_access_block": True,
            "access_logging": True,
            "encryption_enabled": True,
        }
    )
    assert derived["exposure"]["kind"] == "blocked_public_policy"
    assert "grants anonymous access" in derived["exposure"]["summary"]


def test_derive_lifecycle_chain_requires_joining_edge() -> None:
    """Co-occurrence without a connecting edge is not a chain."""
    derived = derive_lifecycle(
        _assets(
            {
                "id": "sg",
                "type": "aws_security_group",
                "name": "g",
                "direction": "ingress",
                "from_port": 22,
                "to_port": 22,
                "cidr": "0.0.0.0/0",
            },
            {"id": "role", "type": "aws_iam_role", "name": "r", "assumable": True},
        ),
        {
            "kind": "connectivity",
            "edges": [
                {"from": "internet", "to": "sg", "via": "tcp/22", "auth": "none"},
                {"from": "admin-principal", "to": "role", "via": "sts:AssumeRole", "auth": "principal"},
            ],
        },
        {"kind": "sast", "findings": []},
    )
    assert derived["chains"] == []


def test_derive_lifecycle_unknown_severity_fails_closed() -> None:
    with pytest.raises(RangeError, match="unrankable sast severity"):
        derive_lifecycle(
            _assets({"id": "a", "type": "aws_cloudtrail", "name": "n", "enabled": False}),
            {"kind": "connectivity", "edges": [{"from": "x", "to": "a", "via": "v", "auth": "none"}]},
            {
                "kind": "sast",
                "findings": [{"asset_id": "a", "severity": "critial", "rule_id": "t"}],
            },
        )


def test_missing_fixture_is_hard_error(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "version": 1,
                "seed": DEFAULT_SEED,
                "live_aws": False,
                "fixtures": ["missing"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RangeError, match="unknown fixture"):
        run_range(range_root=tmp_path, arm_ids=())


def test_live_aws_manifest_is_refused(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "version": 1,
                "seed": DEFAULT_SEED,
                "live_aws": True,
                "fixtures": [FIXTURE_S3_PUBLIC],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RangeError, match="synthetic"):
        run_range(range_root=tmp_path, arm_ids=())


@pytest.mark.parametrize(
    "bad_seed",
    ("oops", None, [], 3.14, True, {}, ""),
)
def test_manifest_seed_type_is_range_error(tmp_path: Path, bad_seed: Any) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {"version": 1, "seed": bad_seed, "live_aws": False, "fixtures": [FIXTURE_S3_PUBLIC]}
        ),
        encoding="utf-8",
    )
    with pytest.raises(RangeError, match="seed"):
        run_range(range_root=tmp_path, arm_ids=())


def test_manifest_seed_out_of_range_is_range_error(tmp_path: Path) -> None:
    for bad in (2**31, -(2**31) - 1, 10_000_000_000):
        (tmp_path / "manifest.json").write_text(
            json.dumps(
                {"version": 1, "seed": bad, "live_aws": False, "fixtures": [FIXTURE_S3_PUBLIC]}
            ),
            encoding="utf-8",
        )
        with pytest.raises(RangeError, match="range|seed"):
            run_range(range_root=tmp_path, arm_ids=())


@pytest.mark.parametrize("bad_version", (99, 2, 0, "1", 1.0, True))
def test_manifest_version_must_be_one(tmp_path: Path, bad_version: Any) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {"version": bad_version, "live_aws": False, "fixtures": [FIXTURE_S3_PUBLIC]}
        ),
        encoding="utf-8",
    )
    with pytest.raises(RangeError, match="version"):
        run_range(range_root=tmp_path, arm_ids=())


def test_manifest_fixtures_must_be_unique(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "version": 1,
                "live_aws": False,
                "fixtures": [FIXTURE_S3_PUBLIC, FIXTURE_S3_PUBLIC],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RangeError, match="unique"):
        run_range(range_root=tmp_path, arm_ids=())


@pytest.mark.parametrize("bad_seed", ("oops", "3.14", [], 3.14))
def test_run_range_seed_arg_type_is_range_error(bad_seed: Any) -> None:
    with pytest.raises(RangeError, match="seed must be an integer"):
        run_range(seed=bad_seed, arm_ids=())  # type: ignore[arg-type]


def test_run_range_seed_out_of_range_is_range_error() -> None:
    with pytest.raises(RangeError, match="range|seed"):
        run_range(seed=2**31, arm_ids=())


def test_run_range_multi_asset_fixture_requires_paths(tmp_path: Path) -> None:
    # Multi-asset fixtures are valid, but every asset still needs a
    # connectivity edge: a row without one fails closed (v3 contract).
    fixture_src = RANGE_ROOT / FIXTURE_S3_PUBLIC
    fixture_id = "pathless_multi_asset"
    dst = tmp_path / fixture_id
    (dst / "input").mkdir(parents=True)
    assets = json.loads(
        (RANGE_ROOT / FIXTURE_CHAIN_INGRESS_ROLE / "input" / "assets.json").read_text(
            encoding="utf-8"
        )
    )
    (dst / "input" / "assets.json").write_text(json.dumps(assets), encoding="utf-8")
    # Only one edge: role-escalate has no path into it.
    (dst / "input" / "connectivity.json").write_text(
        json.dumps(
            {
                "kind": "connectivity",
                "edges": [{"from": "internet", "to": "sg-jump", "via": "tcp/22", "auth": "none"}],
            }
        ),
        encoding="utf-8",
    )
    (dst / "input" / "sast.json").write_text(
        json.dumps({"kind": "sast", "findings": []}), encoding="utf-8"
    )
    (dst / "expected.json").write_text(
        (fixture_src / "expected.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {"version": 1, "live_aws": False, "fixtures": [fixture_id]}
        ),
        encoding="utf-8",
    )
    with pytest.raises(RangeError, match="no connectivity path to role-escalate"):
        run_range(range_root=tmp_path, arm_ids=())


def test_arm_transport_error_is_redacted() -> None:
    class SecretRaising(FakeCliTransport):
        def invoke(self, spec: Any, action: str, args: Mapping[str, Any]) -> Result:  # type: ignore[override]
            raise RuntimeError("token abc secret bearer cookie Authorization")

    ext = Extension(
        catalog=_catalog(),
        transports={"cli": SecretRaising(installed_ids={FIXTURE_ARM_ID})},
        arms={
            FIXTURE_ARM_ID: SecretRaising(installed_ids={FIXTURE_ARM_ID}),
        },
    )
    document = run_range(extension=ext, arm_ids=[FIXTURE_ARM_ID])
    _assert_v3_status(document, "failed")
    err = document["fixtures"][0]["arms"][0]["error"]
    assert "[redacted]" in err
    assert "token" not in err.lower()
    assert "bearer" not in err.lower()


def test_resolve_arm_ids_dedupes_preserving_order() -> None:
    fake = FakeCliTransport(installed_ids={FIXTURE_ARM_ID})
    ext = Extension(
        catalog=_catalog(),
        transports={"cli": fake},
        arms={FIXTURE_ARM_ID: fake},
    )
    document = run_range(extension=ext, arm_ids=[FIXTURE_ARM_ID, FIXTURE_ARM_ID, FIXTURE_ARM_ID])
    for row in document["fixtures"]:
        assert len(row["arms"]) == 1
        assert row["arms"][0]["arm_id"] == FIXTURE_ARM_ID


def test_main_writes_result_document(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([])
    printed = json.loads(capsys.readouterr().out)
    assert printed["schema"] == RESULT_SCHEMA_ID
    assert "ok" not in printed
    assert printed["status"] in _RANGE_STATUSES
    assert code == (0 if printed["status"] == "complete" else 1)
    out = tmp_path / "result.json"
    code2 = main(["--out", str(out), "--seed", str(DEFAULT_SEED)])
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["schema"] == RESULT_SCHEMA_ID
    assert written["capability_id"] == "fixture.range-observe"
    assert "ok" not in written
    assert code2 == (0 if written["status"] == "complete" else 1)


def test_main_default_uninstalled_exits_nonzero(
    no_curated_tools: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([]) == 1
    printed = json.loads(capsys.readouterr().out)
    assert printed["schema"] == RESULT_SCHEMA_ID
    assert printed["status"] == "degraded"
    assert "ok" not in printed


def test_module_cli_emits_json() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "extension.range"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    document = json.loads(proc.stdout)
    assert document["schema"] == RESULT_SCHEMA_ID
    assert "ok" not in document
    assert document["status"] in _RANGE_STATUSES
    assert proc.returncode == (0 if document["status"] == "complete" else 1), proc.stderr
