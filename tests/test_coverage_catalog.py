"""Validate extension/coverage.yaml against the published schema and loader."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest
import yaml

from extension.contract import ExtensionError, UnknownIdError, describe, load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "extension" / "coverage.yaml"
SCHEMA_PATH = ROOT / "extension" / "schema" / "coverage.schema.json"

# Public kebab slugs for every catalog row, in registry order.
EXPECTED_IDS = (
    "learning-operator",
    "loopback",
    "foundry",
    "codeguard",
    "vulnhunter",
    "edge-device-posture",
    "defending-code",
    "mantis",
    "raptor",
    "deepsec",
    "vvah",
    "ai-deep-sast",
    "trailofbits",
    "cloudflare",
    "metasploit-mcp",
    "burp-mcp",
    "agent-wiz",
    "maestro",
    "prowler-mcp",
    "semgrep-mcp",
    "google-mcp-security",
    "garak",
    "pyrit",
    "mitre-atlas",
    "cyberseceval",
    "cybench",
    "owasp-agentic",
    "checkov",
    "cloudgoat",
    "stratus-red-team",
    "attackforge-testsuites",
    "attackforge-writeups",
    "attack-stix-data",
    "vulnify",
    "snmp-readtier",
    "ike-readtier",
    "mitreattack-python",
    "mitre-cti",
    "vuls",
    "zaproxy",
    "wapiti",
    "commix",
    "zdns",
    "zgrab2",
    "nmap",
    "page-fetch",
    "http-probe",
    "caldera",
    "osmedeus",
    "sniper",
    "dark-moon",
    "routersploit",
    "rpz-decoder",
    "asset-recon",
    "security-detections-mcp",
    "agentseal",
    "leonidas",
    "specterops-skills",
    "detection-in-the-cloud",
    "pentestkit",
    "collinear",
    "ad-pathfinder",
    "gpohound",
    "claude-ad",
    "numasec",
    "rubeus",
    "m365pwned",
    "ivanti",
    # Campaign 2026-10-23: Pashov skills references, methodology-only,
    # appended after ivanti in catalog order.
    "pashov-x-ray",
    "pashov-solidity-auditor",
    "pashov-fizz",
    # Campaign 2026-10-23: the three bounded offline readers, in catalog order.
    "hostbadger",
    "idwolf",
    "osv",
)

_TEXT_SUFFIXES = {".yaml", ".yml", ".md", ".json", ".py", ".txt", ".toml", ".ini", ".tf"}
_SKIP_DIR_NAMES = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules"}
_ENTRY_FIELDS = {"id", "kind", "protocols", "notes"}
_KINDS = ["head", "arm", "methodology-only"]
_PROTOCOLS = ["mcp", "cli", "http", "none"]


def _load_catalog_yaml() -> dict:
    with CATALOG_PATH.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    assert isinstance(data, dict)
    return data


def _load_schema() -> dict:
    with SCHEMA_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _forbidden_tokens() -> tuple[str, ...]:
    # Built piecewise so this file does not contain the banned substrings.
    return (
        "myth" + "os",
        "glass" + "wing",
        "char" + "ter",
        "spec" + "trum",
        "specaudit-" + "server",
        "specaudit-" + "validator",
        "fusion" + "-rs",
        "specaudit" + "/packs/",
    )


def _minimal_entry(**overrides: object) -> dict:
    entry: dict = {
        "id": "probe-cli",
        "kind": "arm",
        "protocols": ["cli"],
        "notes": "a",
    }
    entry.update(overrides)
    return entry


def _minimal_document(entry: dict | None = None, *, version: object = 1) -> dict:
    document: dict = {"entries": [entry or _minimal_entry()]}
    if version is not None:
        document["version"] = version
    return document


@pytest.fixture(scope="module")
def catalog() -> dict:
    return _load_catalog_yaml()


@pytest.fixture(scope="module")
def entries(catalog: dict) -> list[dict]:
    rows = catalog["entries"]
    assert isinstance(rows, list)
    return rows


def test_schema_entry_contract() -> None:
    schema = _load_schema()
    assert schema["required"] == ["version", "entries"]
    assert schema["additionalProperties"] is False
    entry = schema["definitions"]["entry"]
    assert entry["required"] == ["id", "kind", "protocols", "notes"]
    assert entry["additionalProperties"] is False
    assert set(entry["properties"]) == _ENTRY_FIELDS
    assert entry["properties"]["kind"]["enum"] == _KINDS
    protocols = entry["properties"]["protocols"]
    assert protocols["minItems"] == 1
    assert protocols["uniqueItems"] is True
    assert protocols["items"]["enum"] == _PROTOCOLS
    assert entry["properties"]["notes"]["minLength"] == 1
    assert entry["properties"]["id"]["pattern"] == r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$"


def test_catalog_matches_schema(catalog: dict) -> None:
    jsonschema.validate(instance=catalog, schema=_load_schema())


def test_schema_rejects_removed_admission_fields() -> None:
    schema = _load_schema()
    jsonschema.validate(instance=_minimal_document(), schema=schema)
    for extra in (
        {"tier": "research"},
        {"curated": False},
        {"held_reason": "because"},
    ):
        document = _minimal_document(_minimal_entry(**extra))
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validate(instance=document, schema=schema)


def test_schema_rejects_shape_the_loader_does_not() -> None:
    """Schema requires version and unique protocols. The loader does not."""
    schema = _load_schema()
    missing_version = _minimal_document(version=None)
    duplicate_protocols = _minimal_document(_minimal_entry(protocols=["cli", "cli"]))
    for document in (missing_version, duplicate_protocols):
        with pytest.raises(jsonschema.exceptions.ValidationError):
            jsonschema.validate(instance=document, schema=schema)


def test_survey_ids_match_frozen_set(entries: list[dict]) -> None:
    ids = [row["id"] for row in entries]
    assert ids == list(EXPECTED_IDS)
    assert sorted(ids) == sorted(EXPECTED_IDS)


def test_published_rows_have_only_catalog_fields(entries: list[dict]) -> None:
    for row in entries:
        assert set(row) == _ENTRY_FIELDS
        assert row["kind"] in _KINDS
        assert row["protocols"]
        assert isinstance(row["notes"], str) and row["notes"].strip()


def test_entry_ids_unique_and_kebab_case(entries: list[dict]) -> None:
    ids = [row["id"] for row in entries]
    assert ids == sorted(set(ids), key=ids.index)
    for entry_id in ids:
        assert entry_id == entry_id.lower()
        assert "_" not in entry_id
        assert entry_id[0].isalpha()


def test_none_protocol_is_exclusive(entries: list[dict]) -> None:
    for row in entries:
        protocols = row["protocols"]
        if "none" in protocols:
            assert protocols == ["none"], row["id"]


def test_load_catalog_reads_published_rows() -> None:
    loaded = load_catalog()
    assert loaded.version == 1
    assert [entry.id for entry in loaded.entries] == list(EXPECTED_IDS)
    for entry in loaded.entries:
        assert set(entry.to_dict()) == _ENTRY_FIELDS
        assert entry.protocols
        assert entry.notes.strip()


def test_load_catalog_accepts_minimal_row(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(
        "version: 1\n"
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  notes: a\n",
        encoding="utf-8",
    )
    loaded = load_catalog(path)
    assert loaded.version == 1
    assert len(loaded.entries) == 1
    entry = loaded.entries[0]
    assert entry.id == "probe-cli"
    assert entry.kind == "arm"
    assert entry.protocols == ("cli",)
    assert entry.notes == "a"


def test_describe_returns_catalog_row() -> None:
    described = describe("ai-deep-sast")
    row = next(item for item in _load_catalog_yaml()["entries"] if item["id"] == "ai-deep-sast")
    assert described.id == "ai-deep-sast"
    assert described.kind == row["kind"] == "arm"
    assert described.protocols == tuple(row["protocols"]) == ("cli",)
    assert described.notes == row["notes"]


def test_describe_unknown_id() -> None:
    with pytest.raises(UnknownIdError) as err:
        describe("not-a-catalog-id")
    assert str(err.value) == "unknown id: not-a-catalog-id"


def test_language_bar_on_catalog_ids_and_notes(entries: list[dict]) -> None:
    forbidden = tuple(token.lower() for token in _forbidden_tokens())
    for row in entries:
        haystack = f"{row['id']}\n{row['notes']}".lower()
        for token in forbidden:
            assert token not in haystack, f"{row['id']} contains banned token"


# Resolve at import time: the suite's autouse hermetic-path fixture
# strips PATH for every test, and git must never come from a
# test-controlled directory regardless. A checkout without git cannot
# run the tree walk at all — skip honestly rather than fail opaquely.
_GIT = shutil.which("git")
if _GIT is None:
    pytest.skip("git not available for the language-bar tree walk", allow_module_level=True)


def _tracked_text_files() -> list[Path]:
    listed = subprocess.check_output(
        [_GIT, "ls-files", "-z"],
        cwd=ROOT,
    ).split(b"\0")
    paths: list[Path] = []
    for raw in listed:
        if not raw:
            continue
        path = ROOT / raw.decode("utf-8")
        if not path.is_file():
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        paths.append(path)
    return paths


def test_language_bar_on_added_tree() -> None:
    forbidden = tuple(token.lower() for token in _forbidden_tokens())
    hits: list[str] = []
    for path in _tracked_text_files():
        text = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            if token in text:
                hits.append(f"{path.relative_to(ROOT)}: {token}")
    assert hits == []


@pytest.mark.parametrize(
    "document",
    [
        pytest.param("- not-a-mapping\n", id="top-level-not-mapping"),
        pytest.param("entries: not-a-list\n", id="entries-not-list"),
        pytest.param(
            "entries:\n"
            "- id: dup\n"
            "  kind: arm\n"
            "  protocols: [cli]\n"
            "  notes: a\n"
            "- id: dup\n"
            "  kind: arm\n"
            "  protocols: [cli]\n"
            "  notes: b\n",
            id="duplicate-id",
        ),
        pytest.param(
            "entries:\n"
            "- id: empty\n"
            "  kind: arm\n"
            "  protocols: []\n"
            "  notes: a\n",
            id="empty-protocols",
        ),
        pytest.param(
            "entries:\n"
            "- id: bad\n"
            "  kind: arm\n"
            "  protocols: cli\n"
            "  notes: a\n",
            id="protocols-not-list",
        ),
        pytest.param(
            "entries:\n"
            "- kind: arm\n"
            "  protocols: [cli]\n"
            "  notes: a\n",
            id="missing-id",
        ),
        pytest.param(
            "entries:\n"
            "- id: probe-cli\n"
            "  protocols: [cli]\n"
            "  notes: a\n",
            id="missing-kind",
        ),
        pytest.param(
            "entries:\n"
            "- id: probe-cli\n"
            "  kind: arm\n"
            "  protocols: [cli]\n",
            id="missing-notes",
        ),
        pytest.param(
            "entries:\n"
            "- id: probe-cli\n"
            "  kind: arm\n"
            "  protocols: [cli]\n"
            "  notes: '   '\n",
            id="blank-notes",
        ),
        pytest.param(
            "entries:\n"
            "- id: probe-cli\n"
            "  kind: bad\n"
            "  protocols: [cli]\n"
            "  notes: a\n",
            id="bad-kind",
        ),
        pytest.param(
            "entries:\n"
            "- id: Bad_ID\n"
            "  kind: arm\n"
            "  protocols: [cli]\n"
            "  notes: a\n",
            id="bad-id",
        ),
        pytest.param(
            "entries:\n"
            "- id: probe-cli\n"
            "  kind: arm\n"
            "  protocols: [badproto]\n"
            "  notes: a\n",
            id="bad-protocol",
        ),
        pytest.param(
            "entries:\n"
            "- id: probe-cli\n"
            "  kind: arm\n"
            "  protocols: [none, cli]\n"
            "  notes: a\n",
            id="none-not-exclusive",
        ),
        pytest.param(
            "version: x\n"
            "entries:\n"
            "- id: probe-cli\n"
            "  kind: arm\n"
            "  protocols: [cli]\n"
            "  notes: a\n",
            id="version-not-integer",
        ),
        pytest.param(
            "entries:\n"
            "- not-a-mapping\n",
            id="entry-not-mapping",
        ),
    ],
)
def test_load_catalog_rejects_malformed_documents(tmp_path: Path, document: str) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(ExtensionError):
        load_catalog(path)


def test_load_catalog_invalid_yaml_is_extension_error(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text("entries: [unclosed\n", encoding="utf-8")
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    assert "invalid catalog yaml" in str(err.value).lower()


def test_load_catalog_duplicate_id_is_not_row_indexed(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(
        "entries:\n"
        "- id: dup\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  notes: a\n"
        "- id: dup\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  notes: b\n",
        encoding="utf-8",
    )
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    assert str(err.value) == "duplicate catalog id: dup"


def test_load_catalog_error_includes_row_index(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  notes: a\n"
        "- kind: arm\n"
        "  protocols: [cli]\n"
        "  notes: b\n",
        encoding="utf-8",
    )
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    assert "entry 1" in str(err.value)
