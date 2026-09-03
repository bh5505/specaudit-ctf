"""Validate extension/coverage.yaml against the published schema."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest
import yaml

from extension.arms.aideepsast.policy import CAVEATS as AI_DEEP_SAST_CAVEATS
from extension.contract import ExtensionError, describe, load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "extension" / "coverage.yaml"
SCHEMA_PATH = ROOT / "extension" / "schema" / "coverage.schema.json"

# Public kebab slugs for every classified survey row, in registry order.
EXPECTED_IDS = (
    "loopback",
    "foundry",
    "codeguard",
    "vulnhunter",
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
    "caldera",
    "osmedeus",
    "sniper",
    "dark-moon",
    "routersploit",
)
CURATED_ARM_ID = "burp-mcp"

_TEXT_SUFFIXES = {".yaml", ".yml", ".md", ".json", ".py", ".txt", ".toml", ".ini", ".tf"}
_SKIP_DIR_NAMES = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules"}


def _load_catalog() -> dict:
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


@pytest.fixture(scope="module")
def catalog() -> dict:
    return _load_catalog()


@pytest.fixture(scope="module")
def entries(catalog: dict) -> list[dict]:
    rows = catalog["entries"]
    assert isinstance(rows, list)
    return rows


def test_catalog_matches_schema(catalog: dict) -> None:
    jsonschema.validate(instance=catalog, schema=_load_schema())


def test_survey_ids_match_frozen_set(entries: list[dict]) -> None:
    ids = [row["id"] for row in entries]
    assert ids == list(EXPECTED_IDS)
    assert sorted(ids) == sorted(EXPECTED_IDS)


def test_entry_ids_unique_and_kebab_case(entries: list[dict]) -> None:
    ids = [row["id"] for row in entries]
    assert ids == sorted(set(ids), key=ids.index)
    for entry_id in ids:
        assert entry_id == entry_id.lower()
        assert "_" not in entry_id
        assert entry_id[0].isalpha()


def test_methodology_only_rows_are_not_curated(entries: list[dict]) -> None:
    curated_methodology = [
        row["id"]
        for row in entries
        if row["kind"] == "methodology-only" and row["curated"]
    ]
    assert curated_methodology == []


def test_curated_arms_are_exactly_the_curated_set(entries: list[dict]) -> None:
    curated = [row for row in entries if row["curated"]]
    assert {row["id"] for row in curated} == {
        "burp-mcp",
        "semgrep-mcp",
        "checkov",
        "prowler-mcp",
        "garak",
        "zaproxy",
        "wapiti",
        "commix",
        "mitreattack-python",
        "vuls",
        "stratus-red-team",
        "osmedeus",
        "zdns",
        "page-fetch",
        "caldera",
        "google-mcp-security",
        "metasploit-mcp",
        "routersploit",
        "sniper",
        "zgrab2",
        "nmap",
        "dark-moon",
        "pyrit",
        "deepsec",
        "vvah",
        "ai-deep-sast",
        "agent-wiz",
    }
    for arm in curated:
        assert arm["kind"] == "arm"


def test_none_protocol_is_exclusive(entries: list[dict]) -> None:
    for row in entries:
        protocols = row["protocols"]
        if "none" in protocols:
            assert protocols == ["none"], row["id"]


def test_describe_ai_deep_sast_notes_match_live_caveats() -> None:
    notes = describe("ai-deep-sast").notes
    for phrase in (
        "--skip-llm",
        "AI_DEEP_SAST_SEMGREP_CONFIG",
        "no registry p/",
        "Foundation-Sec",
        "llama-completion",
        "dry_run --dry-run",
    ):
        assert phrase in AI_DEEP_SAST_CAVEATS, phrase
        assert phrase in notes, phrase
    assert "redacted source" not in notes.lower()


def test_language_bar_on_catalog_ids_and_notes(entries: list[dict]) -> None:
    forbidden = tuple(token.lower() for token in _forbidden_tokens())
    for row in entries:
        haystack = f"{row['id']}\n{row['notes']}\n{row.get('held_reason') or ''}".lower()
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
        # top-level mapping required
        "- not-a-mapping\n",
        # entries must be a list
        "entries: not-a-list\n",
        # duplicate id
        "entries:\n"
        "- id: dup\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: false\n"
        "  notes: a\n"
        "- id: dup\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: false\n"
        "  notes: b\n",
        # empty protocols list
        "entries:\n"
        "- id: empty\n"
        "  kind: arm\n"
        "  protocols: []\n"
        "  curated: false\n"
        "  notes: a\n",
        # non-list protocols
        "entries:\n"
        "- id: bad\n"
        "  kind: arm\n"
        "  protocols: cli\n"
        "  curated: false\n"
        "  notes: a\n",
        # missing id
        "entries:\n"
        "- kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: false\n"
        "  notes: a\n",
        # missing kind
        "entries:\n"
        "- id: probe-cli\n"
        "  protocols: [cli]\n"
        "  curated: false\n"
        "  notes: a\n",
        # missing notes
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: false\n",
        # bad kind value
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: bad\n"
        "  protocols: [cli]\n"
        "  curated: false\n"
        "  notes: a\n",
        # methodology-only must not be curated
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: methodology-only\n"
        "  protocols: [none]\n"
        "  curated: true\n"
        "  notes: a\n",
        # bad id pattern (uppercase)
        "entries:\n"
        "- id: Bad_ID\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: false\n"
        "  notes: a\n",
        # invalid protocol value
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [badproto]\n"
        "  curated: false\n"
        "  notes: a\n",
        # none must be exclusive
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [none, cli]\n"
        "  curated: false\n"
        "  notes: a\n",
        # version non-integer
        "version: x\nentries:\n- id: probe-cli\n  kind: arm\n  protocols: [cli]\n  curated: false\n  notes: a\n",
        # missing tier
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: false\n"
        "  notes: a\n",
        # invalid tier
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: false\n"
        "  tier: stable\n"
        "  notes: a\n",
        # methodology-only must not be maintained
        "entries:\n"
        "- id: teach-only\n"
        "  kind: methodology-only\n"
        "  protocols: [none]\n"
        "  curated: false\n"
        "  tier: maintained\n"
        "  notes: a\n",
        # held requires a reason
        "entries:\n"
        "- id: held-mcp\n"
        "  kind: arm\n"
        "  protocols: [mcp]\n"
        "  curated: true\n"
        "  tier: held\n"
        "  notes: a\n",
        # curated must be a real boolean, not a string
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: 'true'\n"
        "  tier: research\n"
        "  notes: a\n",
        # curated integer is not a boolean
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: 1\n"
        "  tier: research\n"
        "  notes: a\n",
        # missing curated
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  tier: research\n"
        "  notes: a\n",
    ],
)
def test_load_catalog_rejects_malformed_documents(
    tmp_path: Path, document: str
) -> None:
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


@pytest.mark.parametrize("curated_yaml", ('"true"', '"false"', '"yes"', "1", "0", "null"))
def test_load_catalog_rejects_non_boolean_curated(
    tmp_path: Path, curated_yaml: str
) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        f"  curated: {curated_yaml}\n"
        "  tier: research\n"
        "  notes: a\n",
        encoding="utf-8",
    )
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    message = str(err.value).lower()
    assert "curated" in message
    assert "boolean" in message


def test_load_catalog_error_includes_row_index(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(
        "entries:\n"
        "- id: probe-cli\n"
        "  kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: false\n"
        "  tier: research\n"
        "  notes: a\n"
        "- kind: arm\n"
        "  protocols: [cli]\n"
        "  curated: false\n"
        "  tier: research\n"
        "  notes: b\n",
        encoding="utf-8",
    )
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    assert "entry 1" in str(err.value)
