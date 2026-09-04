"""Lifecycle/support tiers: research | experimental | maintained | held."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from extension.contract import (
    Catalog,
    CatalogEntry,
    Extension,
    ExtensionError,
    NotHeldError,
    describe,
    list_entries,
    load_catalog,
)
from extension.__main__ import main
from extension.mcp_server import McpServer
from tests.test_alt_head_mcp import _call, _content_json, _content_text
from tests.test_contract import FakeCliTransport
from tests.test_coverage_catalog import _load_catalog, _load_schema

ALLOWED_TIERS = frozenset({"research", "experimental", "maintained", "held"})
# The 2026-09-04 transport-gate campaign closed the held set: zero
# held rows remain in the live catalog. The held tier itself is still
# exercised by the fixture-based tests below and the envelope goldens.
HELD_HTTP_MCP_ARM_IDS: tuple[str, ...] = ()
PINNED_CURATED_NOT_MAINTAINED = "checkov"
METHODOLOGY_ID = "vulnhunter"
HELD_FIXTURE_ID = "held-mcp"


def _row(
    *,
    entry_id: str = "probe-cli",
    kind: str = "arm",
    protocols: str = "[cli]",
    curated: str = "false",
    extra: str = "",
    notes: str = "a",
) -> str:
    return (
        f"- id: {entry_id}\n"
        f"  kind: {kind}\n"
        f"  protocols: {protocols}\n"
        f"  curated: {curated}\n"
        f"{extra}"
        f"  notes: {notes}\n"
    )


def _catalog_doc(*rows: str) -> str:
    return "version: 1\nentries:\n" + "".join(rows)


@pytest.fixture(scope="module")
def catalog() -> dict:
    return _load_catalog()


@pytest.fixture(scope="module")
def entries(catalog: dict) -> list[dict]:
    rows = catalog["entries"]
    assert isinstance(rows, list)
    return rows


def test_schema_requires_tier_enum_on_every_entry(
    catalog: dict, entries: list[dict]
) -> None:
    schema = _load_schema()
    entry_schema = schema["definitions"]["entry"]
    assert "tier" in entry_schema["required"]
    assert set(entry_schema["properties"]["tier"]["enum"]) == set(ALLOWED_TIERS)
    jsonschema.validate(instance=catalog, schema=schema)
    for row in entries:
        assert row["tier"] in ALLOWED_TIERS, row["id"]


def test_every_catalog_row_has_tier(entries: list[dict]) -> None:
    missing = [row["id"] for row in entries if row.get("tier") not in ALLOWED_TIERS]
    assert missing == []
    maintained = [row["id"] for row in entries if row["tier"] == "maintained"]
    # X5-PROMOTE: exactly one maintained arm, no bulk promotion.
    assert maintained == ["agent-wiz"]


def test_kind_counts_preserved(entries: list[dict]) -> None:
    kinds = [row["kind"] for row in entries]
    assert kinds.count("arm") == 27
    assert kinds.count("methodology-only") == 19
    assert len(entries) == 46


def test_schema_rejects_missing_tier() -> None:
    schema = _load_schema()
    document = {
        "version": 1,
        "entries": [
            {
                "id": "probe-cli",
                "kind": "arm",
                "protocols": ["cli"],
                "curated": False,
                "notes": "a",
            }
        ],
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=document, schema=schema)


def test_load_catalog_rejects_missing_tier(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(_catalog_doc(_row()), encoding="utf-8")
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    assert "tier" in str(err.value).lower()


def test_load_catalog_rejects_invalid_tier(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(
        _catalog_doc(_row(extra="  tier: stable\n")),
        encoding="utf-8",
    )
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    assert "tier" in str(err.value).lower()


def test_load_catalog_rejects_methodology_only_maintained(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(
        _catalog_doc(
            _row(
                entry_id="teach-only",
                kind="methodology-only",
                protocols="[none]",
                extra="  tier: maintained\n",
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    assert "methodology-only" in str(err.value).lower()
    assert "maintained" in str(err.value).lower()


def test_schema_rejects_methodology_only_maintained() -> None:
    schema = _load_schema()
    entry_schema = schema["definitions"]["entry"]
    assert "tier" in entry_schema.get("properties", {})
    document = {
        "version": 1,
        "entries": [
            {
                "id": "teach-only",
                "kind": "methodology-only",
                "protocols": ["none"],
                "curated": False,
                "tier": "maintained",
                "notes": "a",
            }
        ],
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=document, schema=schema)


def test_load_catalog_rejects_held_without_reason(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(
        _catalog_doc(_row(curated="true", extra="  tier: held\n")),
        encoding="utf-8",
    )
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    assert "held" in str(err.value).lower()


def test_schema_rejects_held_without_reason() -> None:
    schema = _load_schema()
    entry_schema = schema["definitions"]["entry"]
    assert "tier" in entry_schema.get("properties", {})
    assert "held_reason" in entry_schema.get("properties", {})
    document = {
        "version": 1,
        "entries": [
            {
                "id": "held-mcp",
                "kind": "arm",
                "protocols": ["mcp", "http"],
                "curated": True,
                "tier": "held",
                "notes": "a",
            }
        ],
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=document, schema=schema)


def test_load_catalog_rejects_empty_held_reason(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(
        _catalog_doc(
            _row(
                curated="true",
                extra="  tier: held\n  held_reason: '   '\n",
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    assert "held" in str(err.value).lower()


def test_load_catalog_rejects_held_reason_on_non_held(tmp_path: Path) -> None:
    path = tmp_path / "coverage.yaml"
    path.write_text(
        _catalog_doc(
            _row(extra="  tier: research\n  held_reason: leftover\n")
        ),
        encoding="utf-8",
    )
    with pytest.raises(ExtensionError) as err:
        load_catalog(path)
    assert "held_reason" in str(err.value).lower()


def test_methodology_only_rows_are_not_maintained(entries: list[dict]) -> None:
    bad = [
        row["id"]
        for row in entries
        if row["kind"] == "methodology-only" and row.get("tier") == "maintained"
    ]
    assert bad == []
    for row in entries:
        if row["kind"] == "methodology-only":
            assert row.get("tier") in ALLOWED_TIERS - {"maintained"}
            assert row["curated"] is False


def test_methodology_only_cannot_be_invoked() -> None:
    fake = FakeCliTransport(installed_ids={METHODOLOGY_ID})
    ext = Extension(transports={"cli": fake}, arms={METHODOLOGY_ID: fake})
    with pytest.raises(ExtensionError) as err:
        ext.invoke(METHODOLOGY_ID, "extract", {})
    assert "not an arm" in str(err.value).lower()
    assert fake.calls == []


def test_curated_true_does_not_imply_maintained(entries: list[dict]) -> None:
    checkov = next(row for row in entries if row["id"] == PINNED_CURATED_NOT_MAINTAINED)
    assert checkov["curated"] is True
    assert checkov["kind"] == "arm"
    assert checkov["tier"] != "maintained"
    curated_not_maintained = [
        row["id"]
        for row in entries
        if row.get("curated") is True and row.get("tier") != "maintained"
    ]
    assert PINNED_CURATED_NOT_MAINTAINED in curated_not_maintained


def test_no_entries_are_held(entries: list[dict]) -> None:
    held_rows = [row for row in entries if row["tier"] == "held"]
    assert held_rows == []
    assert set(HELD_HTTP_MCP_ARM_IDS) == set()


def test_held_cannot_be_invoked_even_if_curated_and_installed() -> None:
    """The live catalog has no held rows anymore; the fixture catalog
    pins the held gate itself (see also the fixture-row test below)."""
    entry = CatalogEntry(
        id=HELD_FIXTURE_ID,
        kind="arm",
        protocols=("mcp", "http"),
        curated=True,
        notes="Fixture held HTTP MCP arm.",
        tier="held",
        held_reason="HTTP MCP is held on this public cut.",
    )
    fake = FakeCliTransport(installed_ids={HELD_FIXTURE_ID})
    ext = Extension(
        catalog=Catalog([entry]),
        transports={"mcp": fake},
        arms={HELD_FIXTURE_ID: fake},
    )
    with pytest.raises(NotHeldError) as err:
        ext.invoke(HELD_FIXTURE_ID, "list_tools", {})
    assert err.value.entry_id == HELD_FIXTURE_ID
    assert "held" in str(err.value).lower()
    assert fake.calls == []


def test_fixture_held_row_cannot_be_invoked_even_if_curated() -> None:
    entry = CatalogEntry(
        id=HELD_FIXTURE_ID,
        kind="arm",
        protocols=("mcp", "http"),
        curated=True,
        notes="Fixture held HTTP MCP arm.",
        tier="held",
        held_reason="HTTP MCP is held on this public cut.",
    )
    catalog = Catalog([entry])
    fake = FakeCliTransport(installed_ids={HELD_FIXTURE_ID})
    ext = Extension(
        catalog=catalog,
        transports={"mcp": fake},
        arms={HELD_FIXTURE_ID: fake},
    )
    with pytest.raises(NotHeldError) as err:
        ext.invoke(HELD_FIXTURE_ID, "ping", {})
    assert err.value.entry_id == HELD_FIXTURE_ID
    assert "held" in str(err.value).lower()
    assert fake.calls == []


def test_list_entries_include_tier() -> None:
    rows = [entry.to_dict() for entry in list_entries()]
    assert rows
    for row in rows:
        assert row["tier"] in ALLOWED_TIERS, row["id"]


def test_describe_includes_tier() -> None:
    described = describe(PINNED_CURATED_NOT_MAINTAINED).to_dict()
    assert described["id"] == PINNED_CURATED_NOT_MAINTAINED
    assert described["tier"] in ALLOWED_TIERS
    assert described["tier"] != "maintained"
    burp = describe("burp-mcp").to_dict()
    assert burp["tier"] == "research"
    assert not burp.get("held_reason")
    meta = describe("metasploit-mcp").to_dict()
    assert meta["tier"] == "research"
    assert not meta.get("held_reason")


def test_cli_list_and_describe_include_tier(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["list"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed
    for row in listed:
        assert row["tier"] in ALLOWED_TIERS, row["id"]
    assert main(["describe", PINNED_CURATED_NOT_MAINTAINED]) == 0
    described = json.loads(capsys.readouterr().out)
    assert described["tier"] in ALLOWED_TIERS
    assert main(["describe", "burp-mcp"]) == 0
    burp = json.loads(capsys.readouterr().out)
    assert burp["tier"] == "research"


def test_mcp_list_and_describe_include_tier() -> None:
    server = McpServer()
    rows = _content_json(_call(server, "list"))
    assert rows
    for row in rows:
        assert row["tier"] in ALLOWED_TIERS, row["id"]
    described = _content_json(
        _call(server, "describe", {"id": PINNED_CURATED_NOT_MAINTAINED})
    )
    assert described["tier"] in ALLOWED_TIERS
    burp = _content_json(_call(server, "describe", {"id": "burp-mcp"}))
    assert burp["tier"] == "research"


def test_mcp_invoke_held_is_tool_error_even_when_installed() -> None:
    entry = CatalogEntry(
        id=HELD_FIXTURE_ID,
        kind="arm",
        protocols=("mcp", "http"),
        curated=True,
        notes="Fixture held HTTP MCP arm.",
        tier="held",
        held_reason="HTTP MCP is held on this public cut.",
    )
    fake = FakeCliTransport(installed_ids={HELD_FIXTURE_ID})
    ext = Extension(
        catalog=Catalog([entry]),
        transports={"mcp": fake},
        arms={HELD_FIXTURE_ID: fake},
    )
    server = McpServer(extension=ext)
    response = _call(server, "invoke", {"id": HELD_FIXTURE_ID, "action": "list_tools"})
    assert response["result"]["isError"] is True
    assert "held" in _content_text(response).lower()
    assert fake.calls == []


def test_cli_invoke_unconfigured_admitted_is_failed_envelope(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["invoke", "metasploit-mcp", "list_tools"]) == 2
    captured = capsys.readouterr()
    assert "arm is not installed" in captured.out
