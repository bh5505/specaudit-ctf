"""Curated osv arm: offline snapshot reads + bounded live OSV API queries.

Offline and fully deterministic: the snapshot layer reads caller-supplied
files, and every live-layer test injects a scripted fake transport, so no
test ever opens a network socket.  Exercises the exact ok/exit mapping for
complete/partial/unknown/invalid results, every snapshot rejection case,
the pagination/cap/HTTP-classification contract of the live client, and CLI
parity through extension.dispatch.dispatch_invoke.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import urllib.error
from pathlib import Path

import pytest

from extension.contract import ArmSpec, Catalog, CatalogEntry, Extension
from extension.dispatch import dispatch_invoke
from extension.arms.osv import ALLOWED_ACTIONS, ARM_ID, OsvArm
from extension.arms.osv import api, policy, reader
from extension.arms.osv.api import (
    _RefuseRedirect,
    _RedirectRefused,
    run_query,
)
from extension.arms.osv.policy import (
    EVIDENCE_BODY_BYTES,
    LIVE_TIMEOUT_SECONDS,
    MAX_LIVE_RECORDS,
    MAX_PAGES,
    MAX_RESPONSE_BYTES,
    SNAPSHOT_SCHEMA,
    args_refusal,
    demo_snapshot_path,
    snapshot_refusal,
)
from extension.arms.osv.reader import (
    MAX_RECORD_BYTES,
    SnapshotError,
    load_snapshot_bytes,
    load_snapshot_file,
    lookup_by_coordinate,
    staleness_note,
)

DATA = Path(__file__).resolve().parent.parent / "extension" / "arms" / "osv" / "data"
DEMO_SNAPSHOT = DATA / "demo-osv-snapshot.json"

SNAPSHOT_TIME = "2026-10-23T00:00:00Z"
COMMIT = "a" * 40


# --- Harness ---------------------------------------------------------------

def _spec() -> ArmSpec:
    return ArmSpec(id=ARM_ID, protocols=("cli",), notes="test arm")


def _ext(transport=None) -> Extension:
    entry = CatalogEntry(id=ARM_ID, kind="arm", protocols=("cli",), notes="test arm row")
    return Extension(catalog=Catalog([entry]), arms={ARM_ID: OsvArm(transport=transport)})


def _invoke(action: str, args: dict, transport=None):
    return OsvArm(transport=transport).invoke(_spec(), action, args)


def _dispatch(action: str, args: dict | None, transport=None):
    return dispatch_invoke(_ext(transport), arm_id=ARM_ID, action=action, args=args)


class FakeResponse:
    """Scripted 200-style response with bounded incremental reads."""

    def __init__(self, status: int, body: bytes = b"", headers: dict | None = None):
        self.status = status
        self.code = status
        self.headers = headers or {}
        self._body = body
        self._offset = 0
        self.reads = 0

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        if size is None or size < 0:
            data = self._body[self._offset:]
            self._offset = len(self._body)
            return data
        data = self._body[self._offset:self._offset + size]
        self._offset += len(data)
        return data


class FakeTransport:
    """Scripted transport: pops queued responses or raises; counts calls."""

    def __init__(self, script: list):
        self.script = list(script)
        self.calls: list = []
        self.timeouts: list[float] = []

    def __call__(self, request, timeout: float):
        self.calls.append(request)
        self.timeouts.append(timeout)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


# Snapshot helpers -----------------------------------------------------------

def _record(**overrides) -> dict:
    record = {
        "id": "OSV-SYNTH-TEST-0001",
        "modified": "2026-10-01T00:00:00Z",
        "summary": "synthetic test record",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "test-package"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                    }
                ],
            }
        ],
    }
    record.update(overrides)
    return record


def _snapshot_bytes(
    record: dict | None = None,
    *,
    schema: object = SNAPSHOT_SCHEMA,
    packages: dict | None = None,
    snapshot_time: str = SNAPSHOT_TIME,
) -> bytes:
    if packages is None:
        packages = {"PyPI:test-package": [record if record is not None else _record()]}
    document = {
        "snapshot_schema": schema,
        "snapshot_time": snapshot_time,
        "packages": packages,
    }
    return json.dumps(document).encode("utf-8")


def _snapshot_error(raw: bytes) -> str:
    with pytest.raises(SnapshotError) as excinfo:
        load_snapshot_bytes(raw)
    return str(excinfo.value)


def _write_snapshot(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    return path


# Live helpers ---------------------------------------------------------------

def _live_record(
    rid: str = "OSV-SYNTH-LIVE-0001",
    *,
    modified: str = "2026-10-23T00:00:00Z",
    aliases: list | None = None,
    withdrawn: str | None = None,
    references: list | None = None,
) -> dict:
    record = {
        "id": rid,
        "modified": modified,
        "summary": f"synthetic live advisory {rid}",
        "affected": [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "demo-package",
                    "purl": "pkg:pypi/demo-package",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}],
                    }
                ],
            }
        ],
    }
    if aliases is not None:
        record["aliases"] = aliases
    if withdrawn is not None:
        record["withdrawn"] = withdrawn
    if references is not None:
        record["references"] = references
    return record


def _page(vulns: list | None = (), token: str | None = None) -> bytes:
    document: dict = {}
    if vulns is not None:
        document["vulns"] = list(vulns)
    if token is not None:
        document["next_page_token"] = token
    return json.dumps(document).encode("utf-8")


def _ok_response(body: bytes) -> FakeResponse:
    return FakeResponse(200, body, {"Content-Type": "application/json"})


COORDINATE_ARGS = {"ecosystem": "PyPI", "name": "demo-package", "version": "1.2.3"}
PURL_ARGS = {"purl": "pkg:pypi/demo-package", "version": "1.2.3"}


# --- Fixture presence, list_tools, allowlist --------------------------------

def test_shipped_demo_snapshot_exists_and_list_tools_makes_no_coverage_claim() -> None:
    assert demo_snapshot_path().is_file()
    assert demo_snapshot_path() == DEMO_SNAPSHOT
    listed = _invoke("list_tools", {})
    assert listed.ok is True
    assert listed.output["actions"] == sorted(ALLOWED_ACTIONS | {"list_tools", "tools/list"})
    assert listed.output["demo_snapshot"] == str(DEMO_SNAPSHOT)
    assert listed.output["caps"] == {
        "live_timeout_seconds": LIVE_TIMEOUT_SECONDS,
        "max_pages": MAX_PAGES,
        "max_records": MAX_LIVE_RECORDS,
        "max_response_bytes": MAX_RESPONSE_BYTES,
    }
    assert listed.output["live_endpoint"] == {
        "host": "https://api.osv.dev",
        "path": "/v1/query",
    }
    # Interface listing only: no coverage/status claim anywhere in the output.
    assert "status" not in listed.output
    assert any("makes no claim" in caveat for caveat in listed.output["caveats"])


def test_list_tools_refuses_arguments() -> None:
    outcome = _dispatch("list_tools", {"snapshot": "x.json"})
    assert outcome.exit_code == 1
    assert outcome.document["ok"] is False
    assert outcome.document["output"] is None


def test_unknown_action_is_a_plain_failure() -> None:
    outcome = _dispatch("querybatch", {})
    assert outcome.exit_code == 1
    assert "not on the read allowlist" in outcome.document["error"]
    assert outcome.document["output"] is None


# --- Snapshot: complete reads ------------------------------------------------

def test_read_snapshot_is_complete_with_stable_source_identity() -> None:
    result = _invoke("read_snapshot", {"snapshot": str(DEMO_SNAPSHOT)})
    assert result.ok is True
    assert result.error is None
    document = result.output
    assert document["status"] == "complete"
    assert document["query"]["kind"] == "snapshot"
    assert document["query"]["snapshot_time"] == SNAPSHOT_TIME
    assert document["source"]["path"] == str(DEMO_SNAPSHOT)
    raw = DEMO_SNAPSHOT.read_bytes()
    assert document["source"]["sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()
    assert document["source"]["bytes"] == len(raw)
    ids = [record["id"] for record in document["records"]]
    assert ids == sorted(ids)
    assert len(ids) == 4
    assert document["limitations"]
    assert document["reason"] is None


def test_get_advisory_hit_preserves_the_documented_fields() -> None:
    result = _invoke(
        "get_advisory", {"snapshot": str(DEMO_SNAPSHOT), "id": "OSV-SYNTH-DEMO-0001"}
    )
    assert result.ok is True
    document = result.output
    assert document["status"] == "complete"
    assert document["query"]["kind"] == "advisory"
    assert document["query"]["id"] == "OSV-SYNTH-DEMO-0001"
    (record,) = document["records"]
    assert record["id"] == "OSV-SYNTH-DEMO-0001"
    assert record["modified"] == "2026-10-01T12:00:00Z"
    assert record["aliases"] == ["SYNTH-CVE-0001"]
    assert record["summary"]
    assert record["affected"][0]["package"]["ecosystem"] == "PyPI"
    assert record["affected"][0]["ranges"][0]["events"] == [
        {"introduced": "1.0.0"},
        {"fixed": "1.4.0"},
    ]


def test_get_advisory_alias_is_not_identity() -> None:
    result = _invoke(
        "get_advisory", {"snapshot": str(DEMO_SNAPSHOT), "id": "SYNTH-CVE-0001"}
    )
    # The offline snapshot was read in full, so an id miss is a proven
    # zero-match: complete with empty records plus a limitation note.
    assert result.ok is True
    assert result.output["status"] == "complete"
    assert result.output["records"] == []
    assert any("no advisory with id" in note for note in result.output["limitations"])


def test_withdrawn_record_stays_flagged() -> None:
    result = _invoke(
        "get_advisory", {"snapshot": str(DEMO_SNAPSHOT), "id": "OSV-SYNTH-DEMO-0002"}
    )
    assert result.ok is True
    (record,) = result.output["records"]
    assert record["withdrawn"] == "2026-10-05T08:00:00Z"


def test_coordinate_match_and_complete_no_match() -> None:
    snapshot = load_snapshot_file(DEMO_SNAPSHOT)
    match = lookup_by_coordinate(snapshot, "PyPI", "demo-package", "1.2.3")
    assert [record["id"] for record in match] == [
        "OSV-SYNTH-DEMO-0001",
        "OSV-SYNTH-DEMO-0002",
    ]
    no_match = lookup_by_coordinate(snapshot, "PyPI", "nomatch-demo-package", "9.9.9")
    assert no_match == []
    alias_record = lookup_by_coordinate(snapshot, "PyPI", "alias-demo-package", "0.9.0")
    assert [record["id"] for record in alias_record] == ["OSV-SYNTH-DEMO-0003"]
    # A non-dotted-numeric version matches only via the explicit versions list.
    assert [
        record["id"]
        for record in lookup_by_coordinate(snapshot, "PyPI", "alias-demo-package", "0.9.0+local")
    ] == []


def test_snapshot_staleness_helper() -> None:
    note = staleness_note("2026-10-23T00:00:00Z", "2026-10-24T00:00:00Z")
    assert note is not None and "modified after the snapshot" in note
    assert staleness_note("2026-10-23T00:00:00Z", "2026-10-01T00:00:00Z") is None
    assert staleness_note("2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z") is None
    # Unparseable timestamps fall back to exact string comparison.
    fallback = staleness_note("2026-10-23", "2026-10-24")
    assert fallback is not None
    assert staleness_note("2026-10-24", "2026-10-23") is None


def test_reader_never_imports_the_live_client() -> None:
    source = Path(reader.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any("api" in alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert "api" not in (node.module or "")


# --- Snapshot: every reject case is a plain failure ---------------------------

def _record_without(key: str) -> dict:
    record = _record()
    record.pop(key)
    return record


def _affected_with_range(range_entry: dict) -> dict:
    return {
        "package": {"ecosystem": "PyPI", "name": "test-package"},
        "ranges": [range_entry],
    }


_FIXED_RANGE = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}

_SNAPSHOT_REJECT_CASES = [
    # Short ids keep pytest output readable: the raw payloads run to 256 KiB
    # and the auto-generated ids would overflow the 32767-character Windows
    # environment-variable limit pytest uses to track the current test.
    # unknown schema version (past/future/missing)
    pytest.param(
        _snapshot_bytes(schema="specaudit-ctf.osv-snapshot/2"),
        "unknown source schema version",
        id="schema-future",
    ),
    pytest.param(_snapshot_bytes(schema="osv/1"), "unknown source schema version", id="schema-past"),
    pytest.param(_snapshot_bytes(schema=None), "unknown source schema version", id="schema-missing"),
    # mixed record schema versions in one snapshot
    pytest.param(
        _snapshot_bytes(
            packages={
                "PyPI:test-package": [_record(schema_version="1.0.0")],
                "PyPI:other-package": [
                    _record(
                        id="OSV-SYNTH-TEST-0002",
                        schema_version="1.1.0",
                        affected=[
                            {
                                "package": {"ecosystem": "PyPI", "name": "other-package"},
                                "ranges": [_FIXED_RANGE],
                            }
                        ],
                    )
                ],
            }
        ),
        "mixed record schema_version",
        id="mixed-record-schema-versions",
    ),
    # duplicate OSV ids across coordinates
    pytest.param(
        _snapshot_bytes(
            packages={
                "PyPI:test-package": [_record()],
                "PyPI:other-package": [_record()],
            }
        ),
        "duplicate OSV id",
        id="duplicate-id-across-coordinates",
    ),
    # oversized record
    pytest.param(
        _snapshot_bytes(_record(summary="x" * (MAX_RECORD_BYTES + 1))),
        "record cap",
        id="oversized-record",
    ),
    # malformed affected data
    pytest.param(_snapshot_bytes(_record_without("affected")), "missing affected", id="affected-missing"),
    pytest.param(_snapshot_bytes(_record(affected=None)), "affected must be a list", id="affected-none"),
    pytest.param(_snapshot_bytes(_record(affected="nope")), "affected must be a list", id="affected-not-a-list"),
    pytest.param(
        _snapshot_bytes(_record(affected=[{"ranges": []}])),
        "package must be a mapping",
        id="affected-entry-without-package",
    ),
    pytest.param(
        _snapshot_bytes(
            _record(
                affected=[
                    {
                        "package": {"ecosystem": "PyPI:eco", "name": "x"},
                        "ranges": [_FIXED_RANGE],
                    }
                ]
            )
        ),
        "must not contain a coordinate separator",
        id="package-ecosystem-with-separator",
    ),
    pytest.param(
        _snapshot_bytes(
            _record(affected=[_affected_with_range({"type": "BAD", "events": [{"introduced": "0"}]})])
        ),
        "type must be one of",
        id="range-type-unknown",
    ),
    pytest.param(
        _snapshot_bytes(
            _record(affected=[_affected_with_range({"type": "GIT", "events": [{"introduced": "0"}]})])
        ),
        "repo is required for GIT ranges",
        id="git-range-without-repo",
    ),
    pytest.param(
        _snapshot_bytes(
            _record(
                affected=[
                    _affected_with_range(
                        {"type": "SEMVER", "events": [{"introduced": "0", "fixed": "1.0.0"}]}
                    )
                ]
            )
        ),
        "exactly one of",
        id="semver-event-two-keys",
    ),
    pytest.param(
        _snapshot_bytes(
            _record(affected=[_affected_with_range({"type": "SEMVER", "events": [{"bogus": "0"}]})])
        ),
        "exactly one of",
        id="semver-event-unknown-key",
    ),
    pytest.param(
        _snapshot_bytes(
            _record(
                affected=[
                    {"package": {"ecosystem": "PyPI", "name": "x"}, "ranges": [_FIXED_RANGE], "bogus": 1}
                ]
            )
        ),
        "unsupported fields",
        id="affected-entry-unsupported-field",
    ),
    # unsupported coordinates
    pytest.param(_snapshot_bytes(packages={"PyPI": [_record()]}), "'<ecosystem>:<name>'", id="coordinate-missing-name"),
    pytest.param(
        _snapshot_bytes(packages={"PyPI:test:package": [_record()]}),
        "must not contain ':'",
        id="coordinate-extra-separator",
    ),
    pytest.param(_snapshot_bytes(packages={":test-package": [_record()]}), "non-empty", id="coordinate-empty-ecosystem"),
    pytest.param(
        _snapshot_bytes(packages={"Py PI:test-package": [_record()]}),
        "must not contain whitespace",
        id="coordinate-whitespace",
    ),
    # a record filed under a coordinate it does not affect
    pytest.param(
        _snapshot_bytes(packages={"PyPI:other-package": [_record()]}),
        "does not list the coordinate",
        id="record-filed-under-wrong-coordinate",
    ),
    # empty containers
    pytest.param(_snapshot_bytes(packages={}), "non-empty packages mapping", id="packages-empty"),
    pytest.param(
        _snapshot_bytes(packages={"PyPI:test-package": []}),
        "non-empty records list",
        id="records-empty",
    ),
    # bad record scalars
    pytest.param(_snapshot_bytes(_record(id=" ")), "non-empty string", id="id-blank"),
    pytest.param(_snapshot_bytes(_record(id=7)), "must be a non-empty string", id="id-not-a-string"),
]


@pytest.mark.parametrize("raw,expected_fragment", _SNAPSHOT_REJECT_CASES)
def test_snapshot_rejects(raw: bytes, expected_fragment: str) -> None:
    message = _snapshot_error(raw)
    assert expected_fragment in message


def test_duplicate_json_keys_and_invalid_utf8_are_rejected(tmp_path: Path) -> None:
    head = (
        '{"snapshot_schema": "specaudit-ctf.osv-snapshot/1", '
        '"snapshot_schema": "specaudit-ctf.osv-snapshot/1", '
        '"snapshot_time": "2026-10-23T00:00:00Z", '
        '"packages": {}}'
    )
    assert "duplicate mapping key" in _snapshot_error(head.encode("utf-8"))
    assert "not valid UTF-8" in _snapshot_error(b'{"snapshot_schema": "\xff\xfe"}')


def test_snapshot_rejections_are_plain_arm_failures(tmp_path: Path) -> None:
    path = _write_snapshot(tmp_path / "bad.json", _snapshot_bytes(schema="osv/9"))
    for action, args in (
        ("read_snapshot", {"snapshot": str(path)}),
        ("get_advisory", {"snapshot": str(path), "id": "OSV-SYNTH-TEST-0001"}),
    ):
        result = _invoke(action, args)
        assert result.ok is False
        assert result.output is None
        assert result.error and "unknown source schema version" in result.error


# --- Snapshot: path and argument refusals ------------------------------------

def test_snapshot_path_refusals(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    url_refusal = snapshot_refusal("https://demo.invalid/snap.json")
    assert url_refusal == (None, "args.snapshot must be a local file, not a URL")
    assert snapshot_refusal(str(missing))[1] == (
        f"args.snapshot is not an existing file: {missing}"
    )
    wrong_suffix = _write_snapshot(tmp_path / "snap.jsonl", _snapshot_bytes())
    assert ".jsonl" in snapshot_refusal(str(wrong_suffix))[1]
    assert snapshot_refusal(str(tmp_path))[1] == (
        f"args.snapshot is not an existing file: {tmp_path}"
    )
    assert "requires a local snapshot path" in snapshot_refusal(7)[1]
    assert "requires a local snapshot path" in snapshot_refusal(None)[1]
    tiny = _write_snapshot(tmp_path / "tiny.json", b"12345678901234")
    _, refusal = snapshot_refusal(str(tiny), max_bytes=8)
    assert refusal is not None and "byte read cap" in refusal


@pytest.mark.parametrize(
    "args,fragment",
    [
        ({"snapshot": str(DEMO_SNAPSHOT)}, "requires args.id"),
        ({"snapshot": str(DEMO_SNAPSHOT), "id": 5}, "args.id must be a non-empty string"),
        ({"snapshot": str(DEMO_SNAPSHOT), "id": " OSV-SYNTH-DEMO-0001"}, "surrounding whitespace"),
        ({}, "requires a local snapshot path"),
        ({"snapshot": str(DEMO_SNAPSHOT), "id": "X", "extra": 1}, "unexpected: extra"),
    ],
)
def test_get_advisory_argument_refusals(args: dict, fragment: str) -> None:
    result = _invoke("get_advisory", args)
    assert result.ok is False
    assert result.output is None
    assert fragment in result.error


# --- Live: complete pagination ----------------------------------------------

def test_single_page_complete_envelope() -> None:
    body = _page(
        [
            _live_record(
                aliases=["SYNTH-CVE-0001"],
                withdrawn="2026-10-01T00:00:00Z",
                references=[{"type": "WEB", "url": "https://advisories.demo.invalid/x"}],
            )
        ]
    )
    transport = FakeTransport([_ok_response(body)])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is True
    assert result.error is None
    document = result.output
    assert document["status"] == "complete"
    assert document["query"] == {
        "package": {"ecosystem": "PyPI", "name": "demo-package"},
        "version": "1.2.3",
    }
    (record,) = document["records"]
    assert set(record) == {
        "id",
        "aliases",
        "modified",
        "summary",
        "withdrawn",
        "affected",
        "source_link",
    }
    assert record["id"] == "OSV-SYNTH-LIVE-0001"
    assert record["aliases"] == ["SYNTH-CVE-0001"]
    assert record["withdrawn"] == "2026-10-01T00:00:00Z"
    assert record["source_link"] == "https://advisories.demo.invalid/x"
    assert record["affected"][0]["package"]["purl"] == "pkg:pypi/demo-package"
    source = document["source"]
    assert source["host"] == "https://api.osv.dev"
    assert source["endpoint"] == "/v1/query"
    assert source["fetched_at"]
    assert source["pages"] == 1
    (page,) = source["page_outcomes"]
    assert page["http_status"] == 200
    assert page["request_sha256"]
    assert page["response_sha256"] == hashlib.sha256(body).hexdigest()
    assert page["response_bytes"] == len(body)
    assert page["vulns_retained"] == 1
    assert "next_page_token_seen" not in page
    assert document["reason"] is None
    assert document["evidence"] == []


def test_live_request_is_a_post_to_the_fixed_endpoint_and_follows_tokens() -> None:
    transport = FakeTransport(
        [
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0001")], token="page-2")),
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0002")])),
        ]
    )
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is True
    assert len(transport.calls) == 2
    first, second = transport.calls
    assert first.method == "POST"
    assert first.full_url == "https://api.osv.dev/v1/query"
    assert first.get_header("Content-type") == "application/json"
    first_body = json.loads(first.data.decode("utf-8"))
    assert first_body == {
        "package": {"ecosystem": "PyPI", "name": "demo-package"},
        "version": "1.2.3",
    }
    second_body = json.loads(second.data.decode("utf-8"))
    assert second_body["page_token"] == "page-2"
    outcomes = result.output["source"]["page_outcomes"]
    assert outcomes[0]["next_page_token_seen"] is True
    assert outcomes[0]["request_sha256"] != outcomes[1]["request_sha256"]


def test_multi_page_complete_and_one_overall_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    # A controlled clock makes the shrinking budgets exact; real-clock ticks
    # can be coarser than the gap between requests, so budgets would tie.
    now = [0.0]
    monkeypatch.setattr(api.time, "monotonic", lambda: now[0])
    inner = FakeTransport(
        [
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0001")], token="t2")),
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0002")], token="t3")),
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0003")])),
        ]
    )

    def transport(request, timeout: float):
        now[0] += 1.0
        return inner(request, timeout)

    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is True
    assert result.output["status"] == "complete"
    assert result.output["source"]["pages"] == 3
    assert [record["id"] for record in result.output["records"]] == [
        "OSV-SYNTH-LIVE-0001",
        "OSV-SYNTH-LIVE-0002",
        "OSV-SYNTH-LIVE-0003",
    ]
    # One overall deadline: per-request budgets shrink and never reset.
    assert inner.timeouts == [LIVE_TIMEOUT_SECONDS, 9.0, 8.0]


def test_token_only_page_is_followed_then_completes() -> None:
    transport = FakeTransport(
        [
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0001")], token="t2")),
            _ok_response(_page([], token="t3")),
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0002")])),
        ]
    )
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is True
    assert result.output["status"] == "complete"
    assert result.output["source"]["pages"] == 3
    assert len(result.output["records"]) == 2


@pytest.mark.parametrize(
    "vulns,token",
    [
        ((), None),
        ([], None),
    ],
)
def test_complete_zero_match_is_ok(vulns: list | tuple, token: str | None) -> None:
    transport = FakeTransport([_ok_response(_page(list(vulns), token))])
    result = _invoke("query_commit", {"commit": COMMIT}, transport=transport)
    assert result.ok is True
    assert result.output["status"] == "complete"
    assert result.output["records"] == []
    assert result.output["query"] == {"commit": COMMIT}


def test_uppercase_commit_is_normalized_in_the_request_body() -> None:
    transport = FakeTransport([_ok_response(_page())])
    result = _invoke("query_commit", {"commit": COMMIT.upper()}, transport=transport)
    assert result.ok is True
    body = json.loads(transport.calls[0].data.decode("utf-8"))
    assert body == {"commit": COMMIT}


def test_versioned_purl_alone_is_a_valid_query() -> None:
    transport = FakeTransport([_ok_response(_page())])
    result = _invoke(
        "query_package", {"purl": "pkg:pypi/demo-package@1.2.3"}, transport=transport
    )
    assert result.ok is True
    body = json.loads(transport.calls[0].data.decode("utf-8"))
    assert body == {"package": {"purl": "pkg:pypi/demo-package@1.2.3"}}


# --- Live: cap handling is partial, never clean ------------------------------

def test_page_cap_yields_partial() -> None:
    script = [
        _ok_response(_page([_live_record(f"OSV-SYNTH-PAGE-{index:02d}")], token=f"t{index}"))
        for index in range(MAX_PAGES)
    ]
    transport = FakeTransport(script)
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    document = result.output
    assert document["status"] == "partial"
    assert document["reason"] == "page_cap"
    assert document["source"]["pages"] == MAX_PAGES
    assert document["evidence"][0]["kind"] == "page_cap"
    assert len(document["records"]) == MAX_PAGES
    assert len(transport.calls) == MAX_PAGES


def test_record_cap_yields_partial() -> None:
    flood = [_live_record(f"OSV-SYNTH-BULK-{index:04d}") for index in range(150)]
    transport = FakeTransport([_ok_response(_page(flood))])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    document = result.output
    assert document["status"] == "partial"
    assert document["reason"] == "record_cap"
    assert len(document["records"]) == MAX_LIVE_RECORDS == 100
    assert document["evidence"][0]["kind"] == "record_cap"
    assert document["evidence"][0]["cap"] == MAX_LIVE_RECORDS


def test_byte_cap_yields_partial_with_incremental_reads() -> None:
    # 3 MiB body: the client must stop reading at the 2 MiB cap without
    # ever seeing the (unparseable) end of the stream.
    transport = FakeTransport([_ok_response(b"x" * (3 * 1024 * 1024))])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    document = result.output
    assert document["status"] == "partial"
    assert document["reason"] == "byte_cap"
    evidence = document["evidence"][0]
    assert evidence["kind"] == "byte_cap"
    assert evidence["cap"] == MAX_RESPONSE_BYTES
    assert MAX_RESPONSE_BYTES < evidence["response_bytes"] <= MAX_RESPONSE_BYTES + 64 * 1024
    assert document["records"] == []


# --- Live: HTTP classification and transport failures ------------------------

def _http_error(code: int, body: bytes = b"", headers: dict | None = None) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.osv.dev/v1/query", code, "Err", dict(headers or {}), io.BytesIO(body)
    )


def test_http_400_is_an_error_with_bounded_redacted_body_evidence() -> None:
    body = b'{"error": "invalid query ' + b"A" * 2000 + b' secret-token-123456"}'
    transport = FakeTransport([_http_error(400, body)])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    document = result.output
    assert document["status"] == "error"
    assert document["reason"] == "http_status_400"
    (evidence,) = document["evidence"]
    assert evidence["kind"] == "http_status"
    assert evidence["http_status"] == 400
    # Evidence is bounded to the design cap and redacted before exposure.
    assert evidence["body_bytes"] == EVIDENCE_BODY_BYTES + 1
    assert len(evidence["body_excerpt"]) <= EVIDENCE_BODY_BYTES
    assert "secret-token-123456" not in evidence["body_excerpt"]


def test_http_429_is_an_error_retry_after_recorded_never_honored() -> None:
    transport = FakeTransport([_http_error(429, b"slow down", {"Retry-After": "30"})])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    assert result.output["status"] == "error"
    assert result.output["reason"] == "http_status_429"
    (evidence,) = result.output["evidence"]
    assert evidence["retry_after"] == "30"
    # ZERO retries: exactly one request was made.
    assert len(transport.calls) == 1


def test_http_5xx_is_an_error() -> None:
    transport = FakeTransport([_http_error(503, b"unavailable")])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    assert result.output["status"] == "error"
    assert result.output["reason"] == "http_status_503"
    assert result.output["evidence"][0]["http_status"] == 503


@pytest.mark.parametrize(
    "script,reason",
    [
        ([TimeoutError("read timed out")], "timeout"),
        ([urllib.error.URLError(TimeoutError("timed out"))], "timeout"),
        ([urllib.error.URLError(OSError("connection refused"))], "transport_error"),
        ([OSError("connection reset")], "transport_error"),
    ],
)
def test_transport_failures_are_errors(script: list, reason: str) -> None:
    transport = FakeTransport(script)
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    document = result.output
    assert document["status"] == "error"
    assert document["reason"] == reason
    assert document["evidence"]


def test_malformed_200_body_is_an_error() -> None:
    transport = FakeTransport([_ok_response(b"{not json at all")])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    document = result.output
    assert document["status"] == "error"
    assert document["reason"] == "malformed_json"
    (evidence,) = document["evidence"]
    assert evidence["kind"] == "malformed_json"
    assert len(evidence["body_excerpt"]) <= EVIDENCE_BODY_BYTES


@pytest.mark.parametrize(
    "payload",
    [
        b'{"vulns": {"not": "a list"}}',
        b'{"vulns": ["a string record"]}',
        b'{"vulns": [{"modified": "2026-10-23T00:00:00Z"}]}',
        b'{"vulns": [{"id": "OSV-SYNTH-LIVE-0001"}]}',
        b'{"next_page_token": 5}',
    ],
)
def test_unrecognized_200_shape_is_unknown(payload: bytes) -> None:
    transport = FakeTransport([_ok_response(payload)])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    document = result.output
    assert document["status"] == "unknown"
    assert document["reason"] == "response_shape_unrecognized"
    assert document["evidence"]


def test_302_redirect_is_refused_with_the_code_recorded() -> None:
    transport = FakeTransport(
        [FakeResponse(302, b"", {"Location": "https://evil.invalid/x"})]
    )
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    document = result.output
    assert document["status"] == "error"
    assert document["reason"] == "redirect_refused_302"
    assert document["evidence"][0]["http_status"] == 302
    assert len(transport.calls) == 1


def test_default_opener_redirect_handler_refuses_without_following() -> None:
    with pytest.raises(_RedirectRefused) as excinfo:
        _RefuseRedirect().redirect_request(
            None, None, 302, "Found", None, "https://evil.invalid/x"
        )
    assert excinfo.value.code == 302


def test_repeated_page_token_is_an_error() -> None:
    transport = FakeTransport(
        [
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0001")], token="same")),
            _ok_response(_page([], token="same")),
        ]
    )
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.ok is False
    document = result.output
    assert document["status"] == "error"
    assert document["reason"] == "repeated_page_token"
    (evidence,) = document["evidence"]
    assert evidence["kind"] == "repeated_page_token"
    assert evidence["page_token_sha256"] == hashlib.sha256(b"same").hexdigest()


# --- Live: identity, duplicates, aliases, withdrawn ---------------------------

def test_duplicate_ids_across_pages_are_retained_and_noted() -> None:
    transport = FakeTransport(
        [
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0001")], token="t2")),
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0001")])),
        ]
    )
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    # Pagination completed, so the status stays complete — but the id
    # collision is retained and surfaced as a limitation.
    assert result.output["status"] == "complete"
    assert len(result.output["records"]) == 2
    assert any("duplicate OSV id" in note for note in result.output["limitations"])


def test_duplicate_ids_within_one_page_are_retained_and_noted() -> None:
    transport = FakeTransport([_ok_response(_page([_live_record(), _live_record()]))])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.output["status"] == "complete"
    assert len(result.output["records"]) == 2
    assert any("duplicate OSV id" in note for note in result.output["limitations"])


def test_out_of_order_ids_are_retained_with_a_limitation() -> None:
    transport = FakeTransport(
        [
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0009")], token="t2")),
            _ok_response(_page([_live_record("OSV-SYNTH-LIVE-0002")])),
        ]
    )
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.output["status"] == "complete"
    assert any("not monotonically ordered" in note for note in result.output["limitations"])


def test_aliases_without_cve_are_not_identity_and_are_carried() -> None:
    transport = FakeTransport(
        [_ok_response(_page([_live_record(aliases=["SYNTH-GHSA-0003", "SYNTH-ADVISORY-0042"])]))]
    )
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    (record,) = result.output["records"]
    assert record["id"] == "OSV-SYNTH-LIVE-0001"
    assert record["aliases"] == ["SYNTH-GHSA-0003", "SYNTH-ADVISORY-0042"]


def test_record_without_references_gets_the_canonical_source_link() -> None:
    transport = FakeTransport([_ok_response(_page([_live_record()]))])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    (record,) = result.output["records"]
    assert record["source_link"] == "https://osv.dev/vulnerability/OSV-SYNTH-LIVE-0001"


def test_live_limitations_note_advisory_context_only() -> None:
    transport = FakeTransport([_ok_response(_page())])
    result = _invoke("query_package", dict(COORDINATE_ARGS), transport=transport)
    assert result.output["limitations"] == list(policy.LIVE_LIMITATIONS)
    assert any("cannot change a challenge grade" in note for note in result.output["limitations"])


# --- Live: request-validation refusals (plain failures) -----------------------

@pytest.mark.parametrize(
    "args,fragment",
    [
        # purl / version combination refusals
        ({"purl": "pkg:pypi/demo-package@1.2.3", "version": "1.2.3"}, "must not accompany a versioned purl"),
        ({"purl": "pkg:pypi/demo-package"}, "requires args.version"),
        ({"purl": "pkg:pypi/demo-package", "version": "1.2.3", "ecosystem": "PyPI"}, "must not be combined"),
        ({"purl": "pkg:pypi/demo-package", "version": "1.2.3", "name": "demo-package"}, "must not be combined"),
        ({"purl": "pypi/demo-package", "version": "1.2.3"}, "pkg:type/name[@version]"),
        ({"purl": "pkg:pypi", "version": "1.2.3"}, "pkg:type/name[@version]"),
        ({"purl": "pkg:pypi/demo package", "version": "1.2.3"}, "pkg:type/name[@version]"),
        ({"purl": 7}, "must be a non-empty string"),
        # coordinate form refusals
        ({"ecosystem": "PyPI", "name": "demo-package"}, "missing: version"),
        ({"ecosystem": "PyPI", "version": "1.2.3"}, "missing: name"),
        ({"name": "demo-package", "version": "1.2.3"}, "missing: ecosystem"),
        ({"ecosystem": "PyPI", "name": "demo-package", "version": 3}, "must be a non-empty string"),
        ({}, "requires one coordinate form"),
        # extra arguments are refused
        ({"ecosystem": "PyPI", "name": "demo-package", "version": "1.0.0", "commit": COMMIT}, "unexpected: commit"),
        ({"purl": "pkg:pypi/demo-package@1.2.3", "extra": 1}, "unexpected: extra"),
    ],
)
def test_query_package_refusals(args: dict, fragment: str) -> None:
    result = _invoke("query_package", args)
    assert result.ok is False
    assert result.output is None
    assert fragment in result.error


@pytest.mark.parametrize(
    "args,fragment",
    [
        ({}, "requires args.commit"),
        ({"commit": "abc"}, "40-character hexadecimal"),
        ({"commit": "z" * 40}, "40-character hexadecimal"),
        ({"commit": "a" * 39}, "40-character hexadecimal"),
        ({"commit": f" {COMMIT} "}, "surrounding whitespace"),
        ({"commit": 123}, "40-character hexadecimal"),
        ({"commit": COMMIT, "version": "1.0.0"}, "unexpected: version"),
    ],
)
def test_query_commit_refusals(args: dict, fragment: str) -> None:
    result = _invoke("query_commit", args)
    assert result.ok is False
    assert result.output is None
    assert fragment in result.error


def test_policy_args_refusal_matches_the_arm_path() -> None:
    assert args_refusal("query_package", {"ecosystem": "PyPI"}) is not None
    assert args_refusal("read_snapshot", {"snapshot": "x"}) is None
    assert args_refusal("bogus", {}) is not None


# --- CLI parity through dispatch_invoke ---------------------------------------

def test_dispatch_complete_maps_to_exit_zero() -> None:
    for action, args in (
        ("read_snapshot", {"snapshot": str(DEMO_SNAPSHOT)}),
        ("get_advisory", {"snapshot": str(DEMO_SNAPSHOT), "id": "OSV-SYNTH-DEMO-0001"}),
        ("get_advisory", {"snapshot": str(DEMO_SNAPSHOT), "id": "SYNTH-CVE-0001"}),
    ):
        outcome = _dispatch(action, args)
        assert outcome.exit_code == 0, (action, args)
        assert outcome.document["ok"] is True
        assert outcome.document["output"]["status"] == "complete"


@pytest.mark.parametrize(
    "script,expected_status,expected_reason",
    [
        ([_ok_response(_page([_live_record(f"OSV-SYNTH-BULK-{i:04d}") for i in range(150)]))], "partial", "record_cap"),
        ([_ok_response(b'{"vulns": "not a list"}')], "unknown", "response_shape_unrecognized"),
        ([_http_error(400, b"bad")], "error", "http_status_400"),
    ],
)
def test_dispatch_degraded_maps_to_exit_one_with_status_and_evidence(
    script: list, expected_status: str, expected_reason: str
) -> None:
    transport = FakeTransport(script)
    outcome = _dispatch(
        "query_package", dict(COORDINATE_ARGS), transport=transport
    )
    assert outcome.exit_code == 1
    document = outcome.document
    assert document["ok"] is False
    assert document["output"]["status"] == expected_status
    assert document["output"]["reason"] == expected_reason
    assert document["output"]["evidence"]
    assert document["error"] == expected_reason


def test_dispatch_invalid_maps_to_exit_one_with_no_output() -> None:
    outcome = _dispatch("query_package", {"ecosystem": "PyPI"})
    assert outcome.exit_code == 1
    assert outcome.document["ok"] is False
    assert outcome.document["output"] is None
    assert outcome.document["error"]


def test_dispatch_partial_live_result_keeps_bounded_records() -> None:
    flood = [_live_record(f"OSV-SYNTH-BULK-{index:04d}") for index in range(150)]
    transport = FakeTransport([_ok_response(_page(flood))])
    outcome = _dispatch("query_package", dict(COORDINATE_ARGS), transport=transport)
    document = outcome.document
    assert outcome.exit_code == 1
    assert document["output"]["status"] == "partial"
    assert len(document["output"]["records"]) == MAX_LIVE_RECORDS
