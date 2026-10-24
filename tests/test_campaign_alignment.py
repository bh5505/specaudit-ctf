"""Regression checks for campaign source completeness and OSV event semantics."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extension.arms.idwolf.arm import ReportError, parse_report_bytes
from extension.arms.osv.api import run_query
from extension.arms.osv.reader import _range_covers_version


@pytest.mark.parametrize(
    "events,version,expected",
    [
        ([{"introduced": "0"}], "1.2.3", True),
        ([{"introduced": "0"}, {"fixed": "2.0.0"}], "2.0.0", False),
        ([{"introduced": "1.0.0"}, {"limit": "2.0.0"}], "1.9.0", True),
        ([{"introduced": "1.0.0"}, {"limit": "2.0.0"}], "2.0.0", False),
        ([{"introduced": "1.0.0"}, {"limit": "2.0.0"}], "3.0.0", False),
        ([{"limit": "2.0.0"}, {"introduced": "1.0.0"}], "1.9.0", True),
        ([{"introduced": "0"}, {"last_affected": "2.0.0"}], "2.0.0", True),
        ([{"introduced": "0"}, {"last_affected": "2.0.0"}], "2.0.1", False),
        (
            [
                {"introduced": "1.0.0"},
                {"fixed": "1.2.0"},
                {"introduced": "3.0.0"},
                {"fixed": "3.2.0"},
            ],
            "1.1.0",
            True,
        ),
        (
            [
                {"introduced": "1.0.0"},
                {"fixed": "1.2.0"},
                {"introduced": "3.0.0"},
                {"fixed": "3.2.0"},
            ],
            "2.0.0",
            False,
        ),
        (
            [
                {"fixed": "3.2.0"},
                {"introduced": "3.0.0"},
                {"fixed": "1.2.0"},
                {"introduced": "1.0.0"},
            ],
            "1.1.0",
            True,
        ),
        (
            [
                {"fixed": "3.2.0"},
                {"introduced": "3.0.0"},
                {"fixed": "1.2.0"},
                {"introduced": "1.0.0"},
            ],
            "2.0.0",
            False,
        ),
        ([{"introduced": "0"}, {"fixed": "1.2.0"}], "1.2", False),
        ([{"introduced": "0"}, {"fixed": "2.0.0"}], "１.2.3", False),
        ([{"introduced": "0"}, {"fixed": "2.0.0"}], "9" * 100, False),
    ],
)
def test_osv_numeric_range_timeline(
    events: list[dict[str, str]], version: str, expected: bool
) -> None:
    assert _range_covers_version({"type": "SEMVER", "events": events}, version) is expected


class _Response:
    status = 200
    headers: dict[str, str] = {}

    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self, size: int) -> bytes:
        chunk, self.body = self.body[:size], self.body[size:]
        return chunk


def test_osv_malformed_aliases_return_unknown_instead_of_raising() -> None:
    body = json.dumps(
        {
            "vulns": [
                {
                    "id": "GHSA-synthetic",
                    "modified": "2026-10-24T00:00:00Z",
                    "aliases": None,
                }
            ]
        }
    ).encode()
    result = run_query(
        {"package": {"ecosystem": "PyPI", "name": "synthetic"}, "version": "1.0"},
        transport=lambda request, timeout: _Response(body),
    )
    assert result["status"] == "unknown"
    assert result["reason"] == "response_shape_unrecognized"
    assert result["evidence"]


@pytest.mark.parametrize("events", [None, [{"introduced": 1}], [{"fixed": "2.0"}, {}]])
def test_osv_malformed_range_events_return_unknown(events: object) -> None:
    body = json.dumps(
        {
            "vulns": [
                {
                    "id": "GHSA-synthetic",
                    "modified": "2026-10-24T00:00:00Z",
                    "affected": [{"ranges": [{"type": "SEMVER", "events": events}]}],
                }
            ]
        }
    ).encode()
    result = run_query(
        {"package": {"ecosystem": "PyPI", "name": "synthetic"}, "version": "1.0"},
        transport=lambda request, timeout: _Response(body),
    )
    assert result["status"] == "unknown"
    assert result["reason"] == "response_shape_unrecognized"


def test_idwolf_future_analyzer_version_is_not_assumed_compatible() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "extension/arms/idwolf/data/demo-idwolf-ad.jsonl"
    ).read_bytes()
    changed = source.replace(b'"tool_version":"1.2"', b'"tool_version":"9.9"')
    assert changed != source
    with pytest.raises(ReportError, match="not a supported analyzer version"):
        parse_report_bytes(changed)
