"""Causal tests for EVID-01 dynamic caller-path binding."""

from __future__ import annotations

import pytest

from caller_path_binding import CallerPathBindingError, bind_caller_path


def test_basic_binding():
    b = bind_caller_path(
        attempt_id="attempt-1", arm_id="vulnify", action="lookup",
        path="/tmp/feed.json", content=b'{"a":1}', collected_at="2026-01-01T00:00:00Z",
    )
    assert b.byte_count == 7
    assert b.digest.startswith("sha256:")
    assert b.path == "/tmp/feed.json"


def test_empty_content_rejected():
    with pytest.raises(Exception):
        bind_caller_path(
            attempt_id="attempt-1", arm_id="vulnify", action="lookup",
            path="/tmp/f", content=b"", collected_at="2026-01-01T00:00:00Z",
        )


def test_empty_path_rejected():
    with pytest.raises(Exception):
        bind_caller_path(
            attempt_id="attempt-1", arm_id="vulnify", action="lookup",
            path="", content=b"x", collected_at="2026-01-01T00:00:00Z",
        )


def test_control_char_path_rejected():
    with pytest.raises(Exception):
        bind_caller_path(
            attempt_id="attempt-1", arm_id="vulnify", action="lookup",
            path="/tmp/f\x00", content=b"x", collected_at="2026-01-01T00:00:00Z",
        )


def test_oversized_content_rejected():
    with pytest.raises(Exception):
        bind_caller_path(
            attempt_id="attempt-1", arm_id="vulnify", action="lookup",
            path="/tmp/f", content=b"x" * (16 * 1024 * 1024 + 1),
            collected_at="2026-01-01T00:00:00Z",
        )


def test_digest_differs_for_different_bytes():
    a = bind_caller_path(
        attempt_id="attempt-1", arm_id="vulnify", action="lookup",
        path="/tmp/f", content=b"abc", collected_at="2026-01-01T00:00:00Z",
    )
    b = bind_caller_path(
        attempt_id="attempt-1", arm_id="vulnify", action="lookup",
        path="/tmp/f", content=b"xyz", collected_at="2026-01-01T00:00:00Z",
    )
    assert a.digest != b.digest


@pytest.mark.parametrize("field,value", [
    ("attempt_id", " "), ("arm_id", "arm\x00"), ("action", ""),
    ("path", " \t"), ("path", "/tmp/f\n"),
    ("collected_at", "not-a-time"), ("collected_at", "2026-01-01T00:00:00"),
    ("collected_at", "2026-02-30T00:00:00Z"), ("custody", " "),
])
def test_malformed_declarations_are_rejected(field, value):
    arguments = dict(
        attempt_id="attempt-1", arm_id="vulnify", action="lookup",
        path="/tmp/feed.json", content=b"x", collected_at="2026-01-01T00:00:00Z",
    )
    arguments[field] = value
    with pytest.raises(CallerPathBindingError):
        bind_caller_path(**arguments)


def test_locator_and_custody_are_explicitly_unverified(tmp_path):
    locator = tmp_path / "does-not-exist.json"
    binding = bind_caller_path(
        attempt_id="attempt-1", arm_id="vulnify", action="lookup",
        path=str(locator), content=b"declared bytes",
        collected_at="2026-01-01T00:00:00Z",
    )
    assert not locator.exists()
    assert binding.custody == "caller-declared-bytes"
    assert binding.evidence_class == "declared"
    assert "bytes-supplied-by-caller-not-acquired-from-locator" in binding.limitations
    assert "source-and-reader-consumption-not-authenticated" in binding.limitations
