"""Causal tests for EVID-01 dynamic caller-path binding."""

from __future__ import annotations

import pytest

from caller_path_binding import bind_caller_path


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
