"""User-controlled DNS names cannot become dig control arguments."""

import importlib.util
from pathlib import Path

import pytest


_PATH = Path(__file__).resolve().parents[1] / "tools" / "livefire_capture.py"
_SPEC = importlib.util.spec_from_file_location("livefire_capture", _PATH)
livefire = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(livefire)


@pytest.mark.parametrize("name", ["+trace", "@server", "-f", "ok.test\n+trace", "ok.test..", "bad label", "a/../b"])
def test_dig_control_syntax_rejected_before_spawn(monkeypatch, name):
    def forbidden(*args, **kwargs):
        raise AssertionError("dig must not run")
    monkeypatch.setattr(livefire.subprocess, "run", forbidden)
    with pytest.raises(ValueError, match="invalid DNS query name"):
        livefire.dns_probe_dig("127.0.0.1", 53, 1, name)


def test_valid_name_is_one_literal_argument(monkeypatch):
    seen = []
    def fake_run(argv, **kwargs):
        seen.append(argv)
        return type("Completed", (), {"stdout": ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"})()
    monkeypatch.setattr(livefire.subprocess, "run", fake_run)
    result = livefire.dns_probe_dig("127.0.0.1", 53, 1, "owned.example.")
    assert seen[0][-2:] == ["owned.example.", "A"]
    assert result["dns_rcode"] == "NOERROR"
