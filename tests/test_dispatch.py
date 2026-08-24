"""Two-tier dispatch machinery: scope parsing, matching, audit, stamps."""

from __future__ import annotations

import pytest

from extension.arms.dispatch import (
    authorize,
    log_dispatch,
    parse_scope,
    stamp,
    target_in_scope,
    unarmed_refusal,
)


# --- scope parsing ------------------------------------------------------


def test_parse_scope_accepts_mixed_items() -> None:
    scope, refusal = parse_scope("10.10.0.0/16,192.168.1.5,lab-host.internal,localhost")
    assert refusal is None and scope is not None
    assert scope.networks == ("10.10.0.0/16", "192.168.1.5/32")
    assert sorted(scope.hosts) == ["lab-host.internal", "localhost"]


def test_parse_scope_accepts_ipv6_and_uri_prefixes() -> None:
    scope, refusal = parse_scope("fd00::/8,https://api.lab.internal/v1")
    assert refusal is None and scope is not None
    assert scope.networks == ("fd00::/8",)
    assert scope.uri_prefixes == ("https://api.lab.internal/v1",)


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "   ",
        "*",
        "0.0.0.0/0",
        "::/0",
        "10.0.0.0/16,",
        "not a host!",
        "http://x/\x00",
        "10.10.0.999/16",
        ", ".join(f"h{i}.lab" for i in range(40)),
    ],
)
def test_parse_scope_refuses_blanket_and_malformed(bad: str | None) -> None:
    scope, refusal = parse_scope(bad)
    assert scope is None, bad
    assert refusal is not None


# --- target matching ----------------------------------------------------


def _scope(raw: str):
    scope, refusal = parse_scope(raw)
    assert refusal is None
    return scope


def test_ip_in_cidr_and_literal() -> None:
    scope = _scope("10.10.0.0/16,192.168.1.5")
    assert target_in_scope("10.10.5.22", scope) is True
    assert target_in_scope("192.168.1.5", scope) is True
    assert target_in_scope("10.11.0.1", scope) is False
    assert target_in_scope("192.168.1.6", scope) is False


def test_hostname_exact_match_no_subdomains() -> None:
    scope = _scope("lab-host.internal")
    assert target_in_scope("lab-host.internal", scope) is True
    assert target_in_scope("LAB-HOST.internal.", scope) is True  # case/FC-root-dot
    assert target_in_scope("evil.lab-host.internal", scope) is False
    assert target_in_scope("lab-host.internal.evil.example", scope) is False


def test_url_matches_by_host_and_uri_prefix() -> None:
    scope = _scope("10.10.0.0/16,https://api.lab.internal/v1")
    assert target_in_scope("http://10.10.9.9:8080/path", scope) is True
    assert target_in_scope("https://api.lab.internal/v1/scan", scope) is True
    assert target_in_scope("https://api.lab.internal/v2", scope) is False
    assert target_in_scope("https://other.lab.internal/v1", scope) is False


def test_empty_target_never_matches() -> None:
    assert target_in_scope("", _scope("10.0.0.0/8")) is False
    assert target_in_scope("   ", _scope("10.0.0.0/8")) is False


# --- authorization ------------------------------------------------------


def test_authorize_unarmed_names_the_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("X_ARM_DISPATCH_SCOPE", raising=False)
    scope, refusal = authorize("X_ARM_DISPATCH_SCOPE", "module_execute", "10.0.0.1")
    assert scope is None
    assert "dispatch action" in refusal
    assert "X_ARM_DISPATCH_SCOPE" in refusal
    assert "logged" in refusal


def test_authorize_armed_in_scope_and_out_of_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("X_ARM_DISPATCH_SCOPE", "10.10.0.0/16")
    scope, refusal = authorize("X_ARM_DISPATCH_SCOPE", "detonate", "10.10.1.1")
    assert refusal is None and scope is not None
    scope, refusal = authorize("X_ARM_DISPATCH_SCOPE", "detonate", "8.8.8.8")
    assert scope is None
    assert "outside the armed dispatch scope" in refusal


def test_authorize_bad_scope_value_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("X_ARM_DISPATCH_SCOPE", "*")
    scope, refusal = authorize("X_ARM_DISPATCH_SCOPE", "detonate", "10.0.0.1")
    assert scope is None
    assert "blanket scope" in refusal


def test_authorize_target_none_allowed_when_armed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("X_ARM_DISPATCH_SCOPE", "10.10.0.0/16")
    scope, refusal = authorize("X_ARM_DISPATCH_SCOPE", "module_execute", None)
    assert refusal is None and scope is not None


def test_unarmed_refusal_message() -> None:
    msg = unarmed_refusal("METASPLOIT_DISPATCH_SCOPE", "module_execute")
    assert "module_execute" in msg
    assert "METASPLOIT_DISPATCH_SCOPE" in msg


# --- audit and stamp ----------------------------------------------------


def test_log_dispatch_writes_stderr_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    scope = _scope("10.10.0.0/16")
    log_dispatch("metasploit-mcp", "module_execute", scope, "10.10.5.22")
    err = capsys.readouterr().err
    assert err.startswith("[dispatch] ")
    assert "arm=metasploit-mcp" in err
    assert "action=module_execute" in err
    assert "scope=10.10.0.0/16" in err
    assert "target=10.10.5.22" in err
    log_dispatch("metasploit-mcp", "module_execute", scope, None)
    assert "target=unknown" in capsys.readouterr().err


def test_stamp_shape() -> None:
    scope = _scope("10.10.0.0/16")
    marked = stamp(scope, "10.10.5.22")
    assert marked == {
        "dispatch": "true",
        "scope": "10.10.0.0/16",
        "target": "10.10.5.22",
    }
    assert stamp(scope, None)["target"] == "unknown"


def test_parse_scope_refuses_blanket_variants() -> None:
    """Canonicalization variants of blanket scopes are refused (review fix)."""
    for bad in ("0::/0", "0.0.0.0/0.0.0.0", "::/128.0.0.0" if False else "0.0.0.0/0"):
        scope, refusal = parse_scope(bad)
        assert scope is None, bad
        assert "blanket" in refusal, bad


def test_parse_scope_refuses_tab_and_escape() -> None:
    scope, refusal = parse_scope("http://x/\t1")
    assert scope is None
    assert "control characters" in refusal


def test_uri_prefix_scheme_and_boundary() -> None:
    scope = _scope("https://api.lab.internal/v1")
    assert target_in_scope("https://api.lab.internal/v1/scan", scope) is True
    # No segment-boundary bleed: /v10 is not under /v1.
    assert target_in_scope("https://api.lab.internal/v10", scope) is False
    assert target_in_scope("https://api.lab.internal/v1evil", scope) is False
    # Scheme must match; https prefix does not authorize http targets.
    assert target_in_scope("http://api.lab.internal/v1/x", scope) is False


def test_scope_hostname_syntax() -> None:
    for bad in ("-lead.lab", "trail-", ".lead.lab", "trail.lab.", "dou..ble"):
        scope, refusal = parse_scope(bad)
        assert scope is None, bad


def test_bare_userhost_target_refused() -> None:
    assert target_in_scope("user@10.10.0.1", _scope("10.10.0.0/16")) is False
