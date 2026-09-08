"""Curated rpz-decoder arm: ad-hoc raw indicator extraction, fail-closed."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from extension.contract import (
    ArmSpec,
    Catalog,
    CatalogEntry,
    Extension,
    NotInstalledError,
)
from extension.arms.rpzdecoder import ARM_ID, RpzDecoderArm
from extension.arms.rpzdecoder.decoder import ZoneDecodeError, decode_axfr
from extension.arms.rpzdecoder.policy import (
    ENV_DISPATCH_SCOPE,
    args_refusal,
    keyfile_refusal,
    master_refusal,
    port_refusal,
    zone_refusal,
)

ZONE = "Example-Policy.rpz.threatstop.local"
SUFFIX = f".{ZONE}."
MASTER = "192.0.2.53"
# synthetic fixture secret (fake base64); never a real credential
SECRET = "Zm9vYmFyYmF6cXV1eHRyaWNreXNlY3JldGxlbmd0aG9mNjRieXRlcw=="

FIXTURE_AXFR = "\n".join(
    [
        f"{ZONE}. 60 IN SOA ns1.threatstop.com. hostmaster.threatstop.com. 1788838349 900 900 86400 60",
        f"{ZONE}. 0 IN NS ns1.threatstop.com.",
        f"bad.threatstop.com.{SUFFIX} 900 IN CNAME .",
        f"*.cloudflare-dns.com.{SUFFIX} 900 IN CNAME .",
        f"evil.example.com.{SUFFIX} 0 IN CNAME .",
        f"*.phish.example.net.{SUFFIX} 900 IN CNAME rpz-passthru.",
        f"32.67.115.78.5.rpz-ip.{SUFFIX} 900 IN CNAME rpz-passthru.",
        f"24.2.0.192.rpz-ip.{SUFFIX} 900 IN CNAME rpz-passthru.",
        f"32.1.0.0.127.rpz-ip.{SUFFIX} 900 IN CNAME .",
        f"48.zz.101.db8.2001.rpz-ip.{SUFFIX} 900 IN CNAME rpz-passthru.",
        f"32.8.b.d.0.1.0.0.2.rpz-ip.{SUFFIX} 900 IN CNAME rpz-passthru.",
        f"ns.evil.example.com.rpz-nsdname.{SUFFIX} 900 IN CNAME rpz-passthru.",
        f"32.9.9.9.8.rpz-nsip.{SUFFIX} 900 IN CNAME rpz-drop.",
        f"blocked.example.org.{SUFFIX} 60 IN TXT \"vuhuvahu\"",
        f"local.example.org.{SUFFIX} 60 IN A 10.0.0.1",
        f"dropme.example.org.{SUFFIX} 900 IN CNAME rpz-drop.",
        f"tcp.example.org.{SUFFIX} 900 IN CNAME rpz-tcp-only.",
        f"garden.example.org.{SUFFIX} 900 IN CNAME garden.threatstop.com.",
        f"garbage-label.rpz-ip.{SUFFIX} 900 IN CNAME rpz-passthru.",
        "threatstop-charte02. 0 ANY TSIG hmac-md5.sig-alg.reg.int. 1788838573 300 16 xxxxx 0 NOERROR 0",
    ]
)

EXPECTED_IPS = [
    "5.78.115.67/32",
    "192.0.2.0/24",
    "127.0.0.1/32",
    "2001:db8:101::/48",
    "2001:db8::/32",
    "8.9.9.9/32",
]
EXPECTED_DOMAINS = [
    "*.cloudflare-dns.com",
    "evil.example.com",
    "*.phish.example.net",
    "ns.evil.example.com",
    "blocked.example.org",
    "local.example.org",
    "dropme.example.org",
    "tcp.example.org",
    "garden.example.org",
]


def _spec(entry_id: str = ARM_ID) -> ArmSpec:
    return ArmSpec(
        id=entry_id,
        protocols=("cli",),
        curated=True,
        notes="test",
        tier="research",
        held_reason=None,
    )


def _ext() -> Extension:
    entry = CatalogEntry(
        id=ARM_ID,
        kind="arm",
        protocols=("cli",),
        curated=True,
        notes="test arm row",
        tier="research",
        held_reason=None,
    )
    arm = RpzDecoderArm()
    return Extension(catalog=Catalog([entry]), arms={ARM_ID: arm})


def _write_dump(tmp_path: Path) -> Path:
    dump = tmp_path / "zone-axfr.txt"
    dump.write_text(FIXTURE_AXFR, encoding="utf-8")
    return dump


# ----------------------------------------------------------------------
# decoder unit tests

def test_decode_counts_and_extracts_raw_lists() -> None:
    report = decode_axfr(FIXTURE_AXFR, ZONE)
    assert report["serial"] == 1788838349
    assert report["counts"]["records"] == 17
    assert report["counts"]["qname"] == 8
    assert report["counts"]["ip"] == 5
    assert report["counts"]["nsip"] == 1
    assert report["counts"]["nsdname"] == 1
    assert report["counts"]["control"] == 1
    assert report["counts"]["unparsed"] == 1
    assert report["counts"]["skipped"] == 2
    assert report["ips"] == EXPECTED_IPS
    assert report["domains"] == EXPECTED_DOMAINS
    assert report["actions"]["passthru"] == 7
    assert report["actions"]["nxdomain"] == 4
    assert report["actions"]["drop"] == 2
    assert report["actions"]["redirect:garden.threatstop.com"] == 1
    assert report["actions"]["txt"] == 1
    assert report["actions"]["local-data"] == 1
    assert report["actions"]["tcp-only"] == 1


def test_decode_ndjson_pairs_indicator_with_action() -> None:
    report = decode_axfr(FIXTURE_AXFR, ZONE)
    parsed = [json.loads(line) for line in report["ndjson"]]
    by_value = {row["value"]: row for row in parsed}
    assert by_value["5.78.115.67/32"] == {
        "type": "ip",
        "value": "5.78.115.67/32",
        "action": "passthru",
    }
    assert by_value["127.0.0.1/32"]["action"] == "nxdomain"
    assert by_value["garden.example.org"]["action"].startswith("redirect:")
    assert by_value["ns.evil.example.com"]["type"] == "nsdname"


def test_decode_include_control_keeps_vendor_names() -> None:
    report = decode_axfr(FIXTURE_AXFR, ZONE, include_control=True)
    assert "bad.threatstop.com" in report["domains"]
    assert report["counts"]["control"] == 1


def test_decode_truncated_ipv4_prefix_padding() -> None:
    text = (
        f"{ZONE}. 60 IN SOA ns1.threatstop.com. hostmaster.threatstop.com. 1 900 900 86400 60\n"
        f"24.10.0.192.rpz-ip.{SUFFIX} 0 IN CNAME rpz-passthru.\n"
        f"16.0.254.172.rpz-ip.{SUFFIX} 0 IN CNAME rpz-passthru.\n"
    )
    report = decode_axfr(text, ZONE)
    assert report["ips"] == ["192.0.10.0/24", "172.254.0.0/16"]


def test_decode_rejects_wrong_zone_mention() -> None:
    with pytest.raises(ZoneDecodeError):
        decode_axfr(FIXTURE_AXFR, "Other-Policy.rpz.threatstop.local")


def test_decode_bad_ipv4_labels_land_in_unparsed() -> None:
    text = (
        f"{ZONE}. 60 IN SOA ns1.threatstop.com. hostmaster.threatstop.com. 1 900 900 86400 60\n"
        f"32.300.1.2.3.rpz-ip.{SUFFIX} 0 IN CNAME rpz-passthru.\n"
        f"40.1.2.3.4.5.rpz-ip.{SUFFIX} 0 IN CNAME rpz-passthru.\n"
    )
    report = decode_axfr(text, ZONE)
    assert report["counts"]["unparsed"] == 2
    assert report["ips"] == []


# ----------------------------------------------------------------------
# policy refusals

def test_zone_master_port_refusals() -> None:
    assert zone_refusal("Basic-DNSFW.rpz.threatstop.local") is None
    assert zone_refusal("example.com") is not None
    assert zone_refusal("") is not None
    assert master_refusal("192.124.129.51") is None
    assert master_refusal("ns1.threatstop.com") is not None
    assert master_refusal("999.1.1.1") is not None
    assert port_refusal(53) is None
    assert port_refusal(5353) is None
    assert port_refusal(443) is not None


def test_args_refusal_rejects_unknown_and_missing() -> None:
    assert args_refusal("decode", {"dump": "x"}) is None
    assert args_refusal("decode", {"dump": "x", "bogus": 1}) is not None
    assert args_refusal("decode", {}) is not None
    assert args_refusal("fetch", {"outdir": "o"}) is not None  # keyfile missing
    assert args_refusal("explode", {}) is not None


def test_keyfile_refusal_requires_two_lines_and_0600(
    tmp_path: Path,
) -> None:
    good = tmp_path / "key"
    good.write_text(f"threatstop-key\n{SECRET}\n", encoding="utf-8")
    if os.name == "posix":
        good.chmod(0o600)
        assert keyfile_refusal(good) is None
        permissive = tmp_path / "loose"
        permissive.write_text(f"threatstop-key\n{SECRET}\n", encoding="utf-8")
        permissive.chmod(0o644)
        assert keyfile_refusal(permissive) is not None
    else:
        assert keyfile_refusal(good) is None
    missing = tmp_path / "absent"
    assert keyfile_refusal(missing) is not None
    thin = tmp_path / "thin"
    thin.write_text("only-a-name\n", encoding="utf-8")
    assert keyfile_refusal(thin) is not None


# ----------------------------------------------------------------------
# arm-level behaviour

def test_installed_is_id_match_and_wrong_id_raises() -> None:
    arm = RpzDecoderArm()
    assert arm.installed(_spec()) is True
    assert arm.installed(_spec("other-arm")) is False
    with pytest.raises(NotInstalledError):
        arm.invoke(_spec("other-arm"), "decode", {"dump": "x"})


def test_arm_decode_returns_bounded_report_and_writes_lists(
    tmp_path: Path,
) -> None:
    arm = RpzDecoderArm()
    outdir = tmp_path / "lists"
    result = arm.invoke(
        _spec(),
        "decode",
        {"dump": str(_write_dump(tmp_path)), "outdir": str(outdir)},
    )
    assert result.ok is True
    output = result.output
    assert output["zone"] == ZONE
    assert output["serial"] == 1788838349
    assert output["counts"]["ip"] == 5
    assert len(output["samples"]["ips"]) <= 25
    assert "bad.threatstop.com" not in output["samples"]["domains"]
    assert set(output["files"]) == {"ips", "domains", "ndjson"}
    assert Path(output["files"]["ips"]).read_text(encoding="utf-8").splitlines() == EXPECTED_IPS
    assert Path(output["files"]["domains"]).read_text(encoding="utf-8").splitlines() == EXPECTED_DOMAINS
    first = json.loads(
        Path(output["files"]["ndjson"]).read_text(encoding="utf-8").splitlines()[0]
    )
    assert set(first) == {"type", "value", "action"}


def test_arm_decode_zone_mismatch_is_evaluated_failure(tmp_path: Path) -> None:
    arm = RpzDecoderArm()
    result = arm.invoke(
        _spec(),
        "decode",
        {"dump": str(_write_dump(tmp_path)), "zone": "Other.rpz.threatstop.local"},
    )
    assert result.ok is False
    assert "args.zone said" in (result.error or "")


def test_arm_decode_corrupt_utf8_is_fail_closed(tmp_path: Path) -> None:
    dump = tmp_path / "zone-axfr.txt"
    dump.write_bytes(FIXTURE_AXFR.encode("utf-8") + b"\xff\xfe binary\n")
    arm = RpzDecoderArm()
    result = arm.invoke(_spec(), "decode", {"dump": str(dump)})
    assert result.ok is False
    assert "not valid UTF-8" in (result.error or "")


def test_arm_decode_empty_and_oversize_dumps_fail(tmp_path: Path) -> None:
    arm = RpzDecoderArm()
    empty = tmp_path / "empty.txt"
    empty.write_text("   \n", encoding="utf-8")
    result = arm.invoke(_spec(), "decode", {"dump": str(empty)})
    assert result.ok is False
    assert "empty" in (result.error or "")

    from extension.arms.rpzdecoder.policy import MAX_DUMP_BYTES

    big = tmp_path / "big.txt"
    with big.open("wb") as handle:
        handle.truncate(MAX_DUMP_BYTES + 1)
    result = arm.invoke(_spec(), "decode", {"dump": str(big)})
    assert result.ok is False
    assert "MAX_DUMP_BYTES" in (result.error or "")


def test_arm_decode_no_soa_zone_fails(tmp_path: Path) -> None:
    dump = tmp_path / "nozone.txt"
    dump.write_text("example.com. 60 IN SOA a.b. c.d. 1 2 3 4 5\n", encoding="utf-8")
    arm = RpzDecoderArm()
    result = arm.invoke(_spec(), "decode", {"dump": str(dump)})
    assert result.ok is False
    assert "no SOA" in (result.error or "")


def test_arm_list_tools_and_unknown_action(tmp_path: Path) -> None:
    arm = RpzDecoderArm()
    listed = arm.invoke(_spec(), "list_tools", {})
    assert listed.ok is True
    names = {tool["name"] for tool in listed.output["tools"]}
    assert names == {"decode", "fetch", "status"}
    refused = arm.invoke(_spec(), "explode", {})
    assert refused.ok is False
    assert "not on the allowlist" in (refused.error or "")


# ----------------------------------------------------------------------
# dispatch tier: unarmed refusals + fake-dig plumbing

def _fake_dig(tmp_path: Path, mode: str) -> Path:
    """A dig stand-in: success mode prints the fixture; fail mode echoes argv."""
    script = tmp_path / "fake-dig.py"
    script.write_text(
        "import os, sys\n"
        "if os.environ.get('FAKE_DIG_MODE') == 'fail':\n"
        "    sys.stderr.write('dig args: ' + ' '.join(sys.argv[1:]) + '\\n')\n"
        "    sys.exit(9)\n"
        "sys.stdout.write(open(os.environ['FAKE_DIG_FIXTURE'], encoding='utf-8').read())\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        wrapper = tmp_path / "dig.bat"
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8")
        return wrapper
    wrapper = tmp_path / "dig"
    wrapper.write_text(
        f"#!{sys.executable}\nimport os, sys\n"
        "if os.environ.get('FAKE_DIG_MODE') == 'fail':\n"
        "    sys.stderr.write('dig args: ' + ' '.join(sys.argv[1:]) + '\\n')\n"
        "    sys.exit(9)\n"
        f"sys.stdout.write(open(r'{tmp_path / 'fixture.txt'}', encoding='utf-8').read())\n",
        encoding="utf-8",
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    (tmp_path / "fixture.txt").write_text(FIXTURE_AXFR, encoding="utf-8")
    return wrapper


def _keyfile(tmp_path: Path) -> Path:
    key = tmp_path / "tsig"
    key.write_text(f"threatstop-key\n{SECRET}\n", encoding="utf-8")
    if os.name == "posix":
        key.chmod(0o600)
    return key


def _arm_args(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setenv("RPZDECODER_DIG_BIN", str(_fake_dig(tmp_path, "ok")))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, MASTER)
    return {
        "zone": ZONE,
        "master": MASTER,
        "keyfile": str(_keyfile(tmp_path)),
        "outdir": str(tmp_path / "out"),
    }


def test_fetch_unarmed_is_evaluated_failure(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv(ENV_DISPATCH_SCOPE, raising=False)
    monkeypatch.setenv("RPZDECODER_DIG_BIN", str(sys.executable))
    arm = RpzDecoderArm()
    result = arm.invoke(
        _spec(),
        "fetch",
        {
            "zone": ZONE,
            "master": MASTER,
            "keyfile": str(_keyfile(tmp_path)),
            "outdir": str(tmp_path / "out"),
        },
    )
    assert result.ok is False
    assert "RPZDECODER_DISPATCH_SCOPE" in (result.error or "")


def test_fetch_without_dig_is_evaluated_failure(monkeypatch) -> None:
    monkeypatch.delenv("RPZDECODER_DIG_BIN", raising=False)
    monkeypatch.delenv(ENV_DISPATCH_SCOPE, raising=False)
    arm = RpzDecoderArm()
    result = arm.invoke(
        _spec(),
        "status",
        {"zone": ZONE, "master": MASTER},
    )
    assert result.ok is False
    assert "dig binary not found" in (result.error or "")


@pytest.mark.skipif(os.name == "nt", reason="fake dig wrapper is POSIX-only")
def test_fetch_armed_transfers_and_writes_lists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    args = _arm_args(tmp_path, monkeypatch)
    arm = RpzDecoderArm(timeout=30)
    result = arm.invoke(_spec(), "fetch", args)
    assert result.ok is True, result.error
    output = result.output
    assert output["serial"] == 1788838349
    assert output["counts"]["ip"] == 5
    assert output["dispatch"]["target"].endswith(ZONE)
    lists = output["files"]
    assert Path(lists["ips"]).read_text(encoding="utf-8").splitlines() == EXPECTED_IPS
    assert (tmp_path / "out" / "zone-axfr.txt").is_file()


@pytest.mark.skipif(os.name == "nt", reason="fake dig wrapper is POSIX-only")
def test_status_armed_reports_serial(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RPZDECODER_DIG_BIN", str(_fake_dig(tmp_path, "ok")))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, MASTER)
    arm = RpzDecoderArm(timeout=30)
    result = arm.invoke(_spec(), "status", {"zone": ZONE, "master": MASTER})
    assert result.ok is True, result.error
    assert result.output["serial"] == 1788838349
    assert result.output["refresh"] == 900


@pytest.mark.skipif(os.name == "nt", reason="fake dig wrapper is POSIX-only")
def test_fetch_failure_redacts_tsig_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FAKE_DIG_MODE", "fail")
    args = _arm_args(tmp_path, monkeypatch)
    arm = RpzDecoderArm(timeout=30)
    result = arm.invoke(_spec(), "fetch", args)
    assert result.ok is False
    assert "[REDACTED]" in (result.error or "")
    assert SECRET not in (result.error or "")


def test_decoder_ext_registered_in_extension() -> None:
    ext = _ext()
    assert ext.arms[ARM_ID].installed(_spec()) is True


def test_decode_zzless_hextet_and_multichar_nibble_are_unparsed() -> None:
    text = (
        f"{ZONE}. 60 IN SOA ns1.threatstop.com. hostmaster.threatstop.com. 1 900 900 86400 60\n"
        f"32.2001.db8.0.0.0.0.0.0.rpz-ip.{SUFFIX} 0 IN CNAME rpz-passthru.\n"
        f"32.ab.cd.ef.12.rpz-ip.{SUFFIX} 0 IN CNAME rpz-passthru.\n"
    )
    report = decode_axfr(text, ZONE)
    assert report["counts"]["unparsed"] == 2
    assert report["ips"] == []


def test_arm_decode_outdir_is_a_file_is_evaluated_failure(tmp_path: Path) -> None:
    arm = RpzDecoderArm()
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    result = arm.invoke(
        _spec(),
        "decode",
        {"dump": str(_write_dump(tmp_path)), "outdir": str(blocker)},
    )
    assert result.ok is False
    assert "write indicator lists" in (result.error or "")


def test_arm_fetch_non_utf8_keyfile_is_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = tmp_path / "tsig"
    key.write_bytes(b"threatstop-key\n\xff\xfe-not-utf8\n")
    if os.name == "posix":
        key.chmod(0o600)
    monkeypatch.setenv("RPZDECODER_DIG_BIN", str(_fake_dig(tmp_path, "ok")))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, MASTER)
    arm = RpzDecoderArm(timeout=30)
    result = arm.invoke(
        _spec(),
        "fetch",
        {
            "zone": ZONE,
            "master": MASTER,
            "keyfile": str(key),
            "outdir": str(tmp_path / "out"),
        },
    )
    assert result.ok is False
    assert "not valid UTF-8" in (result.error or "")


@pytest.mark.skipif(os.name == "nt", reason="fake dig wrapper is POSIX-only")
def test_fetch_non_utf8_dump_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RPZDECODER_DIG_BIN", str(_fake_dig(tmp_path, "ok")))
    bad = tmp_path / "fixture.txt"
    bad.write_bytes(b"\xff\xfe not a zone\n")
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, MASTER)
    arm = RpzDecoderArm(timeout=30)
    result = arm.invoke(
        _spec(),
        "fetch",
        {
            "zone": ZONE,
            "master": MASTER,
            "keyfile": str(_keyfile(tmp_path)),
            "outdir": str(tmp_path / "out"),
        },
    )
    assert result.ok is False
    assert "not valid UTF-8" in (result.error or "")


@pytest.mark.skipif(os.name == "nt", reason="fake dig wrapper is POSIX-only")
def test_status_without_soa_is_evaluated_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    empty = tmp_path / "fixture.txt"
    empty.write_text("", encoding="utf-8")
    script = tmp_path / "fake-dig.py"
    script.write_text(
        "import sys\n"
        f"sys.stdout.write(open(r'{empty}', encoding='utf-8').read())\n",
        encoding="utf-8",
    )
    wrapper = tmp_path / "dig"
    wrapper.write_text(
        f"#!{sys.executable}\nexec(open(r'{script}').read())\n", encoding="utf-8"
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("RPZDECODER_DIG_BIN", str(wrapper))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, MASTER)
    arm = RpzDecoderArm(timeout=30)
    result = arm.invoke(_spec(), "status", {"zone": ZONE, "master": MASTER})
    assert result.ok is False
    assert "no SOA in status response" in (result.error or "")
