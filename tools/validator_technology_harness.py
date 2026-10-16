#!/usr/bin/env python3
"""Exercise the Rust technology probe path with synthetic provider replies.

The case files supply transport bytes and expected *result fields*. This
program never interprets cloud policy or launches a cloud CLI. The validator's
fixture entrypoint uses its production parser/evaluator with provider replies
supplied in memory, without starting a provider process.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CASES_ROOT = ROOT / "tests" / "fixtures" / "technology_validator"
MAX_CASE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 20
PREFLIGHT_REFUSAL_REASONS = {
    "not_authorized",
    "claim_reason_mismatch",
    "account_scope_incomplete",
    "account_scope_mismatch",
    "region_scope_mismatch",
    "invalid_gcp_fixture_scope",
    "candidate_scope_mismatch",
}
PROVIDER_IDENTITY_MISMATCH_REASONS = {
    "group_identity_mismatch",
    "project_identity_mismatch",
    "bucket_identity_mismatch",
    "bucket_policy_identity_mismatch",
    "subscription_identity_mismatch",
    "nsg_identity_mismatch",
}


class HarnessError(Exception):
    """A case, validator invocation, or expected result was invalid."""


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_CASE_BYTES:
        raise HarnessError(f"missing, linked, or oversized fixture: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HarnessError(f"invalid JSON fixture: {path.name}") from exc
    if not isinstance(value, dict):
        raise HarnessError(f"fixture must be an object: {path.name}")
    return value


def _fixture_path(name: str) -> Path:
    if not name or name in (".", "..") or Path(name).name != name:
        raise HarnessError(f"invalid fixture name: {name!r}")
    path = CASES_ROOT / name
    if path.is_symlink() or not path.is_file():
        raise HarnessError(f"fixture is absent or linked: {name}")
    return path


def _contains(actual: Any, expected: Any, field: str) -> None:
    """Assert a small result projection without reimplementing probe logic."""
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            raise HarnessError(f"{field}: expected object, got {type(actual).__name__}")
        for key, value in expected.items():
            if key not in actual:
                raise HarnessError(f"{field}: missing {key}")
            _contains(actual[key], value, f"{field}.{key}")
    elif isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            raise HarnessError(f"{field}: expected list of length {len(expected)}")
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected)):
            _contains(actual_item, expected_item, f"{field}[{index}]")
    elif actual != expected:
        raise HarnessError(f"{field}: expected {expected!r}, got {actual!r}")


def run_case(validator_bin: Path, case_file: str) -> None:
    case = _read_json(_fixture_path(case_file))
    if case.get("synthetic") is not True:
        raise HarnessError(f"{case_file}: synthetic must be true")
    request = case.get("request")
    expected = case.get("expect")
    response_file = case.get("response_file")
    if not isinstance(request, dict) or not isinstance(expected, dict):
        raise HarnessError(f"{case_file}: request and expect must be objects")
    reason = expected.get("reason_code")
    if reason in PREFLIGHT_REFUSAL_REASONS and case.get("expect_no_plan") is not True:
        raise HarnessError(f"{case_file}: preflight refusal must assert no command plan")
    if reason in PROVIDER_IDENTITY_MISMATCH_REASONS and case.get("expect_plan") is not True:
        raise HarnessError(f"{case_file}: provider identity mismatch must assert a command plan")
    if case.get("expect_no_plan") is True and case.get("expect_plan") is True:
        raise HarnessError(f"{case_file}: conflicting command-plan expectations")
    if request.get("schema") != "specaudit.validator.technology-fixture.v1":
        raise HarnessError(f"{case_file}: unsupported fixture request schema")
    if request.get("provider") not in ("aws", "gcp", "azure"):
        raise HarnessError(f"{case_file}: unknown provider")
    if "fake_provider_response_path" in request or "fake_provider_response" in request:
        raise HarnessError(f"{case_file}: provider response must use response_file")
    if not isinstance(response_file, str) or "transcript_file" in case:
        raise HarnessError(f"{case_file}: one response_file is required")
    provider_response = _read_json(_fixture_path(response_file))
    authorization = request.get("authorization")
    if not isinstance(authorization, dict) or any(
        key in authorization for key in ("executable", "credential_root")
    ):
        raise HarnessError(f"{case_file}: provider executable and credential root are forbidden")
    if request["provider"] == "azure":
        tenant = authorization.get("tenant_id")
        subscription = authorization.get("subscription_id")
        if isinstance(tenant, str) and tenant and isinstance(subscription, str) and subscription:
            if tenant.lower() == subscription.lower():
                raise HarnessError(f"{case_file}: Azure tenant and subscription must differ")
        if case.get("expect_no_plan") is not True:
            detail = request.get("details")
            detail_account = detail.get("account_id") if isinstance(detail, dict) else None
            inventory_account = request.get("account_id")
            if not isinstance(tenant, str) or not tenant or not all(
                isinstance(account, str) and account.lower() == tenant.lower()
                for account in (inventory_account, detail_account)
            ):
                raise HarnessError(
                    f"{case_file}: admitted Azure candidate/detail account IDs must be the tenant"
                )

    with tempfile.TemporaryDirectory(prefix="specaudit-ctf-tech-") as tmp:
        scratch = Path(tmp)
        (scratch / "empty-path").mkdir()
        (scratch / "home").mkdir()
        (scratch / "azure").mkdir()
        # Raw provider replies, never a Python-computed cloud finding.
        request["fake_provider_response"] = provider_response
        input_path = scratch / "case.json"
        output_path = scratch / "result.json"
        input_path.write_text(json.dumps(request, sort_keys=True), encoding="utf-8")
        # No provider executable or cloud credential is supplied. The Rust
        # fixture branch consumes the provider replies in memory.
        env = {
            "PATH": str(scratch / "empty-path"),
            "HOME": str(scratch / "home"),
            "AZURE_CONFIG_DIR": str(scratch / "azure"),
            "AWS_EC2_METADATA_DISABLED": "true",
            "NO_PROXY": "*",
            "no_proxy": "*",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
        }
        try:
            completed = subprocess.run(
                [str(validator_bin), "--evaluate-technology-fixture", str(input_path),
                 "--output", str(output_path)],
                cwd=scratch,
                env=env,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise HarnessError(f"{case_file}: validator timed out") from exc
        except OSError as exc:
            raise HarnessError(f"{case_file}: validator could not start: {exc.strerror}") from exc
        if completed.returncode != 0:
            raise HarnessError(
                f"{case_file}: validator exited {completed.returncode}: "
                f"{completed.stderr[-500:].strip()}"
            )
        result = _read_json(output_path)
        if result.get("schema") != "specaudit.validator.result.v1":
            raise HarnessError(f"{case_file}: unexpected validator result schema")
        if request["provider"] in ("gcp", "azure") and (
            case.get("expect_no_plan") is not True
        ) and (
            result.get("probe_schema") != "specaudit.validator.technology-probe.v1"
        ):
            raise HarnessError(f"{case_file}: unexpected cloud probe schema")
        _contains(result, expected, case_file)
        # Optional exact negative control: no live command may be planned when
        # authorization or subject identity fails.
        if case.get("expect_no_plan") is True and result.get("planned_argv") != []:
            raise HarnessError(f"{case_file}: refused case still planned a provider command")
        if case.get("expect_plan") is True and not result.get("planned_argv"):
            raise HarnessError(f"{case_file}: expected provider reads were not planned")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validator-bin", required=True, type=Path,
                        help="absolute path to the built validator binary")
    parser.add_argument("--case", action="append", default=[],
                        help="run only a named case file; default is manifest order")
    args = parser.parse_args(argv)
    validator_bin = args.validator_bin.resolve()
    if not args.validator_bin.is_absolute() or not validator_bin.is_file():
        parser.error("--validator-bin must name an existing absolute file")
    manifest = _read_json(CASES_ROOT / "manifest.json")
    case_files = args.case or manifest.get("cases")
    if not isinstance(case_files, list) or not case_files or any(
        not isinstance(name, str) for name in case_files
    ):
        raise HarnessError("case manifest must contain a non-empty string list")
    if len(case_files) != len(set(case_files)):
        raise HarnessError("case list contains a duplicate")
    if not args.case:
        recorded = set(case_files)
        present = {path.name for path in CASES_ROOT.glob("*.case.json")}
        if recorded != present:
            raise HarnessError("case manifest does not enumerate every case file")
    failed = 0
    for case_file in case_files:
        try:
            run_case(validator_bin, case_file)
        except HarnessError as exc:
            failed += 1
            print(f"FAIL {case_file}: {exc}", file=sys.stderr)
        else:
            print(f"PASS {case_file}")
    print(f"{len(case_files) - failed}/{len(case_files)} synthetic technology cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
