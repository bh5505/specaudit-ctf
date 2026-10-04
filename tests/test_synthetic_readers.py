"""Packaged fictional reader scenarios execute through the public admission path."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from exercise.synthetic_readers import recipes
from extension.contract import Extension
from extension.dispatch import dispatch_invoke
from extension.invoke_profiles import invoke_profile


@pytest.fixture(scope="module")
def reports(tmp_path_factory):
    extension = Extension()
    result = {}
    for index, (scenario, (arm_id, action, args)) in enumerate(recipes().items()):
        directory = tmp_path_factory.mktemp(f"reader-{index}")
        outcome = dispatch_invoke(
            extension, arm_id=arm_id, action=action, args=args,
            attempt_id="attempt-" + f"{index:064x}", artifact_dir=str(directory),
        )
        assert outcome.exit_code == 0, (scenario, outcome.envelope)
        assert outcome.envelope is not None
        assert outcome.envelope["status"] == "complete"
        assert outcome.envelope["capability_id"] == f"{arm_id}.{action}"
        assert invoke_profile(arm_id, action) is not None
        # Read the actual produced artifact, not a direct handler return or
        # list_tools metadata. The hash is the envelope's custody receipt.
        artifacts = [artifact for artifact in outcome.envelope["artifacts"]
                     if artifact["kind"] == "policy-report"]
        assert len(artifacts) == 1
        files = [path for path in directory.iterdir() if path.is_file()]
        assert len(files) == 1
        data = files[0].read_bytes()
        assert artifacts[0]["digest"] == "sha256:" + hashlib.sha256(data).hexdigest()
        result[scenario] = json.loads(data)
    return result


def test_all_fourteen_admitted_reader_families_actually_execute(reports) -> None:
    assert len(reports) == 14
    assert set(reports) == set(recipes())


def test_synthetic_results_preserve_negative_and_unknown_context(reports) -> None:
    assert reports["reader-vulnify"]["count_matched"] == 2
    assert any(row["status"] == "unmatched" for row in reports["reader-vulnify"]["results"])
    assert reports["reader-pentestkit"]["by_status"]["fail"] >= 1
    assert reports["reader-ad-pathfinder"]["not_assessed_paths"] == 1
    assert reports["reader-gpohound"]["policy"]["status"] == "disabled"
    assert reports["reader-numasec"]["status"] == "resolved"


def test_instructor_answers_and_telemetry_values_are_not_reader_output(reports) -> None:
    scenario = reports["reader-collinear"]["scenario"]
    assert not {"expected_findings", "trace_keys", "expected_evidence"} & set(scenario)
    telemetry = reports["reader-rubeus"]["telemetry"]
    assert telemetry["indicators"] == [{"type": "ticket_kind"}]
    assert "[REDACTED]" not in json.dumps(telemetry)


def test_packaged_fixtures_are_local_and_profiles_remain_conservative() -> None:
    for scenario, (arm_id, action, args) in recipes().items():
        profile = invoke_profile(arm_id, action)
        assert profile is not None, scenario
        assert profile.synthetic_only is False  # general caller-file contract
        assert profile.side_effects == ("local-read",)
        assert all(Path(value).is_absolute() and Path(value).exists()
                   for key, value in args.items()
                   if key in {"index", "fixture", "bundle_path", "corpus", "catalog",
                              "playbook_dir", "ledger", "scenarios_file", "export",
                              "evidence", "method_file", "telemetry_file", "cases_file"})
