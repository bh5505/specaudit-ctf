"""Instructor-plane separation at the operator-profile layer.

Enumerates ``challenges/*/instructor/*`` and
``exercise_operator/contracts/*.json``, proves direct reads from a
simulated learner root are typed-refused by the acquisition gate, that a
reader-mediated (harness) case with an instructor path is blocked before
dispatch, that the instructor canary strings never appear in an
``exercise_operator`` prepare export, and that a deliberate leak fixture
fires the detector.

NOTE on prepare coverage, stated honestly: ``exercise_operator.prepare``
ships only the fixture-backed challenges in its FIXTURES map (the
telecom-aws-* set plus lab-knowledge-01); the challenges with instructor
keys (lab-review-01-threat-model, lab-k8s-01-rbac-path, and the
lab-agent-01 / lab-detect-01 grading keys) are NOT in the shippable
inventory -- ``prepare`` refuses the fixture-backed ones -- so the
canary-absence check runs against every shippable export plus the
packaged contracts and the shipped range fixture inputs.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from containment.harness import run_case
from containment.profile import OperatorProfile
from exercise_operator.__main__ import OperatorError, prepare

from reader_evidence import AcquisitionError, acquire

REPO_ROOT = Path(__file__).resolve().parents[1]
CANARY_MARK = "INSTRUCTOR-CANARY"
LEARNER_SUFFIXES = frozenset({".json", ".md", ".yaml", ".yml", ".txt"})
GATE_AT = datetime(2026, 10, 13, 12, 0, 0)


def instructor_files() -> list[Path]:
    """Every file under every challenges/*/instructor/ directory."""
    return sorted(
        path for path in (REPO_ROOT / "challenges").glob("*/instructor/*")
        if path.is_file()
    )


def contract_files() -> list[Path]:
    return sorted((REPO_ROOT / "exercise_operator" / "contracts").glob("*.json"))


def scan_for_canary(root: Path) -> list[str]:
    """The leak detector: relative paths whose bytes contain the canary
    mark. Deliberately naive byte-substring scan -- the property is about
    content, not format."""
    hits = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if CANARY_MARK.encode("utf-8") in path.read_bytes():
            hits.append(path.relative_to(root).as_posix())
    return hits


@pytest.fixture(scope="module")
def learner_profile(tmp_path_factory) -> OperatorProfile:
    """The simulated learner/operator sandbox: an approved root that is
    NOT the repository -- instructor material lies outside by construction."""
    root = tmp_path_factory.mktemp("instructor-plane")
    approved = root / "approved"
    scratch = root / "scratch"
    approved.mkdir()
    scratch.mkdir()
    return OperatorProfile(
        approved_root=str(approved), scratch_root=str(scratch))


def test_instructor_plane_enumerated() -> None:
    """The challenges with instructor keys exist, at minimum the four the
    campaign names (review-01, k8s-01, agent-01, detect-01), and their key
    documents carry canaries."""
    files = instructor_files()
    assert files, "no instructor material found under challenges/"
    by_challenge = {path.parts[-3]: path for path in files}
    for challenge in ("lab-review-01-threat-model", "lab-k8s-01-rbac-path",
                      "lab-agent-01-tool-boundary",
                      "lab-detect-01-technique-chain"):
        assert challenge in by_challenge, challenge
    canaried = [path for path in files
                if CANARY_MARK in path.read_text(encoding="utf-8")]
    assert len(canaried) >= 4  # review-01, k8s-01, agent-01, detect-01
    for path in canaried:
        assert path.parent.parent.name in (
            "lab-review-01-threat-model", "lab-k8s-01-rbac-path",
            "lab-agent-01-tool-boundary", "lab-detect-01-technique-chain")


def test_direct_read_of_instructor_material_is_typed_refused(
    learner_profile: OperatorProfile,
) -> None:
    """Direct read from the simulated learner cwd: OUT of the approved
    root -> typed acquisition refusal (root-escape)."""
    for path in instructor_files() + contract_files():
        with pytest.raises(AcquisitionError) as excinfo:
            acquire(
                path,
                approved_root=Path(learner_profile.approved_root),
                allowed_suffixes=LEARNER_SUFFIXES,
                max_bytes=1_048_576,
                acquired_at=GATE_AT,
            )
        assert excinfo.value.reason == "root-escape", path


def test_new_instructor_keys_are_canaried_and_refused(
    learner_profile: OperatorProfile,
) -> None:
    """The #92 grading key documents (agent-01 answers.json, detect-01
    expected.json) exist under their challenges' instructor directories,
    carry their canary markers, are typed-refused both directly and by
    traversal from the simulated learner root, and the detect-01 LEARNER
    assessment packet carries no canary (safe to export)."""
    agent_key = (REPO_ROOT / "challenges" / "lab-agent-01-tool-boundary" /
                 "instructor" / "answers.json")
    detect_key = (REPO_ROOT / "challenges" / "lab-detect-01-technique-chain" /
                  "instructor" / "expected.json")
    assert "INSTRUCTOR-CANARY-AGENT-01-ANSWERS" in \
        agent_key.read_text(encoding="utf-8")
    assert "INSTRUCTOR-CANARY-DETECT-01-EXPECTED" in \
        detect_key.read_text(encoding="utf-8")
    approved = Path(learner_profile.approved_root)
    for key in (agent_key, detect_key):
        with pytest.raises(AcquisitionError) as direct:
            acquire(key, approved_root=approved,
                    allowed_suffixes=LEARNER_SUFFIXES,
                    max_bytes=1_048_576, acquired_at=GATE_AT)
        assert direct.value.reason == "root-escape", key
        # A ``..`` locator climbing out of the learner root is refused
        # lexically before any open.
        traversal = approved / ".." / key.relative_to(REPO_ROOT)
        with pytest.raises(AcquisitionError) as climbed:
            acquire(traversal, approved_root=approved,
                    allowed_suffixes=LEARNER_SUFFIXES,
                    max_bytes=1_048_576, acquired_at=GATE_AT)
        assert climbed.value.reason == "traversal-refused", key
    # The learner-facing assessment packets are canary-free: exporting them
    # to a learner context cannot leak the instructor marker.
    packets = sorted((REPO_ROOT / "challenges" / "lab-detect-01-technique-chain" /
                      "instructor" / "assessment").glob("*.json"))
    assert len(packets) == 6
    for packet_path in packets:
        assert CANARY_MARK.encode("utf-8") not in packet_path.read_bytes(), packet_path


def test_reader_mediated_instructor_case_blocked_before_dispatch(
    learner_profile: OperatorProfile,
) -> None:
    """Reader-mediated (harness case with an instructor path): blocked
    before dispatch with the typed reason; no child is spawned."""
    key = REPO_ROOT / "challenges" / "lab-review-01-threat-model" / \
        "instructor" / "KEY.md"
    case = run_case(
        learner_profile, arm_id="vulnify", action="list_vulns",
        payload={"feed": str(key), "limit": 5},
        hostile="absolute-out-of-root", variant="hostile-instructor",
    )
    assert case.outcome == "blocked"
    assert case.reason == "root-escape"


def test_prepare_export_carries_no_instructor_canary(
    tmp_path: Path,
) -> None:
    """Canary strings are absent from a real exercise_operator prepare
    export (a shippable fixture-backed challenge) and from the packaged
    contracts and shipped range fixture inputs."""
    destination = tmp_path / "packet"
    result = prepare("telecom-aws-01-reachability", destination)
    assert result["status"] == "complete"
    packet = Path(result["packet"])
    assert scan_for_canary(packet) == []
    # Negative control at the source surfaces: packaged contracts and
    # shipped range inputs must be canary-free too.
    assert all(CANARY_MARK.encode("utf-8") not in path.read_bytes()
               for path in contract_files())
    range_root = REPO_ROOT / "extension" / "range"
    shipped = [path for path in range_root.rglob("*")
               if path.is_file() and path.suffix != ".pyc"]
    assert all(CANARY_MARK.encode("utf-8") not in path.read_bytes()
               for path in shipped)


def test_instructor_key_challenges_are_not_preparable(tmp_path: Path) -> None:
    """The challenges whose instructor keys exist are outside the
    shippable fixture-backed inventory: prepare refuses them."""
    for challenge in ("lab-review-01-threat-model", "lab-k8s-01-rbac-path"):
        with pytest.raises(OperatorError):
            prepare(challenge, tmp_path / f"packet-{challenge}")


def test_canary_detector_fires_on_deliberate_leak(tmp_path: Path) -> None:
    """A deliberate leak fixture (instructor key dropped into an export)
    fires the detector; a clean export stays silent."""
    (tmp_path / "BRIEF.md").write_text("clean packet\n", encoding="utf-8")
    assert scan_for_canary(tmp_path) == []
    leak = tmp_path / "leaked" / "KEY.md"
    leak.parent.mkdir()
    leak.write_text(
        "Canary: `INSTRUCTOR-CANARY-REVIEW-01` -- must never ship.\n",
        encoding="utf-8")
    assert scan_for_canary(tmp_path) == ["leaked/KEY.md"]


def test_mcp_guard_denies_checkout_instructor_contracts(
    tmp_path_factory,
) -> None:
    """Tool-mediated instructor-plane closure in a CHECKOUT layout.

    A real MCP stdio round trip against the guarded server, asking
    vulnify.lookup to read a genuine operator-held expected-findings
    contract (exercise_operator/contracts/*.json -- the answer key of a
    shipped challenge). The read-allowlist covers only the package
    directories the guarded jobs import, so the enforcer denies the open
    even though the file lives inside the repository, and the answer key
    never surfaces in the response.
    """
    from containment.mcp_guard import guarded_call, invoke_arguments

    root = tmp_path_factory.mktemp("instructor-mcp")
    approved = root / "approved"
    scratch = root / "scratch"
    approved.mkdir()
    scratch.mkdir()
    profile = OperatorProfile(
        approved_root=str(approved), scratch_root=str(scratch))
    contract = contract_files()[0]
    result = guarded_call(
        profile, tool="invoke",
        arguments=invoke_arguments(
            entry_id="vulnify", action="lookup",
            args={"feed": str(contract), "cve_id": "CVE-2024-0001"}),
    )
    payload = result.response["result"]
    assert payload["isError"] is True
    assert result.denials, "the enforcer must record the denied open"
    assert result.denials[0]["event"] == "open"
    assert "contracts" in str(result.denials[0].get("path", ""))
    # The answer-key bytes must not leak through the error channel either.
    assert contract.read_bytes()[:64] not in json.dumps(payload).encode()
