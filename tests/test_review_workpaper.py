import copy
import json
from importlib.resources import files
from pathlib import Path

from review_workpaper.__main__ import main, validate


ROOT = Path(__file__).resolve().parents[1]
LEARNER = ROOT / "challenges/lab-review-01-threat-model/learner"
INSTRUCTOR = ROOT / "challenges/lab-review-01-threat-model/instructor"


def packet():
    return json.loads((LEARNER / "manifest.json").read_text())


def workpaper():
    def claim(key, refs, status):
        return dict(id=key, status=status, hypothesis=key, boundary="note to assistant",
                    observation="see cited record", inference="bounded inference",
                    alternative="other channel or unrelated draft text", validation="compare source and ledger",
                    residual_risk="unobserved delivery", evidence_ids=refs)

    return dict(schema="specaudit.review-workpaper.v1", subject="Harbor Notes",
                version="0.4", period="fixture interval", boundary="BLUE only",
                criterion="gateway workspace policy", reviewer="training reviewer",
                assets=["note", "draft"], trust_boundaries=["untrusted note to assistant"],
                attacker_goals=["induce RED export claim"], untested=["other channels"],
                limitations=["ledger unavailable"], recommendation=["review draft"],
                retest=["collect outbound ledger"], overall="inconclusive",
                claims=[claim("allowed-read", ["gateway"], "supported"),
                        claim("export", ["note", "gateway"], "rejected"),
                        claim("delivery", ["telemetry-gap"], "unresolved")],
                coverage=[dict(surface="gateway", disposition="bounded review",
                               claim_ids=["allowed-read", "export"]),
                          dict(surface="outbound", disposition="untested", claim_ids=["delivery"])])


def test_valid_packet_and_structural_workpaper(tmp_path, capsys):
    submission = tmp_path / "workpaper.json"
    submission.write_text(json.dumps(workpaper()))
    assert main(["--manifest", str(LEARNER / "manifest.json"),
                 "--submission", str(submission), "--evidence-root", str(LEARNER)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {"structurally_valid": True, "human_review_required": True, "errors": []}


def test_false_assurance_inputs_are_not_accepted_as_structural_success():
    sample = workpaper()
    sample["overall"] = "all-clear"
    sample["claims"][0]["evidence_ids"] = ["architecture"]
    sample["claims"][1]["evidence_ids"] = ["forged"]
    errors = validate(packet(), sample, LEARNER)
    assert any("all-clear" in err for err in errors)
    assert any("requires observed" in err for err in errors)
    assert any("unknown reference" in err for err in errors)


def test_custody_and_path_containment(tmp_path):
    manifest = packet()
    manifest["evidence"][0]["file"] = "../instructor/KEY.md"
    assert any("outside evidence root" in e for e in validate(manifest, workpaper(), LEARNER))
    manifest = packet()
    manifest["evidence"][0]["sha256"] = "0" * 64
    manifest["evidence"].append(copy.deepcopy(manifest["evidence"][0]))
    errors = validate(manifest, workpaper(), LEARNER)
    assert any("content mismatch" in e for e in errors)
    assert any("duplicate or invalid id" in e for e in errors)


def test_malformed_fields_do_not_crash():
    sample = workpaper()
    sample["coverage"][0]["claim_ids"] = [{}]
    sample["coverage"][0]["surface"] = {}
    sample["claims"][0]["evidence_ids"] = [{}]
    sample["claims"][0]["status"] = []
    sample["limitations"] = [None]
    sample["untested"] = [{}]
    manifest = packet()
    manifest["evidence"][0]["kind"] = {}
    errors = validate(manifest, sample, LEARNER)
    assert any("kind" in e for e in errors)
    assert any("status" in e for e in errors)
    assert any("limitations[0]" in e for e in errors)
    assert any("untested[0]" in e for e in errors)
    assert validate(packet(), sample, LEARNER)


def test_all_text_arrays_reject_empty_items():
    sample = workpaper()
    fields = ("assets", "trust_boundaries", "attacker_goals", "untested",
              "limitations", "recommendation", "retest")
    for field in fields:
        broken = copy.deepcopy(sample)
        broken[field] = [" "]
        assert any(f"{field}[0]" in e for e in validate(packet(), broken, LEARNER))


def test_manifest_record_and_file_limits(tmp_path):
    manifest = packet()
    manifest["evidence"] = [dict(manifest["evidence"][0], id=f"copy-{i}") for i in range(101)]
    assert any("maximum 100" in e for e in validate(manifest, workpaper(), LEARNER))

    large = tmp_path / "large.bin"
    large.write_bytes(b"A" * (1_048_576 + 1))
    manifest = packet()
    manifest["evidence"][0]["file"] = "large.bin"
    assert any("exceeds 1048576" in e for e in validate(manifest, workpaper(), tmp_path))


def test_learner_packet_excludes_key_and_bundled_copy_matches():
    assert not any("INSTRUCTOR-CANARY-REVIEW-01" in p.read_text() for p in LEARNER.rglob("*") if p.is_file())
    assert "INSTRUCTOR-CANARY-REVIEW-01" in (INSTRUCTOR / "KEY.md").read_text()
    bundled = files("review_workpaper").joinpath("packet")
    for path in LEARNER.rglob("*"):
        if path.is_file():
            assert path.read_bytes() == bundled.joinpath(*path.relative_to(LEARNER).parts).read_bytes()
