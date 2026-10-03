"""SiftRank captured-format and trust-boundary tests; no model call is made."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import time

import pytest

from extension.triage.siftrank import (
    CaptureBinding, TriageImportError, import_capture, lexical_baseline, recall_at_k,
    evaluate_capture, main, run_siftrank,
)


FIXTURES = Path(__file__).resolve().parents[1] / "extension" / "triage" / "fixtures"


def capture():
    source = (FIXTURES / "candidates.json").read_bytes()
    ranking = (FIXTURES / "ranking.synthetic.json").read_bytes()
    binding = CaptureBinding(**json.loads((FIXTURES / "binding.synthetic.json").read_bytes()))
    return source, ranking, binding


def test_review_order_and_held_out_comparison():
    source, ranking, binding = capture()
    result = import_capture(source, ranking, binding)
    assert result["kind"] == "review-order-only"
    assert [r["id"] for r in result["review_order"]] == ["C03", "C05", "C02", "C04", "C01", "C06"]
    assert all("score" not in r and "text" not in r for r in result["review_order"])
    labels = json.loads((FIXTURES / "labels.synthetic.json").read_bytes())
    baseline = lexical_baseline(source, labels["query"])
    relevant = set(labels["relevant_ids"])
    assert recall_at_k(baseline, relevant, labels["k"]) == pytest.approx(2 / 3)
    assert recall_at_k([r["id"] for r in result["review_order"]], relevant, labels["k"]) == 1
    # The ranked fixture was hand-authored to exercise import/evaluation logic.
    # These numbers do not measure model performance or generalize to held-out runs.


@pytest.mark.parametrize("edit", [
    lambda rows: rows.pop(),
    lambda rows: rows[0].update(input_index=rows[1]["input_index"]),
    lambda rows: rows[0].update(rank=2),
    lambda rows: rows[0]["document"].update(text="substituted evidence"),
    lambda rows: rows[0].update(score=float("nan")),
    lambda rows: rows[0].update(exposure=-1),
    lambda rows: rows[0].pop("value"),
])
def test_malformed_even_when_rehashed_by_test_custodian(edit):
    source, ranking, binding = capture()
    rows = json.loads(ranking)
    edit(rows)
    altered = json.dumps(rows).encode()
    binding = replace(binding, ranking_sha256=hashlib.sha256(altered).hexdigest())
    with pytest.raises(TriageImportError):
        import_capture(source, altered, binding)


def test_tamper_and_unreviewed_revision_fail_closed():
    source, ranking, binding = capture()
    with pytest.raises(TriageImportError, match="hashes"):
        import_capture(source + b" ", ranking, binding)
    with pytest.raises(TriageImportError, match="revision"):
        import_capture(source, ranking, replace(binding, upstream_revision="latest"))
    with pytest.raises(TriageImportError, match="custody_ref"):
        import_capture(source, ranking, replace(binding, custody_ref=""))


def test_duplicate_candidate_id_and_invalid_labels():
    source, ranking, binding = capture()
    candidates = json.loads(source)
    candidates[1]["id"] = candidates[0]["id"]
    altered = json.dumps(candidates).encode()
    with pytest.raises(TriageImportError, match="duplicate input id"):
        import_capture(altered, ranking, replace(binding, input_sha256=hashlib.sha256(altered).hexdigest()))
    with pytest.raises(TriageImportError):
        recall_at_k(["C01"], {"C02"}, 1)


def _fake_binary(tmp_path, source):
    binary = tmp_path / "siftrank"
    binary.write_text("#!/usr/bin/env python3\n" + source)
    binary.chmod(0o700)
    return binary


def _options(binary):
    return dict(executable=binary, executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                provider="openai", model="local-test-model", base_url="http://127.0.0.1:8000/v1",
                api_key="sentinel", budget_authority_ref="test-only:budget",
                custody_ref="test-only:capture", run_id="test-only:run",
                captured_at="2026-10-03T00:00:00Z")


def test_optional_cli_uses_fixed_argv_and_closed_environment(tmp_path, monkeypatch, capsys):
    source, ranking, _ = capture()
    binary = _fake_binary(tmp_path, "import os, sys\n"
        "assert '--max-trials' in sys.argv and '--file' in sys.argv\n"
            "assert os.environ['OPENAI_API_KEY'] == 'sentinel' and 'HOME' not in os.environ\n"
        f"sys.stdout.buffer.write({ranking!r})\n")
    options = _options(binary)
    with pytest.raises(TriageImportError, match="opt-in"):
        run_siftrank(source, "Prioritize missing evidence", **options)
    result, raw, binding = run_siftrank(source, "Prioritize missing evidence",
                                         allow_provider_call=True, **options)
    assert result["kind"] == "review-order-only" and raw == ranking
    assert binding.ranking_sha256 == hashlib.sha256(ranking).hexdigest()
    with pytest.raises(TriageImportError, match="hash mismatch"):
        run_siftrank(source, "Prioritize missing evidence", allow_provider_call=True,
                     **{**options, "executable_sha256": "0" * 64})
    (tmp_path / "input.json").write_bytes(source)
    (tmp_path / "prompt.txt").write_text("Prioritize missing evidence")
    monkeypatch.setenv("OPENAI_API_KEY", "sentinel")
    flags = ["rank", "--input", str(tmp_path / "input.json"), "--prompt-file", str(tmp_path / "prompt.txt"),
             "--ranking-output", str(tmp_path / "output.json"), "--binding-output", str(tmp_path / "binding.json"),
             "--executable", str(binary), "--executable-sha256", options["executable_sha256"],
             "--provider", "openai", "--model", "local-test-model", "--base-url", options["base_url"],
             "--api-key-env", "OPENAI_API_KEY", "--budget-authority-ref", "test-only:budget",
             "--custody-ref", "test-only:capture", "--run-id", "test-only:run",
             "--captured-at", "2026-10-03T00:00:00Z", "--allow-provider-call"]
    assert main(flags) == 0
    assert (tmp_path / "output.json").read_bytes() == ranking
    assert "sentinel" not in capsys.readouterr().out
    assert main(["import", "--input", str(tmp_path / "input.json"),
                 "--ranking", str(tmp_path / "output.json"),
                 "--binding", str(tmp_path / "binding.json")]) == 0


def test_execution_output_caps_and_descendant_timeout(tmp_path):
    source, _, _ = capture()
    for stream in ("stdout", "stderr"):
        binary = _fake_binary(tmp_path, f"import sys\nsys.{stream}.buffer.write(b'x' * 1100000)\n")
        with pytest.raises(TriageImportError, match=stream + " limit"):
            run_siftrank(source, "rank", allow_provider_call=True, **_options(binary))
    marker = tmp_path / "descendant-survived"
    binary = _fake_binary(tmp_path,
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {('import time; from pathlib import Path; time.sleep(2); Path(' + repr(str(marker)) + ').write_text(\'bad\')')!r}])\n"
        "time.sleep(10)\n")
    with pytest.raises(TriageImportError, match="timed out"):
        run_siftrank(source, "rank", allow_provider_call=True, timeout_seconds=1, **_options(binary))
    time.sleep(2.2)
    assert not marker.exists()


def test_import_size_and_candidate_limits(tmp_path):
    source, ranking, binding = capture()
    with pytest.raises(TriageImportError, match="byte limit"):
        import_capture(source + b" " * 256_000, ranking, binding)
    with pytest.raises(TriageImportError, match="byte limit"):
        import_capture(source, ranking + b" " * 1_000_000, binding)
    candidates = [{"id": f"C{i}", "text": "x", "source": f"p/{i}"} for i in range(101)]
    altered = json.dumps(candidates).encode()
    with pytest.raises(TriageImportError, match="too many"):
        import_capture(altered, ranking, replace(binding, input_sha256=hashlib.sha256(altered).hexdigest()))
    candidates = json.loads(source)
    candidates[0]["text"] = "x" * 8193
    altered = json.dumps(candidates).encode()
    with pytest.raises(TriageImportError, match="length limit"):
        import_capture(altered, ranking, replace(binding, input_sha256=hashlib.sha256(altered).hexdigest()))
    oversized = tmp_path / "too-large.json"
    oversized.write_bytes(b"x" * 256_001)
    with pytest.raises(SystemExit) as exc:
        main(["import", "--input", str(oversized), "--ranking", str(FIXTURES / "ranking.synthetic.json"),
              "--binding", str(FIXTURES / "binding.synthetic.json")])
    assert exc.value.code == 2


def test_evaluate_cli_and_top_level_help(capsys):
    source, ranking, binding = capture()
    labels = (FIXTURES / "labels.synthetic.json").read_bytes()
    result = evaluate_capture(source, ranking, binding, labels)
    assert result["evaluation_scope"] == "synthetic-format-fixture"
    assert result["ranking"]["recall_at_k"] == 1
    assert result["lexical_baseline"]["recall_at_k"] == pytest.approx(2 / 3)
    assert result["lexical_baseline"]["omitted_relevant_ids"] == ["C03"]
    assert result["ranking"]["review_burden_fraction"] == 0.5
    assert main(["--help"]) == 0
    assert "{import|rank|evaluate}" in capsys.readouterr().out
    assert main(["evaluate", "--input", str(FIXTURES / "candidates.json"),
                 "--ranking", str(FIXTURES / "ranking.synthetic.json"),
                 "--binding", str(FIXTURES / "binding.synthetic.json"),
                 "--labels", str(FIXTURES / "labels.synthetic.json")]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "review-order-evaluation-only"
    malformed = json.dumps({"query": "evidence", "k": 2, "relevant_ids": ["C01"]}).encode()
    with pytest.raises(TriageImportError, match="evaluation_scope"):
        evaluate_capture(source, ranking, binding, malformed)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:1@evil.example/v1", "http://127.0.0.1.evil.example:8000/v1",
    "https://user:pass@example.com/v1", "http://127.0.0.1:bad/v1",
])
def test_spoofed_provider_authority_is_refused(tmp_path, url):
    source, _, _ = capture()
    binary = _fake_binary(tmp_path, "raise AssertionError('must not execute')\n")
    with pytest.raises(TriageImportError, match="endpoint"):
        run_siftrank(source, "rank", allow_provider_call=True,
                     **{**_options(binary), "base_url": url})


def test_rank_cli_removes_partial_artifact_if_second_write_fails(tmp_path, monkeypatch):
    source, ranking, _ = capture()
    binary = _fake_binary(tmp_path, f"import sys\nsys.stdout.buffer.write({ranking!r})\n")
    (tmp_path / "input.json").write_bytes(source)
    (tmp_path / "prompt.txt").write_text("rank")
    monkeypatch.setenv("OPENAI_API_KEY", "sentinel")
    output = tmp_path / "ranking.json"
    binding = tmp_path / "binding.json"
    original_open = Path.open

    def fail_second(self, *args, **kwargs):
        if self == binding and args and args[0] == "xb":
            raise OSError("simulated disk failure")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_second)
    options = _options(binary)
    with pytest.raises(SystemExit) as exc:
        main(["rank", "--input", str(tmp_path / "input.json"),
              "--prompt-file", str(tmp_path / "prompt.txt"), "--ranking-output", str(output),
              "--binding-output", str(binding), "--executable", str(binary),
              "--executable-sha256", options["executable_sha256"], "--provider", "openai",
              "--model", "local-test-model", "--base-url", options["base_url"],
              "--api-key-env", "OPENAI_API_KEY", "--budget-authority-ref", "test-only:budget",
              "--custody-ref", "test-only:capture", "--run-id", "test-only:run",
              "--captured-at", "2026-10-03T00:00:00Z", "--allow-provider-call"])
    assert exc.value.code == 2
    assert not output.exists() and not binding.exists()
