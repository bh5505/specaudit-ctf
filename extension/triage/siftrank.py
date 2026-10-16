"""Offline import of a captured SiftRank JSON ranking for human review order.

No provider, executable, endpoint, or evidence/grading interface is invoked here.
The caller must supply custody metadata independently of the candidate packet.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import selectors
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from dataclasses import dataclass
from pathlib import Path
from typing import Any


UPSTREAM_REVISION = "03e7afe3289a204ea3dcc51613cea91877a651de"
UPSTREAM_URL = "https://github.com/noperator/siftrank"
MAX_STDOUT_BYTES = 1_000_000
MAX_STDERR_BYTES = 65_536
MAX_INPUT_BYTES = 256_000
MAX_CANDIDATES = 100
MAX_BINDING_BYTES = 16_384


class TriageImportError(ValueError):
    """A captured ranking cannot be bound to its declared input and run."""


@dataclass(frozen=True)
class CaptureBinding:
    """Custodian-supplied capture record, never inferred from model output.

    The API compares hashes; authentication of this record and custody of its
    bytes are external responsibilities. A caller-created matching hash alone
    does not make a capture trustworthy.
    """

    upstream_revision: str
    input_sha256: str
    ranking_sha256: str
    prompt_sha256: str
    run_id: str
    captured_at: str
    provider: str
    model: str
    custody_ref: str


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise TriageImportError(f"{label} exceeds byte limit")
    return content


def _array(raw: bytes, name: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TriageImportError(f"{name} must be UTF-8 JSON") from exc
    if not isinstance(parsed, list) or not parsed or any(not isinstance(x, dict) for x in parsed):
        raise TriageImportError(f"{name} must be a nonempty JSON object array")
    return parsed


def _validate_candidates(candidates: list[dict[str, Any]]) -> None:
    if len(candidates) > MAX_CANDIDATES:
        raise TriageImportError("too many candidates")
    ids: set[str] = set()
    for candidate in candidates:
        for field in ("id", "text", "source"):
            if not isinstance(candidate.get(field), str) or not candidate[field].strip():
                raise TriageImportError(f"input candidate requires nonempty {field}")
            if len(candidate[field]) > {"id": 256, "text": 8192, "source": 1024}[field]:
                raise TriageImportError(f"input {field} exceeds length limit")
        if candidate["id"] in ids:
            raise TriageImportError("duplicate input id")
        ids.add(candidate["id"])


def import_capture(input_bytes: bytes, ranking_bytes: bytes, binding: CaptureBinding) -> dict[str, Any]:
    """Return review order for a complete, hash-bound SiftRank CLI capture.

    Input candidates are original JSON objects with unique ``id``, ``text``
    and ``source`` strings. The complete original object must be echoed in
    each output ``document``. No ranked result is dropped, relabeled, or
    interpreted as an observation or a finding.
    """
    if len(input_bytes) > MAX_INPUT_BYTES or len(ranking_bytes) > MAX_STDOUT_BYTES:
        raise TriageImportError("capture exceeds byte limit")
    if binding.upstream_revision != UPSTREAM_REVISION:
        raise TriageImportError("unreviewed SiftRank revision")
    for name in ("prompt_sha256", "input_sha256", "ranking_sha256"):
        value = getattr(binding, name)
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise TriageImportError(f"invalid {name}")
    for name in ("run_id", "captured_at", "provider", "model", "custody_ref"):
        value = getattr(binding, name)
        if not isinstance(value, str) or not value.strip():
            raise TriageImportError(f"missing {name}")
    if _digest(input_bytes) != binding.input_sha256 or _digest(ranking_bytes) != binding.ranking_sha256:
        raise TriageImportError("capture bytes differ from custodian hashes")
    candidates = _array(input_bytes, "input")
    ranking = _array(ranking_bytes, "ranking")
    _validate_candidates(candidates)
    if len(candidates) != len(ranking):
        raise TriageImportError("ranking must cover every input candidate")
    seen: set[int] = set()
    ordered: list[dict[str, Any]] = []
    for position, result in enumerate(ranking, 1):
        index = result.get("input_index")
        if type(index) is not int or index < 0 or index >= len(candidates) or index in seen:
            raise TriageImportError("invalid or duplicate input_index")
        seen.add(index)
        if type(result.get("rank")) is not int or result["rank"] != position:
            raise TriageImportError("rank must match 1-based array order")
        if result.get("document") != candidates[index]:
            raise TriageImportError("ranking document differs from original input")
        if not isinstance(result.get("value"), str) or not result["value"].strip():
            raise TriageImportError("missing rendered value")
        if len(result["value"]) > 16_384:
            raise TriageImportError("rendered value exceeds length limit")
        score = result.get("score")
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
            raise TriageImportError("score must be finite")
        for field in ("exposure", "rounds"):
            if type(result.get(field)) is not int or result[field] < 0:
                raise TriageImportError(f"invalid {field}")
        candidate = candidates[index]
        ordered.append({"rank": position, "id": candidate["id"], "source": candidate["source"],
                        "input_index": index})
    return {
        "kind": "review-order-only", "status": "captured-ranking-unverified-custody",
        "upstream": {"url": UPSTREAM_URL, "revision": binding.upstream_revision},
        "capture": {"run_id": binding.run_id, "captured_at": binding.captured_at,
                    "provider": binding.provider, "model": binding.model,
                    "custody_ref": binding.custody_ref, "prompt_sha256": binding.prompt_sha256,
                    "input_sha256": binding.input_sha256, "ranking_sha256": binding.ranking_sha256},
        "review_order": ordered,
        "limitations": ["ranking may vary between runs", "score is not a probability",
                        "rank is neither evidence nor a finding or grade",
                        "hash comparison does not authenticate custody"],
    }


def lexical_baseline(input_bytes: bytes, query: str) -> list[str]:
    """Deterministic token-overlap comparison, ties in input order."""
    import re

    terms = set(re.findall(r"[a-z0-9]+", query.lower()))
    if not terms:
        raise TriageImportError("query needs at least one token")
    candidates = _array(input_bytes, "input")
    if any(not isinstance(x.get("id"), str) or not isinstance(x.get("text"), str) for x in candidates):
        raise TriageImportError("baseline requires id and text")
    return [x["id"] for _, x in sorted(enumerate(candidates),
            key=lambda pair: (-len(terms & set(re.findall(r"[a-z0-9]+", pair[1]["text"].lower()))), pair[0]))]


def recall_at_k(order: list[str], relevant: set[str], k: int) -> float:
    if not relevant or k < 1 or len(order) != len(set(order)) or not relevant <= set(order):
        raise TriageImportError("invalid held-out labels, order, or k")
    return len(set(order[:k]) & relevant) / len(relevant)


def evaluate_capture(input_bytes: bytes, ranking_bytes: bytes, binding: CaptureBinding,
                     labels_bytes: bytes) -> dict[str, Any]:
    """Compare captured order with a lexical baseline over separately held labels."""
    if len(labels_bytes) > MAX_BINDING_BYTES:
        raise TriageImportError("labels exceed byte limit")
    try:
        labels = json.loads(labels_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise TriageImportError("labels must be UTF-8 JSON") from exc
    if not isinstance(labels, dict) or labels.get("evaluation_scope") not in {
        "synthetic-format-fixture", "actual-held-out"}:
        raise TriageImportError("labels require evaluation_scope")
    query, k, relevant_ids = labels.get("query"), labels.get("k"), labels.get("relevant_ids")
    if not isinstance(query, str) or not query.strip() or len(query) > 4000:
        raise TriageImportError("invalid labels query")
    if type(k) is not int or k < 1:
        raise TriageImportError("invalid labels k")
    if not isinstance(relevant_ids, list) or not relevant_ids or any(
        not isinstance(x, str) or not x or len(x) > 256 for x in relevant_ids
    ) or len(set(relevant_ids)) != len(relevant_ids):
        raise TriageImportError("invalid relevant_ids")
    imported = import_capture(input_bytes, ranking_bytes, binding)
    ordered = [row["id"] for row in imported["review_order"]]
    if k > len(ordered):
        raise TriageImportError("k exceeds candidate count")
    relevant = set(relevant_ids)
    baseline = lexical_baseline(input_bytes, query)
    ranked_recall = recall_at_k(ordered, relevant, k)
    baseline_recall = recall_at_k(baseline, relevant, k)
    return {
        "kind": "review-order-evaluation-only", "evaluation_scope": labels["evaluation_scope"],
        "run_id": binding.run_id, "input_sha256": binding.input_sha256,
        "ranking_sha256": binding.ranking_sha256, "labels_sha256": _digest(labels_bytes),
        "k": k, "candidate_count": len(ordered), "relevant_count": len(relevant),
        "ranking": {"recall_at_k": ranked_recall, "reviewed_at_k": k,
                    "review_burden_fraction": k / len(ordered),
                    "omitted_relevant_ids": sorted(relevant - set(ordered[:k]))},
        "lexical_baseline": {"recall_at_k": baseline_recall, "reviewed_at_k": k,
                             "review_burden_fraction": k / len(ordered),
                             "omitted_relevant_ids": sorted(relevant - set(baseline[:k]))},
        "limitations": ["labels and relevance judgments require independent review",
                        "one captured run cannot establish run-to-run variance or model quality",
                        "top-k omissions remain in the full packet; never discard them",
                        "rank is not evidence, finding, probability, or grade"],
    }


def _allowed_endpoint(base_url: str) -> bool:
    try:
        url = urlsplit(base_url)
        if url.username is not None or url.password is not None or url.fragment:
            return False
        if not url.hostname or url.port is None and url.scheme == "http":
            return False
        if url.scheme == "http":
            return url.hostname == "127.0.0.1" and url.port is not None
        return url.scheme == "https" and bool(url.hostname)
    except ValueError:
        return False


def _bounded_process(argv: list[str], *, env: dict[str, str], cwd: str,
                     timeout_seconds: int) -> bytes:
    """Drain with hard output limits and terminate the entire POSIX process group."""
    if os.name != "posix":
        raise TriageImportError("opt-in execution requires POSIX process groups")
    try:
        process = subprocess.Popen(argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
    except OSError as exc:
        raise TriageImportError("SiftRank invocation failed") from exc
    output = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": MAX_STDOUT_BYTES, "stderr": MAX_STDERR_BYTES}
    deadline = time.monotonic() + timeout_seconds
    try:
        with selectors.DefaultSelector() as selector:
            assert process.stdout is not None and process.stderr is not None
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TriageImportError("SiftRank timed out")
                for key, _ in selector.select(min(remaining, 0.25)):
                    name = key.data
                    # Read at most one byte beyond the cap before aborting.
                    chunk = os.read(key.fileobj.fileno(),
                                    min(65536, limits[name] + 1 - len(output[name])))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output[name].extend(chunk)
                    if len(output[name]) > limits[name]:
                        raise TriageImportError(f"SiftRank {name} limit exceeded")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TriageImportError("SiftRank timed out")
            if process.wait(timeout=remaining):
                raise TriageImportError("SiftRank returned an error")
            return bytes(output["stdout"])
    finally:
        # A child may have inherited the pipes or outlived the CLI. Close all
        # descendants in the process group on success, failure, or timeout.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()


def run_siftrank(
    input_bytes: bytes, prompt: str, *, executable: Path, executable_sha256: str,
    provider: str, model: str, base_url: str, api_key: str,
    budget_authority_ref: str, custody_ref: str, run_id: str, captured_at: str,
    allow_provider_call: bool = False, timeout_seconds: int = 120,
) -> tuple[dict[str, Any], bytes, CaptureBinding]:
    """Explicitly authorized bounded CLI experiment, returning raw output too.

    External containment must enforce provider egress and monetary budget. The
    SiftRank CLI has no hard spend cap; these arguments limit time and trials,
    not charges. Caller retains raw bytes and independently seals custody.
    """
    if not allow_provider_call or not budget_authority_ref.strip():
        raise TriageImportError("provider call requires opt-in and external budget authority")
    if provider not in {"openai", "jev"} or not model.strip() or not api_key:
        raise TriageImportError("explicit supported provider, model, and API key required")
    if not _allowed_endpoint(base_url):
        raise TriageImportError("explicit HTTPS or loopback provider endpoint required")
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 120:
        raise TriageImportError("timeout must be 1..120 seconds")
    if not prompt.strip() or len(input_bytes) > MAX_INPUT_BYTES or len(prompt) > 4000:
        raise TriageImportError("input or prompt exceeds experiment bounds")
    _validate_candidates(_array(input_bytes, "input"))
    binary = executable.resolve(strict=True)
    if not binary.is_file() or _digest(binary.read_bytes()) != executable_sha256:
        raise TriageImportError("executable hash mismatch")
    # Environment is deliberately closed: no inherited profiles or ambient keys.
    key_name = "OPENAI_API_KEY" if provider == "openai" else "TYPESAFE_API_KEY"
    env = {"PATH": os.defpath, key_name: api_key}
    with tempfile.TemporaryDirectory(prefix="siftrank-triage-") as directory:
        root = Path(directory)
        source = root / "candidates.json"
        source.write_bytes(input_bytes)
        prompt_path = root / "prompt.txt"
        prompt_path.write_text(prompt, encoding="utf-8")
        config = root / "config.yaml"
        config.write_text("{}\n", encoding="utf-8")
        argv = [str(binary), "--config-file", str(config), "--provider", provider,
                "--model", model, "--base-url", base_url, "--file", str(source),
                "--prompt", "@" + str(prompt_path), "--template", "ID: {{ .id }}\n{{ .text }}",
                "--concurrency", "1", "--batch-size", "5", "--min-trials", "2",
                "--max-trials", "5", "--tokens", "4096"]
        ranking_bytes = _bounded_process(argv, env=env, cwd=directory,
                                         timeout_seconds=timeout_seconds)
    binding = CaptureBinding(UPSTREAM_REVISION, _digest(input_bytes), _digest(ranking_bytes),
                             _digest(prompt.encode("utf-8")), run_id, captured_at,
                             provider, model, custody_ref)
    return import_capture(input_bytes, ranking_bytes, binding), ranking_bytes, binding


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        import sys
        argv = sys.argv[1:]
    if argv and argv[0] == "rank":
        return _rank_main(argv[1:])
    if argv and argv[0] == "evaluate":
        return _evaluate_main(argv[1:])
    if not argv or argv[0] in {"-h", "--help"}:
        print("usage: python -m learning triage {import|rank|evaluate} ...")
        print("  import    validate a retained captured ranking (offline)")
        print("  rank      opt-in provider CLI run with external budget authority")
        print("  evaluate  compare captured recall@k with a lexical baseline (offline)")
        return 0 if argv else 2
    if argv and argv[0] == "import":
        argv = argv[1:]
    parser = argparse.ArgumentParser(description="Import a custody-bound, captured SiftRank ranking")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--ranking", required=True, type=Path)
    parser.add_argument("--binding", required=True, type=Path,
                        help="trusted custodian record; never accept from candidate content")
    args = parser.parse_args(argv)
    try:
        binding = CaptureBinding(**json.loads(_read_bounded(args.binding, MAX_BINDING_BYTES, "binding")))
        result = import_capture(_read_bounded(args.input, MAX_INPUT_BYTES, "input"),
                                _read_bounded(args.ranking, MAX_STDOUT_BYTES, "ranking"), binding)
    except (OSError, TypeError, json.JSONDecodeError, TriageImportError) as exc:
        parser.exit(2, f"triage import refused: {exc}\n")
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _evaluate_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Offline recall@k comparison for a captured ranking")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--ranking", required=True, type=Path)
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--labels", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        binding = CaptureBinding(**json.loads(_read_bounded(args.binding, MAX_BINDING_BYTES, "binding")))
        result = evaluate_capture(_read_bounded(args.input, MAX_INPUT_BYTES, "input"),
                                  _read_bounded(args.ranking, MAX_STDOUT_BYTES, "ranking"),
                                  binding, _read_bounded(args.labels, MAX_BINDING_BYTES, "labels"))
    except (OSError, TypeError, json.JSONDecodeError, TriageImportError) as exc:
        parser.exit(2, f"triage evaluation refused: {exc}\n")
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


def _rank_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Opt-in SiftRank CLI experiment (provider call)")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--prompt-file", required=True, type=Path)
    parser.add_argument("--ranking-output", required=True, type=Path)
    parser.add_argument("--binding-output", required=True, type=Path)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--executable-sha256", required=True)
    parser.add_argument("--provider", choices=("openai", "jev"), required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--api-key-env", choices=("OPENAI_API_KEY", "TYPESAFE_API_KEY"), required=True)
    parser.add_argument("--budget-authority-ref", required=True)
    parser.add_argument("--custody-ref", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--captured-at", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--allow-provider-call", action="store_true")
    args = parser.parse_args(argv)
    expected_key = "OPENAI_API_KEY" if args.provider == "openai" else "TYPESAFE_API_KEY"
    if args.api_key_env != expected_key:
        parser.exit(2, "triage rank refused: provider/key environment mismatch\n")
    if args.ranking_output.resolve() == args.binding_output.resolve():
        parser.exit(2, "triage rank refused: output paths must differ\n")
    if args.ranking_output.exists() or args.binding_output.exists():
        parser.exit(2, "triage rank refused: output already exists\n")
    created: list[Path] = []
    try:
        result, ranking_bytes, binding = run_siftrank(
            _read_bounded(args.input, MAX_INPUT_BYTES, "input"),
            _read_bounded(args.prompt_file, 16_000, "prompt").decode("utf-8"),
            executable=args.executable, executable_sha256=args.executable_sha256,
            provider=args.provider, model=args.model, base_url=args.base_url,
            api_key=os.environ.get(args.api_key_env, ""),
            budget_authority_ref=args.budget_authority_ref, custody_ref=args.custody_ref,
            run_id=args.run_id, captured_at=args.captured_at,
            allow_provider_call=args.allow_provider_call, timeout_seconds=args.timeout_seconds)
        with args.ranking_output.open("xb") as stream:
            created.append(args.ranking_output)
            stream.write(ranking_bytes)
        with args.binding_output.open("xb") as stream:
            created.append(args.binding_output)
            stream.write((json.dumps(vars(binding), sort_keys=True, indent=2) + "\n").encode())
    except (OSError, UnicodeError, TriageImportError) as exc:
        for path in created:
            path.unlink(missing_ok=True)
        parser.exit(2, f"triage rank refused: {exc}\n")
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
