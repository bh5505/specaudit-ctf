# SiftRank evidence-packet triage (optional research adapter)

This adapter changes **human review order only**. It does not collect evidence,
assert a finding, authenticate custody, decide severity, or grade an attempt.
The default operation is a captured-output import with no model or network call.

The catalog-selected upstream revision is [noperator/siftrank at
`03e7afe3289a204ea3dcc51613cea91877a651de`](https://github.com/noperator/siftrank/tree/03e7afe3289a204ea3dcc51613cea91877a651de).
The README at that exact revision documents a CLI that accepts a JSON array with `--file`, a Go template with
`--template`, and a ranking request with `--prompt`; stdout is a JSON array in
rank order. Each result has `rank` (1-based), `input_index` (zero-based),
`document` (original object), `value` (rendered text), `score`, `exposure`, and
`rounds`. The score is an internal ranking score, not probability. See the
[upstream README](https://github.com/noperator/siftrank#input-and-output-details).
The pinned README flags were checked against the exact commit. No binary was
built or run from that source during this work. Review the executable's build
provenance before a provider experiment; the adapter refuses other declared
revisions but cannot itself establish how a binary was built.

The local candidate array consists of objects with unique nonempty `id`,
`text`, and `source` strings. `source` is a *logical reference*, not evidence
custody. An operator can prepare a frozen, sanitized packet, choose a prompt,
and separately retain input bytes, prompt bytes, ranking stdout and a trusted
capture record. A basic upstream invocation is:

```sh
siftrank --file candidates.json \
  --template 'ID: {{ .id }}\n{{ .text }}' \
  --prompt @prompt.txt > ranking.json
```

The Python API `extension.triage.siftrank.import_capture(input_bytes,
ranking_bytes, CaptureBinding(...))` compares the custodian-provided SHA-256
hashes, checks full unique input-index coverage, exact original documents,
contiguous rank/order, finite scores and structural fields. It returns only
identifiers and logical source references in a `review-order-only` result. The
`CaptureBinding` must come from the operator's separate retained record, not
from the candidate packet or model output. Matching self-asserted hashes do not
authenticate source, capture time, model, provider, or custody.
The importer caps input at 256,000 bytes, ranking at 1,000,000 bytes, binding
at 16,384 bytes in the CLI, and candidate count at 100. Candidate identifier,
text, source and rendered values have field-length limits. Excess input is
refused before full-file reads in the CLI or before JSON decoding in the API.

Import a retained capture with `python -m extension.triage.siftrank import
--input candidates.json --ranking ranking.json --binding binding.json`.
`python -m learning triage --help` lists `import`, `rank`, and `evaluate`.

An opt-in `run_siftrank` Python API calls an explicitly selected, hash-checked
executable with fixed argument names and no shell. The caller must provide a
provider, model, endpoint, key, run metadata, external budget authority, and
`allow_provider_call=True`. It uses a fresh temporary input/config directory,
a closed process environment, at most 100 candidates or 256 KiB, one concurrent
call, five trials, and at most 120 seconds. Preserve the returned stdout and
binding separately; externally seal them with operator custody controls. An
executable hash alone does not prove source-equivalent build provenance, and
the process limits do **not** cap financial charges or guarantee egress denial.
The operator must enforce both outside the process. No default call is made.
Execution requires POSIX process groups; stdout is capped at 1,000,000 bytes
and stderr at 65,536 bytes while streaming, and the process group is killed on
failure, timeout, or completion. The caller's environment is replaced with a
minimal PATH and the one selected provider key. A process can still contact
the selected endpoint before the timeout or output limit trips.

The public opt-in CLI form is `python -m extension.triage.siftrank rank` with
`--input`, `--prompt-file`, `--ranking-output`, `--binding-output`,
`--executable`, `--executable-sha256`, `--provider`, `--model`, `--base-url`,
`--api-key-env`, `--budget-authority-ref`, `--custody-ref`, `--run-id`,
`--captured-at`, and `--allow-provider-call`. For OpenAI-compatible providers,
set `OPENAI_API_KEY` in the operator environment and pass
`--api-key-env OPENAI_API_KEY`; for Jev, use `TYPESAFE_API_KEY`. Never put a key
in command-line arguments. Output files must be new paths. The capture
binding written by the same process records hashes and run declarations; it
still needs independent operator custody to become trusted metadata.
The endpoint parser rejects userinfo, malformed authorities and non-loopback
HTTP hosts. The operator still enforces egress to the selected destination.

The distributable deterministic synthetic fixture under `extension/triage/fixtures/` is
hand-authored in the documented output shape; it is **not** an actual SiftRank
model run. Its held-out labels exercise `recall_at_k` and a deterministic
token-overlap baseline: baseline recall@3 is 2/3 and the illustrative ranking
is 3/3. These figures validate the measurement and importer wiring only; they
cannot establish SiftRank effectiveness, run-to-run variance, omissions, cost,
or suitability. An evaluation requires frozen held-out synthetic packets,
actual version-pinned captures from repeated bounded runs, prompt/model/run
metadata, independent labels and human review of critical, benign and unknown
cases. A model-ranked top-k must never discard the remaining evidence.

For a retained capture, use `python -m learning triage evaluate --input
candidates.json --ranking ranking.json --binding binding.json --labels
labels.json`. Labels are a separate JSON object with `evaluation_scope`
(`synthetic-format-fixture` or `actual-held-out`), `query`, positive integer
`k`, and a unique nonempty `relevant_ids` array. The result reports recall@k,
reviewed item count/fraction, and omitted relevant IDs for the captured order
and deterministic token-overlap baseline. It binds output to input, ranking,
and labels hashes, but a self-declared `actual-held-out` label and a single run
do not prove labeling quality, statistical reliability, or generalization.

Run `python -m pytest tests/test_siftrank_triage.py` for the local contract.
