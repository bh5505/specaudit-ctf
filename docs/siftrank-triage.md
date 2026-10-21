# SiftRank triage adapter

SiftRank orders candidate records for review. Its scores are ranking values, not finding confidence or evidence. The operator chooses the input, executable, provider, model, and endpoint.

Prepare a JSON array of objects with unique `id`, `text`, and `source` strings. `source` is a reference displayed with the ranked result. The adapter supports three commands:

- `python -m learning triage rank` runs the selected SiftRank executable. Pass `--input`, `--prompt-file`, `--ranking-output`, `--binding-output`, `--executable`, `--provider`, `--model`, `--base-url`, and `--api-key-env`. Use `--executable-sha256` only when you want an exact binary check. The key comes from `OPENAI_API_KEY` or `TYPESAFE_API_KEY`, according to the selected provider, never from a command-line value.
- `python -m learning triage import --input candidates.json --ranking ranking.json --binding binding.json` reads a captured ranking without contacting a provider. The binding records declared upstream revision, provider and model, plus input, ranking and prompt hashes. Hashes identify the supplied bytes; they do not establish who produced them.
- `python -m learning triage evaluate --input candidates.json --ranking ranking.json --binding binding.json --labels labels.json` compares recall@k with a deterministic lexical baseline. Labels contain `query`, `k`, and `relevant_ids`.

The importer checks rank order, complete unique input-index coverage, exact original documents, finite scores, and byte hashes. The direct runner uses separate argv without a shell and caps input, output, and time. It requires POSIX process groups. It accepts up to 100 candidates or 256 KiB of input, captures up to 1 MiB of ranking output, and runs for at most 120 seconds. These limits do not cap provider charges; the operator chooses the endpoint and bears responsibility for its use.

The `extension/triage/fixtures/` files are hand-authored format examples, not a model-quality result. `python -m pytest tests/test_siftrank_triage.py` checks the local adapter.
