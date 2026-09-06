# Multi-attempt variance sweep — flagship 06 + knowledge lane (2026-09-06)

First per-cell stability data for the head matrix, produced by
`lab/matrix-variance.sh` (N runner commands per cell) and reduced by
`lab/matrix_stats.py` (no smoothing, no retries; every failure reason
is verbatim). Slice: flagship `telecom-aws-06-chain-rehearsal` + the
new `lab-knowledge-01-attack-mapping`, plus the same two tracks in
hard mode (scaffolding-withheld prompts; same contracts). 28 attempts.

## Stability stats

| cell | attempts | passes (rate) | tool calls | verified | severity flags | duration s | failures |
|---|---|---|---|---|---|---|---|
| claude-kali/lab-knowledge-01-attack-mapping | 3 | 1 (33%) | 0-6 (median 0) | 3 | 0 | 1.7-22.7 (median 1.7) | 2 × infra (see below) |
| claude-kali/lab-knowledge-01-attack-mapping-hard | 2 | 0 (0%) | 0-0 | n/a | 0 | 1.7 | 2 × infra |
| claude-kali/telecom-aws-06-chain-rehearsal | 3 | 3 (100%) | 3-8 (median 6) | 5-5 | 0 | 15.8-18.9 | none |
| claude-kali/telecom-aws-06-chain-rehearsal-hard | 2 | 0 (0%) | 0-0 | n/a | 0 | 1.6-1.7 | 2 × infra |
| codex-kali/lab-knowledge-01-attack-mapping | 3 | 3 (100%) | 6-13 | 3-3 | 0 | 33.9-123.7 | none |
| codex-kali/lab-knowledge-01-attack-mapping-hard | 2 | 2 (100%) | 6-9 | 3-3 | 1 | 115.1-140.2 | none |
| codex-kali/telecom-aws-06-chain-rehearsal | 3 | 3 (100%) | 12-19 | 5-5 | 0 | 47.7-92.2 | none |
| codex-kali/telecom-aws-06-chain-rehearsal-hard | 2 | 2 (100%) | 28-44 | 5-5 | 0 | 273.4-384.5 | none |
| codex-ubuntu/lab-knowledge-01-attack-mapping | 3 | 3 (100%) | 5-13 | 3-3 | 0 | 33.3-134.2 | none |
| codex-ubuntu/lab-knowledge-01-attack-mapping-hard | 2 | 2 (100%) | 7-12 | 3-3 | 2 | 89-138.7 | none |
| codex-ubuntu/telecom-aws-06-chain-rehearsal | 3 | 3 (100%) | 11-21 | 5-5 | 0 | 55.8-222.9 | none |

## What the numbers say

- **Codex is stable on both hosts: 18/18 passes.** Call counts vary
  ~2x within a cell (e.g. knowledge 5-13) — session shape, not
  verdicts; every pass has full verified coverage and zero
  unverified claims. The one earlier knowledge failure (codex@ubuntu,
  matrix records of this date) did NOT reproduce in N=3: a real but
  low-frequency head behavior (the artifact_dir improvisation), not a
  systematic gap.
- **The difficulty mechanism is measurable and honest.** Hard mode
  keeps every cell passable (same contracts, keys still ride the
  prompt) but costs real work: 06-hard doubles-to-quadruples codex's
  calls (28-44 vs 12-19) and duration (273-384s vs 48-92s), and
  severity-calibration flags appear exactly where the scaffolding was
  withheld (1 on kali-hard, 2 on ubuntu-hard knowledge cells). The
  verdict bar never moved — the spread did, which is the signal.
- **The claude@kali outage is infrastructure, not agent quality.**
  Attempts 2-3 of the knowledge cell and all four hard-mode attempts
  died in ~1.7s with zero tool calls: the tier router's upstream
  (OpenRouter) exhausted its key credit limit mid-sweep (402,
  "requires more credits, can only afford ~19k tokens"; probe
  reproduced the same on Ubuntu — the key serves both hosts). The
  affected attempts are kept in the records with verbatim reasons and
  named here; the lane re-enters measurement when the operator tops
  the key up (`lab/validation-results.md`). The three claude attempts
  that ran before the outage are clean (06: 3/3, 3-8 calls).

## Records

Per-attempt `report-*.json` + `stderr-*.log` under
`<head-host>/<cell>/`, exactly the layout the summarizer consumes.
