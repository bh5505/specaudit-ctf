# Track D dogfood runbook — threat-model this suite's own agentic surface

This is a participant worksheet for Curriculum Track D. It is a
**process exercise graded on analyst reasoning, never on generated
prose**: the deliverable is a structured worksheet whose every claim
cites evidence you actually captured from this repository. There is
no `score/` rubric for this exercise and none should be added — the
grading discipline is defined below and pairs with the `score/`
package's doctrine (grade captured evidence; a skipped or failed
required step is never success) as the same lesson applied to
analyst work instead of tool runs.

Teaching path: **this checkout + Python 3.11+ only.** Nothing here
needs a cloud account, an API key, a model endpoint, or any tool
beyond the repository and its stdlib-only extension. Every command
below is local and read-only unless it says otherwise.

## Why dogfood

Track D teaches agentic threat modeling: reasoning about
non-determinism, autonomy, missing trust boundaries, dynamic identity,
and agent-to-agent interaction — the five factors the CURRICULUM §D
lists. The cheapest honest target is not a toy example but **this
suite's own agentic surface**: a tool server (`python -m extension`,
CLI and stdio MCP) that exposes security-audit capabilities to a
client program that may itself be an agent. You threat-model a system
you can read end to end — and the exercise's honesty rules are the
same ones the suite enforces on its own tool runs.

The teaching model is MAESTRO (the public seven-layer reference
architecture for agentic-system security). The layers, from the
upstream framework:

1. **Foundation models** — the model itself as a component.
2. **Data operations** — ingestion, retrieval, storage feeding the
   agent.
3. **Agent frameworks** — orchestration, tool wiring, plugins.
4. **Deployment & infrastructure** — where the agent runs.
5. **Evaluation & observability** — how behavior is measured and
   logged.
6. **Security & compliance** (vertical) — controls spanning layers.
7. **Agent ecosystem** — identities, delegation, agent-to-agent
   interaction.

## The surfaces to inspect (all in this repo)

- **The stdio MCP server** — `python -m extension` exposes exactly
  four tools (`list`, `describe`, `invoke`, `run_range`) over stdio
  JSON-RPC. Read `extension/mcp_server.py` and `extension/heads/`:
  who is the client, what can the client ask for, and what does the
  server do about requests it cannot vouch for?
- **The dispatch path** — `extension/dispatch.py`, the invoke
  registry (`extension/invoke_profiles.py`), and one arm's scope gate
  (e.g. `extension/arms/nmap/policy.py`). An `invoke` of a
  scope-gated action is refused until the operator arms
  `<ARM>_DISPATCH_SCOPE`; blanket scopes are refused. Ask the
  threat-modeling questions: what does the gate authorize, what does
  it NOT bound (the per-arm caveats in `README.md` say so out loud —
  composite egress, redirects, config-decided targets), and who is
  the "operator" when the client is an agent?
- **The envelope contract** — `capability-manifest.v1` before
  dispatch, `execution-result.v1` after, with `complete` /
  `degraded` / `failed` as the only outcome states. Where could a
  component claim more certainty than it has? (The suite's own rule —
  `ok` is true only for `complete`, and no all-clear it did not
  achieve — is the pattern to check everyone else against.)
- **The transport parity property** — identical logical requests on
  CLI and MCP yield equivalent envelopes. Why does parity matter for
  custody: if two transports disagreed, which one would an auditor
  believe?

Working the exercise: `python -m extension list`, `python -m
extension describe nmap`, and an unarmed `python -m extension invoke
nmap scan '{"target": "127.0.0.1"}'` (a typed refusal, no scan) are
enough to see every piece above behave. Do not arm anything; the
refusals are the evidence you need.

## The worksheet

Produce one entry per MAESTRO layer (1–7). For each layer, two
categories — this split is the exercise's core discipline:

- **Category 1 — traditional:** security threats for that layer that
  exist regardless of agentic factors (a vulnerable dependency, a
  weak config, a leaked secret).
- **Category 2 — agentic:** for each of the five factors
  (non-determinism, autonomy, missing trust boundaries, dynamic
  identity, agent-to-agent interaction), does it introduce a NEW
  threat in this layer of THIS system, or exacerbate a traditional
  one? If a factor does not apply, say so — an honest "does not
  apply here, because …" scores better than an invented threat.

Every entry must carry **evidence**: a file path and line range, a
command you ran and its actual output, or a quoted envelope field.
An entry without evidence is not wrong — it is ungraded. Entries
that cite code that does not exist fail the layer.

Then produce **cross-layer chains**: at least two attack narratives
that cross layer boundaries (e.g. a client-program compromise at the
agent-ecosystem layer reaching a scope-gated dispatch through the
framework layer, or log-forging at observability layer influencing an
evaluator at the security-compliance layer). Each chain names the
layers it crosses and the evidence at each hop.

## Grading (analyst process, never prose)

Three dimensions, in priority order:

1. **Layer coverage** — all seven layers attempted, each with both
   categories, factors explicitly considered or explicitly ruled out.
2. **Split quality** — traditional vs agentic is drawn correctly:
   agentic claims actually involve one of the five factors; a
   repackaged traditional threat is not an agentic one.
3. **Cross-layer chain reasoning** — chains are complete (every hop
   has evidence), plausible against this codebase, and end in a
   concrete impact.

Generated prose is worth nothing: a fluent paragraph with no evidence
scores zero; a terse worksheet row citing real lines scores. This is
the same lesson the `score/` package enforces on tool runs — read
`score/README`-adjacent tests (`tests/test_score.py`) and the two
structural rules (transport success is never a verdict; a skipped or
failed required arm is never success) — here you are the arm, and
your worksheet is your envelope: claims must trace to captured
evidence the way findings must trace to planted violations in the
shipped challenges.
