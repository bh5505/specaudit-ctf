# Challenges — synthetic rehearsal exercises

Each challenge is a self-contained teaching exercise against this
repository's real surface: the catalog, the CLI, the stdio MCP server, and
the synthetic range fixtures. The teaching path needs only **Python 3.11+
and this checkout** (plus, optionally, any agent CLI that speaks stdio MCP
for the attachment exercises). No internal trees, no product binaries, no
live cloud accounts, and no real credentials are involved.

Everything is deterministic per host: the range runs with a fixed seed,
so on a given host the planted violations and the range-report digest
are reproducible byte-for-byte. Arm rows, limitations, and the
range-report digest vary with the host's installed state — the planted
fixture ground truth does not.

| Challenge | Lane | Fixtures |
|---|---|---|
| `telecom-aws-01-reachability/` | AWS reachability rehearsal | `tf_s3_public_access` |
| `telecom-aws-02-iam-s3-misconfig/` | IAM/S3 misconfiguration rehearsal | `tf_iam_open` |
| `telecom-aws-03-iam-privesc/` | IAM privilege-escalation rehearsal | `tf_iam_assume_role`, `tf_iam_external_trust` |
| `telecom-aws-04-network-exposure/` | Network exposure + near-miss discipline | `tf_sg_open_ingress`, `tf_s3_policy_blocked_trap` |
| `telecom-aws-05-logging-gaps/` | Logging/detection-gap rehearsal | `tf_cloudtrail_disabled`, `tf_s3_no_access_logging` |
| `telecom-aws-06-chain-rehearsal/` | Flagship multi-stage chain engagement | `tf_chain_ingress_role`, `tf_iam_open`, `tf_s3_public_access` |
| `lab-web-01-dast-surface/` | Web/DAST live-service rehearsal | lab target (`lab/target/` planted web content) |
| `lab-net-01-service-discovery/` | Network service-discovery live rehearsal | lab target (`lab/target/start-services.sh` planted services) |
| `lab-knowledge-01-attack-mapping/` | AI/knowledge ATT&CK mapping rehearsal | `tf_s3_public_access`, `tf_cloudtrail_disabled`, `tf_iam_open` |
| `lab-edge-01-device-posture/` | Edge-device posture live rehearsal | lab target (`lab/target/` planted device surface) |
| `lab-emu-01-caldera-listings/` | Adversary-emulation listing live rehearsal | caldera stockpile ability catalog (shipped data, v5.3.0) |
| `lab-emu-02-msf-listings/` | Exploitation-framework listing live rehearsal | metasploit framework module catalog (Kali package) |
| `lab-code-01-semgrep-review/` | Static code-review planted rehearsal | `lab-code-01-semgrep-review/planted/app.py` |

Start with `telecom-aws-01-reachability/`; each challenge assumes the
skills of its predecessors. Challenge 06 is the flagship: four graded
stages composing discovery, exposure, and chain reasoning into one
deliverable. Solutions are included (`solution/`) — the exercises are
about producing and defending the deliverables, not about guessing.

## Correspondence contract (all challenges)

Every finding you ship must trace to exactly one planted violation in the
synthetic fixture. A finding you cannot trace is wrong; a planted
violation with no finding is a miss. This is the discipline a real audit
cycle demands of machine-generated deliverables, rehearsed here against
data that cannot lie to you.

## Live-service lanes

Two `lab-*` challenges (the web and network rehearsals) draw their
findings from the **spawned lab target** instead of the synthetic range
(their composed runner runs still record the synthetic range lane; the
graded findings trace to planted target content). Their contracts
declare `lane: live-service` and their findings trace to planted target
content (`lab/target/`), built and read honestly: a directory listing, an
implementation-disclosure header, planted services — real-but-inert by
construction. These lanes grade through the standalone found-vs-expected
lane; the runner's `--arms` envelopes recorded in the same run are the
proof the live reads happened. The evidence-doctrined head-attempt lane
**refuses** live-service contracts by design: its coverage gate verifies
synthetic-range fixture touches, which no live finding can honestly name.
The two lane kinds are never compared as like-for-like matrix cells.
(`lab-knowledge-01-attack-mapping` is lab-family but fixture-backed: it is
a normal graded head-matrix cell.)

## Grading

Every challenge in this family ships an expected-findings contract
(`artifacts/expected-findings.json`; challenge 06 adds per-stage
contracts). Grade yourself:

```
python -m score --grade my-findings.json --expected artifacts/expected-findings.json
```

The verdict passes only on exact coverage — misses, extras, and
evidence-less rows all fail it, and a partial finding set never reads
as all-clear. Severity disagreements are surfaced as flags, not
failures. See `score/grading.py` for the semantics.

## Proposed workpaper alongside the graded finding set

**Proposed, not shipped.** Nothing below changes the grading above:
exact coverage stays the machine verdict, `score/grading.py` stays the
semantics, and no challenge ships a workpaper contract today.

The proposal is a second, human-reviewed deliverable next to
`my-findings.json`: a short workpaper stating the criterion and subject,
the population and period the conclusion covers, observed facts kept
separate from inference, any disconfirming evidence, compensating
controls, the scope left untested, and a recommendation with retest
logic — every material statement citing the evidence it rests on.

The two answer different questions. Exact coverage asks *did you find
the planted violations and nothing else*. The workpaper asks *is the
conclusion defensible* — and a passing finding set with an
unsupportable workpaper is a real failure mode the coverage verdict
cannot see. It would be reviewed by a person, never scored by the exact
grader, and it would not soften or override a coverage failure.
Rationale, artifacts and the human rubric are in the
[curriculum](../CURRICULUM.md#the-workpaper-set). Delivery and custody belong to
the [instructor](../INSTRUCTOR_GUIDE.md) and
[operator](../OPERATIONS.md) guides.

## Authoring contract for new content

This section governs future modules and challenges. It does not change the
status of the 13 shipped challenges above. A draft directory or document is not
shipped until its assets, grading, refusal cases, reset and review evidence all
exist.

### Identity and learning design

Every challenge declares:

- a stable id and title, program-domain mappings, audience, proficiency level
  and status (`shipped`, `design-ready`, `research` or `proposed`);
- versioned learning outcomes and prerequisite tasks, knowledge and skills;
- the exact learner deliverables and how each demonstrates an outcome;
- criteria sources, selected versions, owner and currentness review; and
- dependencies and an accessible equivalent route where the interaction mode
  is not itself the competency.

Choose the outcome before the tool. A candidate resource in
[PROGRAM.md](../PROGRAM.md#candidate-register-42-unique-candidates) is an input
to review, not a package dependency by default.

### Scenario, truth and evidence

Keep the learner story, observable scenario, ground truth and assessment
material separate. The package specifies:

- assets, identities, relationships and time state;
- an evidence manifest with producer/version, time, exact subject/scope, raw
  hash or immutable locator, custody, data class, transformations, limitations
  and observed/declared/inferred classification;
- positive behavior, benign or protected behavior, a negative/inapplicable
  case and an inconclusive/missing-evidence case where relevant;
- compensating controls and changed prerequisites where they are part of the
  intended judgment;
- a learner brief that never exposes the answer key; and
- an instructor key explaining what is known, what is not knowable from the
  supplied evidence and which alternate conclusions can be supported.

Expected findings, trace keys, hidden labels, snapshots and rubric anchors must
be unreachable from the learner, target and agent context. Prove the separation
with a refusal or canary test rather than relying on directory names.

### Environment and safety case

Declare the [environment tier](../OPERATIONS.md#environment-tiers), target
boundary, permitted and prohibited actions, identities/privileges, data class,
egress and cost limits, time/rate/concurrency, stop triggers, monitoring,
reset/cleanup and retention. The operator must be able to enforce these outside
the learner or agent.

No package grants authority over a real target. An E3 or E4 delivery needs its
own written rules of engagement and go/no-go. Any external resource must pass
the [admission checklist](../PROGRAM.md#admission-checklist) before it is
bundled, imported or executed.

### Assessment package

Ship together:

- the learner brief and submission schema;
- machine expected-results contract where exact grading applies;
- human rubric and anchored examples where a workpaper applies;
- hint/inject schedule with its scoring effect;
- instructor key and adjudication notes outside learner reach; and
- versioned calibration evidence.

Machine and human verdicts remain distinct. Hard failures include unauthorized
or unsafe action, answer-key access, fabricated/tampered/replayed evidence,
material custody failure, concealed scope expansion and an unsupported
all-clear after required evidence is missing.

### Validation and promotion

Validate the normal path and the cases that can create false assurance. As
applicable, the matrix includes:

- expected positive, benign, blocked, negative and inconclusive outcomes;
- missing tool, source, permission, log or datasource;
- malformed or hostile input, out-of-scope target and denied egress;
- timeout, interruption, partial result and resource limit;
- stale version, changed prerequisite and repeated/replayed attempt;
- answer-key or evidence-tampering attempt; and
- cleanup/revert failure and independent reset verification.

Promotion requires named technical, safety/operator and instructional
reviewers; a successful learner-path dry-run; tested reset and stop controls;
known limitations; owner and supported versions; and a maintenance/retirement
trigger. Revalidate after any material criteria, asset, dependency, tool,
policy, environment, model or rubric change.
