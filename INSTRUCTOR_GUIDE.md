# Instructor guide — design, delivery and assessment

This guide is for instructors, exercise directors and challenge authors using
the [SpecAudit-CTF curriculum](CURRICULUM.md). It describes a complete delivery
and quality system. It does not make proposed modules runnable, admit an
external resource, or authorize a lab action.

The instructor owns learning integrity. The [operator](OPERATIONS.md) owns the
environment and go/no-go. Those roles may be held by one person in a small
exercise, but their decisions remain explicit: educational value cannot waive
containment, and technical availability cannot redefine the learning outcome.

## Start with the outcome

Choose the audit judgment or technical capability the learner must demonstrate
before choosing a tool or scenario. A module plan records:

- audience, proficiency level, prerequisites and versioned learning outcomes;
- the program module and, where useful, NICE task/knowledge/skill mappings;
- criteria and the exact source revision used;
- the scenario, evidence classes, expected artifacts and grading method;
- positive behavior, a benign or protected case, and a negative or
  inconclusive case;
- environment tier, permitted and prohibited actions, data class, egress/cost,
  stop conditions, reset and retention;
- accessibility needs and an equivalent participation route; and
- owner, reviewers, dry-run evidence, currency review and retirement trigger.

A CTF flag can be an intermediate check. The final learning outcome is the
quality and limits of the conclusion supported by the evidence.

## Select the least hazardous delivery form

Use the lowest [environment tier](OPERATIONS.md#environment-tiers) that can
demonstrate the outcome:

1. discussion, architecture or static evidence review at E0;
2. offline synthetic analysis at E1;
3. a disposable private local service at E2;
4. an isolated monitored range at E3 only when the outcome requires action;
5. E4 only for a separately authorized real engagement, never because a course
   plan mentions a live technology.

Recorded telemetry, inert definitions and synthetic graphs are often better
teaching material than a live executor. They allow the learner to evaluate
provenance, applicability, missing data and false explanations without hiding
the lesson behind installation or unsafe access.

## Readiness and pathways

Before a cohort starts, use a short diagnostic rather than assuming a job title
equals readiness. Check whether learners can:

- state the difference between access and authority;
- read the relevant architecture and identify assets/trust boundaries;
- distinguish criterion, condition, observation, declaration and inference;
- reproduce a basic command or artifact check and preserve its provenance;
- explain why a missing tool, log or datasource is not an all-clear; and
- write a bounded conclusion that names untested scope.

Route gaps to the `FND-*` or `AUD-*` foundation modules. Do not solve a
readiness gap by leaking the answer key or removing the negative control.

For team exercises, name at least the analyst, evidence custodian and reviewer.
Advanced and capstone exercises may also name engagement lead, technical
specialists, business/control owner and incident/communications roles. Make
handoffs and decision authority part of the observed performance.

## Protect learning and ground truth

Keep four layers separate:

- **Learner brief:** objectives, scope, rules, permitted resources and required
  deliverables.
- **Scenario surface:** assets, events, management statements and injects the
  learner may observe.
- **Ground truth:** planted conditions, benign protections, missing evidence,
  expected relationships and acceptable alternate conclusions.
- **Assessment material:** machine contracts, human rubric, calibration
  examples, trace keys and adjudication notes.

Ground truth and assessment material must be outside learner, agent and target
reach. Do not place an answer key in model context, a shared filesystem, a
public image layer, shell history or an artifact location the learner can list.
Use canaries and refusal tests to prove separation before delivery.

The scenario story may contain incomplete, mistaken or conflicting claims;
those are teaching inputs. The instructor key states what is actually known,
what remains unknowable from the supplied evidence and which alternate
explanations are supportable.

## Build evidence before prose

Each exercise starts with an evidence manifest, not a narrative. For every
artifact record the producer, selected version, collection or generation time,
subject and scope, raw hash or immutable locator, custody, data class, permitted
learner use, observed/declared/inferred status, limitations and ground-truth
relationship.

Include cases that discriminate judgment:

- a true condition with sufficient evidence;
- expected secure or benign behavior;
- a plausible but inapplicable or blocked condition;
- incomplete evidence requiring a bounded inconclusive answer; and
- where relevant, changed prerequisites for a retest.

Avoid trick questions whose only distinction is undocumented instructor
intent. The evidence should support why one conclusion is better.

## Reconnaissance exercise preparation

For the [asset reconnaissance worksheet](docs/scope-recon.md#offline-analyst-exercise),
freeze a synthetic provider packet and its hashes, seed/exclusion policy,
checkout revision and limits. Include corroborated and shared-service cases,
stale and wildcard CT, misleading PTR, an excluded starting IP and missing
evidence. Dry-run with egress denied and all provider/probe grants unset.
Keep expected conclusions outside learner reach; grade the cited paths,
rejected hypotheses and honest partial coverage. A high association confidence
or a large host count earns no automatic credit. Use the capability guide's
single procedure and rubric mapping; any optional disposable-service observation
requires a new operator decision and never inherits a discovered target list.

## Run of show

### Plan and dry-run

1. Freeze the module, source and asset revisions.
2. Have a technical reviewer validate the facts and expected telemetry.
3. Have a safety/operator reviewer validate containment, identities, data,
   monitoring, stop and cleanup.
4. Have an instructional reviewer check outcome alignment, workload,
   accessibility and rubric discrimination.
5. Run the learner path without privileged knowledge, then the negative,
   missing-dependency, out-of-scope, interruption, tamper and cleanup cases that
   apply.
6. Record timing ranges and hints; do not rewrite the objective to fit a tool's
   accidental output.

### Go/no-go and briefing

The operator performs the technical go/no-go. The instructor confirms the
module revision, roster/readiness, roles, accessible alternatives, assessment
rules and ground-truth isolation. Brief learners on:

- objectives and what is outside assessment;
- exact targets, identities, permitted actions, time and cost boundaries;
- evidence and submission channels;
- AI/tool-use disclosure;
- stop phrase, emergency contact and what happens after a stop; and
- how hints, extensions, collaboration and appeals affect assessment.

Require an affirmative acknowledgement. A generic course enrollment is not
agreement to new technical actions.

### Play and facilitate

Observe decisions and evidence handling, not only terminal output. Injects and
hints should restore progress toward the outcome, not reveal flags. Log the
time, recipient and assessment effect of each hint.

Do not coach learners into reporting every suspicious signal. Ask questions
that expose reasoning: What would disprove this? Which population and period
does this observation cover? Is the control merely configured or did it
operate? What data should exist? What remains untested?

The operator may stop the environment at any time. The instructor may pause for
learning integrity, but may not ask the operator to waive an action, target,
identity, egress, data or safety boundary.

### Close and debrief

Stop actions at the declared time, close evidence channels, preserve the
attempt, and let the operator verify cleanup. Debrief only after assessment
artifacts are protected.

A useful debrief reconstructs the reasoning path:

1. scope and criteria;
2. observations and custody;
3. competing hypotheses and discriminating tests;
4. benign, blocked and missing-evidence cases;
5. control and business consequence;
6. conclusion, recommendation and retest; and
7. what the learner, scenario, rubric and environment should improve.

Do not reduce the debrief to the answer list. Publish reusable lessons only
after sanitization and rights review; do not disclose held-out ground truth.

## Assessment

### Two verdicts, two purposes

For current challenges, the machine grader decides exact finding coverage:
misses, extras and evidence-less rows fail; severity differences are flags.
That verdict remains unchanged.

The human workpaper review asks whether the learner's conclusion is defensible.
It is separate and cannot override machine failure. Conversely, a perfect
finding set does not rescue a fabricated citation, unsupported all-clear or
unsafe action.

### Hard gates

Fail or stop assessment on:

- unauthorized target, action, identity, scope expansion or safety breach;
- answer-key or trace-secret access;
- fabricated, tampered, replayed or unrelated evidence;
- concealed material custody failure;
- deliberate bypass of containment or cleanup; or
- an unsupported all-clear when required evidence is absent.

Distinguish a learner mistake from an exercise-control failure in the incident
record, but do not award a passing outcome that depends on either.

### Human rubric

After hard gates, use the dimensions in the curriculum: scope/criteria,
procedure/reproducibility, evidence/custody, analysis/disconfirmation,
risk/compensating controls, and communication/recommendation/retest. The
10/15/25/20/15/15 allocation is a starting point, not an external standard.

Each performance level needs an anchored example. Examples should include an
excellent supported non-finding and excellent inconclusive work—not only strong
positive findings. Reward a justified rejection of a plausible false claim
more than confident unsupported reporting.

### Calibration and adjudication

- Double-score a representative sample before a new rubric is used for a
  consequential decision.
- Compare dimension-level disagreements, revise anchors, then rescore the
  calibration sample.
- Keep the original and adjusted scores with reviewer identity and rationale.
- Recalibrate after material source, asset, rubric, model or environment change.
- Resolve learner appeals from the preserved brief, attempt, evidence and
  rubric—not from memory or a regenerated model answer.

Do not compare unlike lanes, assisted with unassisted attempts, tuned with
first-pass attempts, or public/saturated cases with held-out cases as though
they measured the same thing.

## AI-assisted work

AI assistance is allowed only as the module declares. Require an AI-use record
that names the actual model/provider and material configuration, permitted tool
authority, data sent, retained output as policy permits, human verification and
rejected suggestions.

Treat retrieved text, skill instructions, tool descriptions and model output as
untrusted inputs. The learner remains accountable for scope, evidence and the
conclusion. A “local” model label is not evidence of no egress, and a model
serving alias is not enough for a reproducible comparison.

Change heads or models only when that variable is part of the study. Hold the
scenario, permitted capabilities, budget and grader constant; retain every
attempt; separate initial, assisted, tuned and held-out results. Model ranking
is never the learning-program outcome.

## Accessibility and fair participation

Publish the required interaction modes, sensory demands, time pressure and
tooling before enrollment. Provide equivalent routes such as static packet
analysis for a command-heavy action, textual descriptions for diagrams,
keyboard-operable interfaces, accessible formats and additional time where it
does not change the competency being measured.

Do not make speed, typing fluency, familiarity with one shell or ability to use
an external paid model an accidental prerequisite. Record accommodations
without exposing private learner information to peers, tools or model prompts.

## Evaluate the program, not just attempts

Keep separate measures for:

- participation and completion with reasons for withdrawal;
- learning: artifact quality and pre/post performance on the same capability;
- transfer: later independent reperformance or work-sample quality;
- safety and operations: stops, boundary refusals, cleanup and custody events;
- fairness and accessibility: outcome differences and accommodation efficacy;
- content quality: item discrimination, false ambiguity and instructor burden;
  and
- currency: overdue source, asset, dependency and criteria reviews.

Do not optimize pass rate in isolation. A rising pass rate caused by leaked
answers, repeated public cases or weaker negative controls is program damage,
not improvement.

## Maintain, revise and retire

The module owner periodically checks criteria versions, threat assumptions,
assets and labels, rights, dependencies, environment controls, expected
telemetry, rubric anchors and links. A change that can alter the answer or
safety case requires revalidation and, where relevant, recalibration.

Deprecate or retire a module when its criteria are withdrawn, assets cannot be
used lawfully, the environment cannot be contained, public solution knowledge
destroys assessment validity, or no owner will maintain it. Historical or
saturated cases may remain clearly labelled teaching/regression material; they
must not silently stay in a comparative holdout.

The [authoring contract](challenges/README.md#authoring-contract-for-new-content)
is the promotion checklist. The [program roadmap](PROGRAM.md#proposed-roadmap)
defines prerequisite work; prose alone does not move an item to shipped.
