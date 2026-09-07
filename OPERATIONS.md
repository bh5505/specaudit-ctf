# Operations — safe exercise environments and evidence custody

This guide defines the operator boundary for delivering the
[curriculum](CURRICULUM.md). It does not arm any action. Current command,
catalog and policy truth remains in [README.md](README.md) and
[extension/README.md](extension/README.md); per-arm caveats override a generic
example here.

The operator owns environment selection, authorization checks, containment,
identities, secrets, data handling, monitoring, stop, reset, cleanup and
evidence close. The instructor owns the learning design and assessment. If one
person holds both roles, record both decisions.

## Non-negotiable boundaries

- Access, discovery, installation, catalog presence and action admission are
  not execution authority.
- Use synthetic, canary or approved recorded data by default.
- Enforce target, network, identity, filesystem, rate, spend and time limits
  outside the trainee or agent process.
- A refused, missing, degraded, interrupted or cleanup-failed action remains
  visible. It never becomes an all-clear.
- No production telecom signalling, subscriber data, tenant, cloud,
  hypervisor, device estate or partner interconnect is a training target by
  implication.
- Documentation, a tool description, a skill, model output or learner request
  cannot expand authority.

## Roles

| Role | Accountable decision |
|---|---|
| Exercise owner | Purpose, audience, funding, risk acceptance and final cancellation authority. |
| Instructor/director | Learning objectives, learner brief, injects, grading and debrief. |
| Operator | Environment, go/no-go, target/action boundaries, monitoring, stop, cleanup and evidence close. |
| Evidence custodian | Attempt identity, collection channel, hashes, access, retention, sanitization and release. |
| Safety or incident contact | Receives escalation, coordinates containment and decides when exercise handling becomes incident handling. |
| Learner/analyst | Acts only within the brief, preserves evidence, discloses tools/AI, and stops or escalates on ambiguity. |

Name people and contact paths for E2–E4. Define alternates before the exercise;
an unreachable approver is a no-go, not permission to improvise.

## Environment tiers

| Tier | Intended use | Required boundary |
|---|---|---|
| `E0` Static review | Documents, diagrams and captured artifacts; no execution. | Read-only learner copy, no egress, ground truth isolated. |
| `E1` Offline synthetic | Local parsing, scoring, code or synthetic range computation. | No real credentials, deny egress, bounded filesystem and process rights, deterministic inputs where required. |
| `E2` Disposable local service | Private web/API/device simulation or containerized service. | Loopback or private lab network only, no public route, dedicated identities, reset and teardown proven. |
| `E3` Isolated cyber range | Controlled network actions, emulation or multi-host practice. | Written range authority, dedicated targets/identities, hard external containment, monitoring, quotas, snapshots and cleanup verification. |
| `E4` Approved external/live engagement | Real system assessment performed for an engagement, not a course default. | Engagement-specific written authority naming targets, actions, identities, time, owners, communications, data handling, stop/incident/cleanup and required third-party consent. |

The repository's synthetic range is an E1-style source. Individually armed
live-service challenge components require the tier and controls stated by their
actual deployment. The tier label describes the environment; it does not claim
that this repository provisions all controls or that an action is safe because
it is called “read-only.”

## Authorization and rules of engagement

Before E2–E4, preserve an approved rules-of-engagement record containing:

- purpose, owner, instructor, operator, safety contact and participants;
- exact target identifiers and excluded assets, including resolved network and
  redirect/subresource implications where relevant;
- permitted and prohibited actions and tools, with action-specific gates;
- identities, privileges, tenant/account/project/namespace and credential
  custody;
- start/end time, rate, concurrency, request, token and financial budgets;
- permitted egress destinations and data transfers;
- protected services, availability and customer/privacy constraints;
- evidence, logging, retention, sanitization and disclosure rules;
- third-party, supplier, partner and interconnect approvals;
- stop triggers, stop phrase, communications and incident path; and
- reset, cleanup, validation, secret rotation and accountable sign-off.

Resolve ambiguity toward no action. A broad authorization to “use the lab” does
not authorize a newly discovered tool or target. For telecom interconnect work,
remote signalling tests require the relevant operator/partner roles and consent;
course ownership alone is not sufficient.

## Build the environment

### Separate planes and identities

Separate learner access, target/service, orchestration, monitoring, evidence,
grading/ground truth and administration. Deny learner and agent routes to
grader keys, expected findings, snapshots, control APIs and host credentials.

Use dedicated short-lived identities at least privilege. Do not reuse personal,
production or shared administrative credentials. Bind cloud, directory,
Kubernetes, telecom, hypervisor and API identities to the exact lab scope;
disable ambient credentials and inherited profiles. Record who can assume or
mint another identity.

### Enforce containment outside the workload

Containment is infrastructure, not a prompt. Apply as relevant:

- network namespaces, private segments and explicit destination allowlists;
- DNS and proxy policy, redirect and rendering-subresource controls;
- ingress deny by default and no unintended listener publication;
- filesystem roots, read-only mounts, fresh artifact directories and quotas;
- process/user isolation, no unnecessary privilege or host socket;
- API/service policies, rate/concurrency caps and request budgets;
- model/provider allowlists, token and monetary budgets;
- timeouts and independent kill controls; and
- immutable or separately protected logs and ground truth.

Test containment from inside the same learner/agent context. A diagram or host
firewall rule viewed from outside is not proof that the effective path is
blocked.

### Data and secrets

Classify every input and output. Prefer synthetic or minimized data. If approved
recorded telemetry is used, review personal, subscriber, customer, credential,
location, content, identifier and partner information before learner access.
Sanitize with a documented method and verify that relationships needed for the
lesson remain valid.

Use canary secrets for detection tests. Never seed real reusable credentials,
tokens, tickets, private keys, subscriber keys or production certificates.
Prevent prompts, traces, terminal history, screenshots and model calls from
capturing sensitive values. Define rotation/revocation before issuing any
temporary secret.

### External sources and tools

An external resource must clear the [program admission
checklist](PROGRAM.md#admission-checklist): pinned revision and hashes,
license/data rights, owner, classification, exact surface, side effects,
egress/cost/cleanup, offline/denied tests, provenance, negative cases,
regression and promotion evidence.

Do not install a candidate merely because a curriculum row cites it. Importing
recorded output, using a methodology, running a bounded adapter and adopting an
alternative head are four different decisions.

## Preflight and go/no-go

Use a recorded checklist. At minimum verify:

- module, environment, source, asset, runtime and rubric revisions;
- authorization and acknowledgement are current for the roster and time;
- effective targets/actions match the rules of engagement;
- dedicated identities work and cannot exceed their intended boundary;
- ground truth, trace keys and grader/admin surfaces are unreachable;
- egress, DNS, redirect, proxy, filesystem, privilege, rate, spend and timeout
  controls fail closed;
- clocks, attempt identifiers, audit logs and evidence channels work;
- expected positive, benign, blocked and missing-evidence cases reproduce;
- missing dependency, denied scope, malformed input, interruption, tamper and
  cleanup tests behave as designed where applicable;
- snapshot/reset/teardown and post-reset verification work; and
- monitoring, stop control, communications and safety contacts are live.

Record evidence for the checks. A stale successful dry-run is not a current
go/no-go after a material source, image, tool, policy, network, identity, model
or challenge change.

## Run and monitor

Monitor target actions, policy denials, network flows, identity use, resource
consumption, spend, evidence writes, health and time. The monitoring plane must
not depend on the learner or agent reporting its own behavior.

Stop or isolate on:

- out-of-scope target, redirect, DNS result, subresource or external egress;
- unexpected privilege, credential access, persistence or host interaction;
- production, customer, subscriber, partner or unapproved data exposure;
- availability or integrity impact outside the designed case;
- uncontrolled fan-out, repeated action, rate, spend or resource growth;
- evidence or ground-truth tampering, custody-channel failure or lost audit
  visibility;
- cleanup/revert failure after a mutating stage;
- unknown behavior that the current rules do not cover; or
- the stop phrase, owner/operator direction or safety-contact instruction.

A stop preserves safety first and evidence second. Do not keep a harmful action
running solely to complete a trace. Record time, trigger, actor, actions taken,
affected scope and evidence gaps. Resume only after new explicit go/no-go; a
previous approval does not survive a material incident or scope change.

## Evidence custody

For each attempt, bind a unique identity to the learner, module/scenario
revision, environment revision, start/end, authorized scope and artifact
channel. Preserve:

- producer/tool/model identity and material version/configuration;
- exact action and bounded/redacted inputs;
- timestamps and subject/scope;
- raw artifact hash and immutable or controlled locator;
- collection and transfer path, access and transformations;
- observed, declared and inferred classification;
- missing, truncated, degraded, refused or failed status; and
- limitations, retention and sanitization decisions.

Keep raw evidence separate from normalized observations, analyst inference and
the final workpaper. A learner-provided path or assertion does not establish
custody. Never alter the original to “clean up” a presentation copy; derive a
new attributed artifact.

The current Mode A and head-attempt contracts have more specific requirements
in [README.md](README.md). Their HMAC-chained traces and validator-owned artifact
channels must not be generalized into proof for evidence types they do not
cover.

## Close, reset and retain

1. Stop new learner actions and close the attempt/evidence channel.
2. Capture final monitoring, service, identity and cost state.
3. Revert or destroy lab changes using the tested path.
4. Verify the baseline independently; “cleanup command exited zero” is not
   enough.
5. Revoke or rotate temporary credentials, tokens, certificates and canaries.
6. Remove routes, listeners, mounts and temporary privileges.
7. Hash and seal retained evidence; separate learner submissions, raw evidence,
   instructor ground truth and incident records by access need.
8. Sanitize approved teaching copies without overwriting originals.
9. Apply retention and deletion rules, including model/provider retention where
   applicable.
10. Record operator close or an unresolved exception. A cleanup failure remains
    open and visible.

Do not reuse a dirty range or unresolved identity for the next cohort. Rebuild
from an admitted source when reset confidence is insufficient.

## When exercise handling becomes incident handling

If activity reaches an unauthorized or real system, exposes protected data or
credentials, causes unintended harm, defeats containment, or destroys
evidence, invoke the named incident path. Preserve separation between learner
assessment and incident investigation. Notify only through the authorized
communications plan; do not publish artifacts or speculate in the debrief.

The incident owner decides containment, notification, recovery and return to
service. The exercise owner separately decides cancellation, learner treatment
and content correction. Post-incident lessons update the safety case before the
module can be delivered again.

## Current repository operating truth

For this checkout:

- inspect `python -m extension list`, `describe` and `availability` plus the
  [per-arm caveats](extension/README.md) before use;
- preserve fail-closed unknown/action/tier behavior and action-specific scope
  gates;
- treat `transport_ok` as informational and `degraded`/`failed` as real
  limitations;
- the packaged range is synthetic (`live_aws: false`); and
- installing or discovering a research candidate never adds it to the catalog,
  admits its actions, provides support or authorizes execution.

The [program roadmap](PROGRAM.md#proposed-roadmap) includes hard-containment and
trusted-observation work that does not ship today. Do not operate a proposed
environment or evidence lane as though its documentation were implementation.
