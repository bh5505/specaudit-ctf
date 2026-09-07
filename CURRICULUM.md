# Curriculum — evidence-led cybersecurity audit practice

This curriculum serves two truths at once. Tracks A–D and the challenge assets
listed below are **shipped** in this repository. The larger module map and
T01–T08 seed packs define the learning program being built; unless explicitly
labelled shipped, they are **design-ready**, **research**, or **proposed** and
cannot be run merely because they are documented.

The course outcome is not tool familiarity or a flag count. A learner must be
able to plan bounded work, collect trustworthy observations, test competing
explanations, and communicate the conclusion an internal auditor can actually
support. The canonical architecture and source map are in
[PROGRAM.md](PROGRAM.md); safe delivery is governed by
[OPERATIONS.md](OPERATIONS.md).

## Choose a pathway

All pathways begin with safety, architecture and evidence. They share modules
rather than creating separate versions of the same lesson.

| Pathway | Core route | Demonstrated outcome |
|---|---|---|
| Cyber-audit foundation | `FND-01`–`03`, `AUD-01`–`04`, `CYB-11`, `CAP-IA` | Plan, perform, document and defend a scoped cybersecurity assurance engagement. |
| Technical assessor | Foundations and audit practice, `CYB-01`–`10`, `CAP-IA` | Reperform and correlate bounded technical tests without turning tool output into unsupported assurance. |
| Telecom cybersecurity specialist | Foundations and audit practice, relevant `CYB-*`, `TEL-01`–`09`, `CAP-TEL` | Assess telecom architecture and control evidence across subscriber, core, interconnect, RAN, telco-cloud, API, edge, fraud and resilience layers. |
| Instructor and challenge author | Cyber-audit foundation plus selected domain modules and the [instructor guide](INSTRUCTOR_GUIDE.md) | Design, deliver, calibrate and maintain safe evidence-led exercises. |
| Lab operator | `FND-01`, `FND-03`, relevant domain modules and [operations](OPERATIONS.md) | Provision, contain, monitor, stop, reset and close an exercise with defensible custody. |

No pathway is a professional certification. A module may map its outcomes to a
versioned NICE task, knowledge or skill statement, but completing a CTF does
not establish an entire work role.

## Progression

- **Foundation** — explain boundaries, recognize trustworthy evidence and
  interpret supplied artifacts.
- **Practitioner** — perform a bounded procedure, preserve evidence and justify
  a scoped positive, negative or inconclusive conclusion.
- **Advanced** — correlate layers, select a discriminating next test, evaluate
  compensating controls and business impact, and manage ambiguity.
- **Capstone** — plan and deliver an end-to-end engagement under safety,
  evidence, time and communication constraints; defend and revise the result.

Progress is demonstrated in retained artifacts. Attendance, a successful tool
call, a fluent report and a high model score are not substitutes.

## What ships in this checkout

The shipped path needs Python 3.11+, this checkout, the `extension` package,
its CLI and stdio MCP server, and the synthetic range fixtures. The separately
armed lab-service challenges have their own stated dependencies. No internal
tooling, product binaries, live cloud account or real credential is required
by the synthetic path. This documentation does not install scanners.

The six telecom/AWS challenges exercise the shipped tracks end to end:
`telecom-aws-01` and `-02` teach envelope reading and correspondence; `-03`
through `-05` drill identity escalation, network exposure with a blocked near
miss, and detection gaps; `-06` is the flagship four-stage chain engagement.
The additional web, network, ATT&CK-knowledge, edge, emulation-listing and code
review challenges are catalogued in [challenges/README.md](challenges/README.md).

### A — Extension fundamentals — shipped

- Distinguish arms, methodology-only rows and survey rows. Catalog presence is
  coverage information, not a support promise.
- Read the `research`, `experimental`, `maintained` and `held` support tiers.
  Promotion to maintained is evidence-gated, never a bulk edit.
- Interpret `capability-manifest.v1` before dispatch and
  `execution-result.v1` afterward. `complete`, `degraded` and `failed` are the
  outcome states; `ok` is true only for `complete`.
- Use the CLI and four stdio MCP tools through their shared dispatch authority;
  equivalent logical requests produce equivalent envelopes.

### B — AWS posture in the telecom rehearsal — shipped

- Read IAM principals, policies and trust boundaries in synthetic
  infrastructure code.
- Evaluate S3 policies, ACLs and public-access blocks.
- Trace exposure, path and impact to a planted condition. Every submitted
  finding must correspond to evidence in the fixture.

This is a cloud rehearsal with telecom framing. It is not current coverage of
subscriber identity, 5G core, interconnect, RAN, telco cloud, OSS/BSS, network
APIs, fraud or telecom resilience.

### C — Working with a validation client — shipped

- Use read-only observation, attempt identities and artifact handoff without
  confusing a child-produced claim with validator custody.
- Interpret honest degradation and refuse to turn missing optional capability
  into an all-clear.
- Grade captured `execution-result.v1` envelopes with `python -m score`.
  Transport success is never a verdict; a skipped or failed required arm is
  never success.

### D — Agentic security practice — shipped

- Attach the extension to an existing stdio-MCP-capable head and reason about
  the difference between `invoke` and `run_range` authority.
- Threat-model non-determinism, autonomy, identity and trust boundaries at the
  agent/tool/evidence seams.
- Use the [track-D dogfood worksheet](docs/track-d-dogfood.md) to perform a
  MAESTRO layer-by-layer review of this suite's MCP, dispatch and envelope
  surfaces. It grades analyst process and evidence, never generated prose, and
  is not a `score/` rubric challenge.

## Complete module map

The module definitions live in [PROGRAM.md](PROGRAM.md#program-architecture).
This table shows the honest relationship between shipped anchors and the full
target curriculum. “Design-ready” means a blueprint exists below; it does not
mean a runnable package exists.

| Program area | Current shipped anchor | Target content status |
|---|---|---|
| `FND-01`–`03` safety, architecture and evidence | Tracks A, C and D; current runtime and grading boundaries | Design-ready as a coherent foundation sequence |
| `AUD-01`–`04` engagement, controls, findings and workpapers | Correspondence and exact grading supply a narrow evidence discipline | Design-ready through T01; no complete audit-engagement package ships |
| `CYB-01` asset/network/configuration | `lab-net-01`, `lab-edge-01`, telecom/AWS exposure cases | Design-ready through T02/T08; target domain is broader |
| `CYB-02` identity and access | `telecom-aws-03` identity-path precursor | Design-ready through T05; AD/GPO/consent assets do not ship |
| `CYB-03` cloud and platform | Telecom/AWS sequence; local Checkov/range surfaces under current gates | Design-ready through T02/T08; no live cloud implied |
| `CYB-04` web/API/mobile/software | `lab-web-01`, `lab-code-01`; current Semgrep/ZAP/Burp surfaces under their gates | Design-ready through T06; full SDLC/API/mobile content remains proposed |
| `CYB-05` vulnerability/exposure | Asset/version and near-miss reasoning in existing fixtures | Design-ready through T03; frozen vulnerability corpus does not ship |
| `CYB-06` detection/IR/DFIR | `telecom-aws-05/-06` and captured grading evidence | Design-ready through T04; recorded telemetry and forensic corpus do not ship |
| `CYB-07` threat-informed validation | `lab-knowledge-01`; Caldera and Metasploit **listing** exercises | Proposed beyond current mapping/listing practice; no emulation execution claim |
| `CYB-08` data/privacy/cryptography | Evidence-custody boundaries only | Proposed |
| `CYB-09` third-party/supply chain | Source-pinning and admission concepts only | Proposed |
| `CYB-10` AI/agent/MCP assurance | Track D and current head/MCP boundaries | Design-ready through T07; external agent resources are not bundled |
| `CYB-11` governance/monitoring | Support tiers, admission and promotion discipline | Proposed as an assurance module |
| `TEL-01`–`09` telecom specialization | Telecom/AWS framing and `lab-edge-01` only | Design-ready through the blueprints below; new governed cases are not shipped |
| `CAP-IA` internal-audit capstone | `telecom-aws-06` is a technical chain precursor | Design-ready outcome; full engagement package not shipped |
| `CAP-TEL` telecom capstone | No full-stack shipped anchor | Design-ready below; full engagement package not shipped |

## Proposed T01–T08 release-wave seed packs

These eight **design-ready** blueprints are the first content wave derived from
the research register. They are not the ceiling of the program and they do not
ship a pack, fixture, importer, grader or external material. Each must pass the
[authoring contract](challenges/README.md#authoring-contract-for-new-content),
source admission and operator safety review before promotion.

### T01 — Audit evidence and AI skepticism

- **Maps to:** `FND-03`, `AUD-01`–`04`, `CYB-10`; Foundation to Practitioner.
- **Outcome:** distinguish transport or execution success, an observation, a
  declaration, an inference and a supportable audit conclusion.
- **Sources/direction:** current envelopes and traces; IIA engagement standards,
  NIST SP 800-53A and NICE; R15, R28, R41 and S01–S03 after their gates.
- **Scenario/evidence:** a synthetic packet with incomplete coverage,
  conflicting management statements, one plausible unsupported claim and an
  instructor-held answer key.
- **Controls:** a valid tool response with missing required coverage; a fluent
  report with no observation; an honestly supported non-finding.
- **Deliverable:** scope and criteria, evidence index, hypothesis ledger,
  control test sheet, workpaper, limitations, AI-use record and reviewer
  response.
- **Assessment:** evidence/custody and safety hard gates plus human workpaper
  review. Unsupported all-clear statements fail.
- **Environment/dependencies:** E0/E1 offline; no external credentials.

### T02 — Cloud control and detection chain

- **Maps to:** `CYB-01`, `CYB-03`, `CYB-06`; Foundation to Advanced.
- **Outcome:** trace an IAM or network condition through preventive controls,
  expected telemetry, detection and accountable response.
- **Sources/direction:** current telecom/AWS fixtures; CSA CCM, NIST control
  assessment; inert selected Leonidas/Detection in the Cloud definitions from
  R33/R34 only after review.
- **Scenario/evidence:** synthetic Terraform, asset/connectivity data, authored
  CloudTrail-style events, rule prerequisites and control-operation records.
- **Controls:** a public-looking policy blocked by an effective control; a rule
  present while its required logs are absent; a correctly functioning control.
- **Deliverable:** control test sheet, attack-path rationale, evidence-linked
  detection conclusion, recommendation and retest plan.
- **Assessment:** retain exact planted-condition grading for current fixtures;
  separately review design versus operation over the stated period.
- **Environment/dependencies:** E1 offline; no cloud credentials or deployment;
  requires T01 workpaper discipline.

### T03 — Risk-based vulnerability prioritization

- **Maps to:** `CYB-01`, `CYB-05`, `AUD-03`; Practitioner.
- **Outcome:** keep affected-version applicability, reachability, CVSS severity,
  KEV evidence, EPSS probability and organizational impact separate.
- **Sources/direction:** frozen CVE/KEV/EPSS material and a bounded local R01
  lookup only after `EVID-01`, `GOV-01` and `DATA-01`.
- **Scenario/evidence:** synthetic asset versions and exposure, an approved
  exception, a stale source and incomplete enrichment.
- **Controls:** a severe CVE on an unaffected build; absent exploit enrichment;
  a compensating control that changes consequence but not the underlying fact.
- **Deliverable:** applicability record, prioritized findings or supported
  non-findings, exception analysis and targeted evidence requests.
- **Assessment:** correct applicability and uncertainty outrank opaque scoring;
  missing enrichment cannot become “not exploitable.”
- **Environment/dependencies:** E1, read-only and denied-egress; T01 required.

### T04 — Detection assurance and forensic triage

- **Maps to:** `CYB-06`, `CYB-07`; Practitioner to Advanced.
- **Outcome:** distinguish a rule, collection, analytic execution, alert, triage,
  response and recovery; preserve a justified inconclusive answer.
- **Sources/direction:** current logging challenges; ATT&CK Detection Strategies,
  NIST SP 800-61 Rev. 3; R23/R43 and S07/S08/S12 after rights, label and
  provenance review.
- **Scenario/evidence:** pinned local rules, permitted recorded telemetry,
  synthetic response records and instructor-reviewed labels.
- **Controls:** legitimate administration that matches a rule; required
  telemetry absent; a true event correctly handled.
- **Deliverable:** evidence timeline, triage record, rule/telemetry/control map,
  response assessment and bounded conclusion.
- **Assessment:** critical misses, unnecessary review burden, evidence support
  and justified abstention remain separate measures.
- **Environment/dependencies:** E0/E1 replay; no malware execution or live
  indicator visits; T01 and evidence bridge required.

### T05 — AD, Group Policy and application consent

- **Maps to:** `CYB-02`, `CYB-08`; Practitioner to Advanced.
- **Outcome:** distinguish configured rights, graph hypotheses, applicable
  policy and demonstrated access; verify permission and response claims against
  the authoritative API owner.
- **Sources/direction:** sanitized/synthetic R02, R08, R25, R36 and R38 patterns
  with S11; NIST digital identity; no default live adapters.
- **Scenario/evidence:** synthetic directory graph, GPO files, filter and
  endpoint evidence, session age, and M365 consent/API records.
- **Controls:** filtered-out GPO, stale session edge, missing datasource, and
  read authority misreported as send authority.
- **Deliverable:** evidence-linked path, applicability/prerequisite table,
  missing-data register, path-breaking controls and safe validation plan.
- **Assessment:** inferred edges never score as demonstrated compromise;
  prerequisite and limitation accuracy are central.
- **Environment/dependencies:** E0/E1, no real hashes, tickets, tokens, tenant or
  mailbox; any future live directory lab is a separate E3 decision.

### T06 — Web, API and code review

- **Maps to:** `CYB-04`, `CYB-05`; Foundation to Advanced.
- **Outcome:** pair a versioned requirement with a specific procedure and
  evidence; falsify unsupported scanner or model suggestions.
- **Sources/direction:** current Semgrep/ZAP/Burp lanes under their gates; OWASP
  ASVS 5.0.0, versioned WSTG, API Security Top 10 and NIST SP 800-228; selected
  S05/S06 cases and bounded R14/R29/R40 patterns after review.
- **Scenario/evidence:** paired vulnerable/fixed or unreachable code, a private
  disposable web target, two identity contexts and recorded HTTP evidence.
- **Controls:** suspicious but unreachable code, denied request demonstrating
  protection, and a changed authentication prerequisite making retest
  inconclusive.
- **Deliverable:** criteria-to-test matrix, request/code evidence, hypothesis
  ledger, finding or supported rejection, and remediation verification.
- **Assessment:** tool flags never decide the verdict; technical proof and
  negative-case reasoning are reviewed together.
- **Environment/dependencies:** code in E1; web target in E2/E3 with explicit
  arming, target scope, reset and no public demo scanning.

### T07 — Agent and MCP governance

- **Maps to:** `CYB-10`, `CYB-09`, `CYB-11`; Practitioner to Advanced.
- **Outcome:** trace authority, identity, untrusted instructions, token/secret
  flow, egress, cost, memory, evidence ownership and human accountability.
- **Sources/direction:** Track D and current custody/dispatch boundaries; NIST AI
  RMF/GenAI profile, MITRE ATLAS, OWASP Agentic 2026 and current MCP security;
  sanitized R07/R16/R35 patterns after their gates.
- **Scenario/evidence:** toy MCP/skill configurations, malicious-looking source
  text, denied tools, canary secrets and fabricated-success claims.
- **Controls:** a tool description requests new authority; a “local” label hides
  remote egress; quarantine would mutate evidence; a deny is correctly enforced.
- **Deliverable:** system/data-flow and threat models, authority matrix,
  observed control tests, AI-use record, residual risk and accountable review.
- **Assessment:** no scope escalation or answer-key access; mechanism-level
  evidence beats generic trust scores.
- **Environment/dependencies:** static E0/E1 first; no real secrets; model calls
  are separately approved, attributable and budgeted.

### T08 — Virtualization and edge-device assurance

- **Maps to:** `CYB-01`, `CYB-03`, `TEL-06`, `TEL-08`; Advanced.
- **Outcome:** reconcile deployed version, configuration, management-plane
  reachability, privilege, change and expected telemetry.
- **Sources/direction:** current `lab-edge-01`; recorded Virtual//Attack R32
  patterns and bounded R14 discovery patterns after review.
- **Scenario/evidence:** synthetic platform logs/configuration, appliance build
  evidence and declared-versus-observed topology.
- **Controls:** CVE for a different build, an inferred route blocked in
  operation, and required virtualization logs not collected.
- **Deliverable:** version/applicability matrix, evidence-linked topology,
  control assessment, residual gaps and remediation/retest plan.
- **Assessment:** observed and inferred edges remain visually and semantically
  distinct; missing telemetry remains inconclusive.
- **Environment/dependencies:** E0/E1 recorded evidence by default; no production
  device or hypervisor action; any active private target requires E3 authority.

## Telecom specialization — design-ready blueprints

These specifications complete the curriculum design for `TEL-01`–`TEL-09`.
They are **design-ready, not shipped**: the repository contains no 4G/5G core,
signalling interconnect, RAN, production OSS/BSS, subscriber system or telecom
cloud. Authors must pin the applicable operator architecture, 3GPP Release,
source versions and jurisdiction when turning a blueprint into a case.

The safe default is correlated static configuration, recorded telemetry and
synthetic service state. A live telecom system is never needed to demonstrate
the learning outcome.

### TEL-01 — Telecom architecture and governance

- **Outcome:** define the service, asset, supplier and data boundary across
  subscriber, device, access, transport, core, interconnect, telco-cloud,
  exposure and operations layers; turn the threat and risk model into scoped
  assurance procedures.
- **Criteria/source direction:** selected releases of 3GPP security
  architecture, GSMA FS.40, ENISA 5G controls, NIST CSWP 36 and applicable
  governance, privacy, resilience and internal-audit criteria.
- **Case/evidence:** inconsistent logical and deployed architecture, asset and
  network-function inventories, trust-zone/data-flow diagrams, supplier
  responsibilities, risk decisions, exceptions and control ownership.
- **Discriminating controls:** a declared interface absent from observed
  inventory, an observed dependency missing from the diagram, and an expired
  exception whose control still operates.
- **Deliverable/safety:** scoped architecture and responsibility model,
  criteria/applicability record, risk-control work program and evidence gaps;
  E0/E1 only, with no discovery against an operator network.

### TEL-02 — Subscriber identity and eSIM

- **Outcome:** assess identity and key lifecycle from onboarding and remote
  provisioning through authentication, temporary/concealed identifiers,
  profile change, recovery, revocation and fraud monitoring.
- **Criteria/source direction:** the chosen 3GPP security architecture plus
  the applicable GSMA consumer or IoT eSIM architecture/specification set and
  operator identity, key-custody, privacy and fraud controls.
- **Case/evidence:** synthetic UICC/eUICC and subscription inventories,
  provisioning events, role/approval records, key-management declarations,
  authentication traces, identifier exposure and SIM-swap or account-recovery
  signals.
- **Discriminating controls:** an authorized profile change, a stale identity
  record with no effective access, a missing audit event, and a management
  claim that cannot be verified without protected key material.
- **Deliverable/safety:** lifecycle/control matrix, exception and fraud path,
  privacy-aware evidence index and bounded conclusion; no real IMSI/SUPI,
  profile, activation code, subscriber key or provisioning endpoint.

### TEL-03 — Mobile core, service-based architecture and slicing

- **Outcome:** evaluate network-function identity, discovery, service
  authorization and transport protection; plane separation; slice/tenant
  isolation; roaming-edge protection; management controls and telemetry.
- **Criteria/source direction:** the selected 3GPP Release of TS 33.501 and
  applicable 33.5xx SCAS, GSMA 5G guidance, ENISA controls and NIST 5G
  capability guidance.
- **Case/evidence:** synthetic NF inventory and certificates, service and
  discovery policy, slice mappings, routing/segmentation state, SEPP/N32
  records, change history and security events.
- **Discriminating controls:** a permissive-looking declaration blocked by an
  effective policy, a valid certificate for the wrong service identity, an
  unobserved cross-slice path, and absent telemetry that prevents an all-clear.
- **Deliverable/safety:** trust-boundary model, criteria-to-procedure matrix,
  evidence-linked isolation and service-authorization results, residual risk
  and retest; simulation or recorded evidence only unless a dedicated E3 range
  is separately authorized.

### TEL-04 — Interconnect and roaming

- **Outcome:** assess SS7/SIGTRAN, Diameter, GTP, IPX/GRX and applicable
  SIP/RCS/SMS trust, filtering, routing, partner onboarding, key/certificate,
  fraud, monitoring and incident controls without treating one protocol in
  isolation.
- **Criteria/source direction:** the applicable GSMA interworking-security
  guidance, selected 3GPP security specifications, operator roaming agreements
  and approved service/fraud requirements.
- **Case/evidence:** synthetic partner and route inventory, signalling-firewall
  policies, allow/deny events, protocol correlation, change/exception records,
  fraud cases and incident handoffs.
- **Discriminating controls:** an apparent malicious pattern generated by an
  approved test partner, a blocked request with no alert, a partner removed
  from contract but left in policy, and an event visible in only one protocol.
- **Deliverable/safety:** partner/control matrix, correlated event timeline,
  rule-effectiveness assessment and response/retest plan; no public or
  production signalling and no remote interconnect test without every affected
  operator/partner approval.

### TEL-05 — RAN and O-RAN

- **Outcome:** assess RU/DU/CU, transport, O-Cloud, SMO, non-RT/near-RT RIC,
  xApp/rApp, interface, component and supplier trust; management-plane and
  telemetry controls; and separation of safety, availability and security.
- **Criteria/source direction:** current applicable O-RAN Alliance security
  specifications, selected 3GPP security and SCAS material, NESAS and
  organization-specific PKI, zero-trust, supply-chain and radio-operations
  criteria.
- **Case/evidence:** synthetic component/software inventory, interface and
  certificate records, app onboarding/signing evidence, O-Cloud policy,
  management access, telemetry and supplier assurance packages.
- **Discriminating controls:** a signed but over-privileged app, a trusted
  component with an unsupported version, an interface claimed to use mTLS but
  lacking observed negotiation evidence, and a management path blocked in
  operation.
- **Deliverable/safety:** component/trust inventory, interface-control tests,
  app/supplier risk assessment and evidence gaps; no RF transmission,
  production RAN change or device attachment.

### TEL-06 — Telco cloud and network platforms

- **Outcome:** assess NFV/NFVI, MANO, SDN, Kubernetes, virtualization and MEC
  from image and workload identity through orchestration, segmentation,
  secrets, observability, resilience and privileged management.
- **Criteria/source direction:** current ETSI NFV specifications, applicable
  3GPP and O-RAN requirements, Kubernetes security guidance, cloud-control and
  zero-trust criteria, and the platform's supported-version baseline.
- **Case/evidence:** synthetic cluster/hypervisor and network-function
  inventories, image provenance, admission and runtime policy, service
  identities, secrets metadata, management routes, events, backup and recovery
  evidence.
- **Discriminating controls:** a vulnerable image not deployed, a compliant
  manifest changed after admission, a namespace boundary bypass hypothesis
  disproved by effective policy, and missing host telemetry.
- **Deliverable/safety:** deployed-state reconciliation, privilege and path
  analysis, preventive/detective/recovery control chain and retest plan; no
  production orchestrator, hypervisor or network-function action.

### TEL-07 — OSS/BSS and network APIs

- **Outcome:** assess provisioning, inventory, mediation, assurance, billing,
  partner and network-exposure workflows; administrative/service identities;
  API purpose and consent; data minimization; fraud controls; and end-to-end
  transaction evidence.
- **Criteria/source direction:** applicable CAMARA/Open Gateway identity and
  consent material, versioned OWASP API and NIST API guidance, operator
  process/data criteria, privacy obligations and partner contracts.
- **Case/evidence:** synthetic orders, entitlements, consent/purpose records,
  API requests, asynchronous outcomes, rating/billing events, reversals,
  privileged changes and fraud alerts across two identity contexts.
- **Discriminating controls:** an accepted API request whose business outcome
  failed, valid consent for the wrong purpose, a technically authorized but
  contractually invalid partner, and a duplicate transaction correctly
  reversed.
- **Deliverable/safety:** business/technical data-flow, authorization and
  consent tests, transaction reconciliation, fraud/control conclusion and
  targeted evidence requests; no real subscriber, customer or partner data.

### TEL-08 — Device, CPE, IoT and edge

- **Outcome:** reconcile deployed device identity, firmware/software version,
  configuration, credentials, services, remote-management reachability,
  update trust, segmentation, telemetry and supplier lifecycle.
- **Criteria/source direction:** applicable product and operator security
  baselines, current vulnerability/advisory evidence, approved device/IoT
  guidance, contractual support requirements and privacy/safety criteria.
- **Case/evidence:** synthetic or owned lab-device inventory, signed update and
  provenance records, configuration and service captures, declared/observed
  topology, remote-management policy, logs and end-of-support notices.
- **Discriminating controls:** a CVE for a different build, a default-looking
  credential that is disabled, a signed but rolled-back firmware image, and a
  management service visible only from a contained administration plane.
- **Deliverable/safety:** version/applicability matrix, path and configuration
  evidence, lifecycle/control assessment and remediation/retest; recorded
  evidence by default, with active testing limited to an owned disposable E2/E3
  target and an explicit non-destructive action list.

### TEL-09 — Detection, fraud, incident response and resilience

- **Outcome:** correlate subscriber, signalling, network-API, RAN,
  telco-cloud, identity and business events through detection, triage, fraud or
  incident ownership, containment, customer/privacy impact, recovery and
  post-incident assurance.
- **Criteria/source direction:** NIST SP 800-61 Rev. 3, current CISA
  communications hardening, GSMA defensive/threat guidance, applicable
  regulatory and operator incident, fraud, continuity and crisis criteria.
- **Case/evidence:** permitted recorded telemetry and a synthetic case file
  containing clock/identity gaps, duplicate alerts, an approved maintenance
  event, a fraud handoff, service impact, communications and recovery tests.
- **Discriminating controls:** rule present but required data absent, detection
  without accountable response, benign maintenance crossing layers, a true
  event contained before customer impact, and an unresolved time skew.
- **Deliverable/safety:** correlated timeline, collection-to-response control
  map, fraud/incident decision record, impact and recovery assessment,
  remaining uncertainty and lessons/retest; replay only, with protected data
  sanitized and labels withheld from the learner.

## Capstones — design-ready engagement specifications

Both capstones require one supported positive finding, one supported
non-finding and one genuinely inconclusive area. The point is to deliver and
defend a bounded assurance conclusion, not to maximize findings or execute an
exploit.

### CAP-IA — Internal-audit cybersecurity engagement

- **Input:** a synthetic organization, approved engagement authority and rules of
  engagement, objectives/risks, architecture, control population, mixed
  technical and process evidence, management declarations, prior actions and
  deliberate gaps.
- **Performance:** plan scope, criteria, population, period and sampling;
  execute and adapt a work program; combine inquiry, inspection, observation
  and safe reperformance; evaluate design, implementation and operation; and
  resolve or preserve reviewer challenge.
- **Output:** the complete [workpaper set](#the-workpaper-set), executive and
  control-owner communications, action/retest plan and a closure record.
- **Assessment:** authorization, custody and support hard gates; independent
  reperformance; significance and compensating-control reasoning; transparent
  uncertainty; and consistency between evidence, workpapers and communication.
- **Environment:** E0/E1 by default. Any E2/E3 technical stage is separately
  bounded and can be replaced by equivalent recorded evidence.

### CAP-TEL — Telecom cybersecurity assurance engagement

- **Input:** a synthetic service spanning at least four telecom layers and two
  organizational/supplier boundaries, plus criteria, architecture, change and
  exception records, correlated technical/business telemetry, a protected-data
  inventory and an incident or resilience thread.
- **Performance:** scope the service rather than a tool; reconcile subscriber
  or API context with core/interconnect/RAN/telco-cloud evidence as applicable;
  evaluate preventive, detective, fraud, incident and recovery controls; trace
  customer, privacy, financial and availability consequence; and distinguish
  operator, supplier and partner responsibility.
- **Output:** service/trust and responsibility models, criteria/applicability
  record, cross-layer test program, correlated evidence timeline, control
  assessment, findings/non-findings/unknowns, communications and retest.
- **Assessment:** every cross-layer link is evidence-backed; protocol or tool
  output is never an operator-wide conclusion; missing telemetry stays
  visible; partner/consent and protected-data boundaries are honored.
- **Environment:** E0/E1 replay is sufficient. No production signalling,
  subscriber system, RAN, interconnect, cloud or OSS/BSS action is implied.

Candidate resource relevance does not authorize bundling or execution. Each
authored module and capstone still has to pass the source, authoring, safety,
dry-run and promotion gates before it can be labelled shipped.

## The workpaper set

Authored modules select the appropriate artifacts from this capstone set:

- objective, subject, scope, criteria, population, period and rules of
  engagement;
- asset, dependency, data-flow and control model plus a test plan;
- evidence index with producer/version, collection time, exact subject/scope,
  raw-artifact hash or immutable locator, custody, observed/declared/inferred
  class and limitations;
- hypothesis and test ledger retaining evidence for and against each claim;
- control test sheet distinguishing design, implementation, operation and
  untested scope;
- finding or supported non-finding with condition, criterion, cause,
  consequence, compensating controls, significance and uncertainty;
- recommendation or action, accountable owner where supplied, and retest logic;
- concise communication, reviewer response and closure record; and
- an AI-use record, when relevant, naming the actual model/provider and
  configuration, tool authority, retained inputs/outputs as permitted, human
  verification and rejected suggestions.

Observed fact and inference never merge. “Fixed,” “not reproduced,” “not
retested” and “inconclusive” remain different outcomes.

## Assessment model

Current challenge grading does not change: exact finding coverage is a machine
verdict; misses, extras and evidence-less rows fail, while severity differences
are flags. A future workpaper receives a separate human review and cannot
soften a machine failure.

Hard failures override points: authorization or safety violation;
fabricated, tampered, replayed or unrelated evidence; answer-key access;
material custody failure; concealed scope expansion; or an unsupported
all-clear after required evidence is missing.

For work that clears the hard gates, instructors calibrate a local rubric
across scope/criteria, procedure/reproducibility, evidence/custody,
analysis/disconfirmation, risk/compensating controls, and
communication/recommendation/retest. A useful starting allocation is
10/15/25/20/15/15 percent respectively, but those weights are not an external
standard and require examples and reviewer calibration.

A learner who correctly rejects a plausible unsupported claim must outperform
one who reports it confidently. A justified inconclusive conclusion can be
excellent work; missing data disguised as an all-clear cannot.

## How each audience uses this curriculum

| Audience | Present action |
|---|---|
| Trainee | Complete shipped A–D and the shipped challenges; submit exact findings today. Treat future seed packs and workpapers as design until promoted. |
| Instructor/user | Choose a declared lane and outcome; preserve positive, benign, negative and inconclusive controls; isolate answer keys; version criteria, evidence and rubric. |
| Challenge author | Apply the authoring contract, prove reset/refusal/tamper cases, and keep scenario story separate from ground truth. |
| Operator | Take runtime truth from `list`, `describe`, `availability` and per-arm caveats; arm only separately authorized shipped actions. Curriculum prose is never execution authority. |

Delivery, calibration and maintenance are detailed in
[INSTRUCTOR_GUIDE.md](INSTRUCTOR_GUIDE.md). Environment selection and go/no-go
are detailed in [OPERATIONS.md](OPERATIONS.md).
