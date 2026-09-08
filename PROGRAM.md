# Program — evidence-led cybersecurity audit learning

This is the single living architecture for the learning program: what the
repository teaches now, what a complete internal-audit and telecom
cybersecurity curriculum must cover, and what has to be true before new
content or capability ships. It consolidates the program model, curriculum
domains, source spine, resource research, integration contracts, and admission
gates.

Each capability is labelled. **Shipped** means present in this checkout under
its stated gates. **Design-ready** means the learning design is specific enough
to author, but its runnable exercise or assets do not ship. **Research** means
the source or integration direction still has unresolved gates. **Proposed**
means target intent, not committed or scheduled work. External source maturity
is separate from repository maturity: a current standard does not make a
module shipped.

Runtime truth comes from the current code, schemas, catalog,
`list`/`describe`/`availability`, and the per-arm caveats. Exercise truth comes
from the challenge files and scoring implementation. The program documents
design; external sources supply criteria and teaching inputs. Where those
surfaces disagree, the runnable surface wins. Documentation grants no execution
authority: an entry here arms nothing, installs nothing, and changes no catalog
row.

## Who this program serves

| Reader | Use this program to | Start with |
|---|---|---|
| Trainee or analyst | Build the judgment needed to turn bounded technical work into a defensible audit conclusion. | [Curriculum](CURRICULUM.md) |
| Instructor or user | Select outcomes, deliver exercises, assess work, and improve the learning program. | [Instructor guide](INSTRUCTOR_GUIDE.md) |
| Challenge author or maintainer | Convert criteria and cases into governed, testable learning assets. | [Challenge authoring contract](challenges/README.md#authoring-contract-for-new-content) |
| Operator | Own authorization, containment, identities, evidence custody, reset, and stop decisions. | [Operations](OPERATIONS.md) |

The program does not award a professional certification. Versioned NICE tasks,
knowledge, skills, work roles, and competency areas may inform a module, but a
CTF result does not demonstrate an entire work role.

## The learning loop

Every module teaches the same accountable loop:

1. authorize the work and bound the subject, population, period, actions, and
   stop conditions;
2. identify the applicable criteria, assets, dependencies, data flows, and
   trust boundaries;
3. design a discriminating procedure, including evidence that could refute the
   working hypothesis;
4. collect attributable observations with source, version, time, scope,
   custody, and limitations;
5. keep observed facts, declarations, and inference separate;
6. evaluate control design, implementation, operation, compensating controls,
   consequence, and uncertainty;
7. communicate a bounded conclusion, recommendation or action, and remaining
   untested scope; and
8. retest, close or revise the conclusion, retain the evidence, and feed the
   lesson back into the program.

Technical validation and internal-audit assurance stay connected but distinct.
A successful exploit does not by itself prove an organization-wide control
failure. A clean scan does not prove control effectiveness. A rule's existence
does not prove collection, alerting, triage, or response. A framework mapping is
not certification. An accepted API request is not proof of the claimed business
outcome.

## Program architecture

Proficiency rises through four levels: **Foundation** explains boundaries and
interprets supplied evidence; **Practitioner** performs a bounded procedure and
justifies a scoped conclusion; **Advanced** correlates layers, chooses tests and
manages ambiguity; **Capstone** plans and delivers an end-to-end engagement
under safety, evidence, time, and communication constraints. Advancement is
shown by graded artifacts, not attendance or tool output.

### Foundations and audit practice

| Module | Capability outcome |
|---|---|
| `FND-01` Safety, ethics and authority | Apply rules of engagement, action boundaries, stop conditions and escalation without confusing tool access with permission. |
| `FND-02` Architecture and assets | Read systems, networks, cloud, identity, application, data and telecom architecture; distinguish declared from observed assets and trust boundaries. |
| `FND-03` Reproducible evidence | Preserve commands, versions, timestamps, hashes, custody and limitations; use AI without treating generated text as evidence. |
| `AUD-01` Engagement design | Set objectives, risk, scope, criteria, population, period, sampling, work program and stakeholder responsibilities. |
| `AUD-02` Control assessment | Distinguish design, implementation and operating effectiveness; combine inquiry, observation, inspection and reperformance; handle positive, negative and inconclusive evidence. |
| `AUD-03` Findings and risk | Develop condition, criterion, cause, consequence, compensating controls, significance, recommendation and residual-risk reasoning without overstating certainty. |
| `AUD-04` Workpapers and follow-through | Produce reviewable workpapers, conclusions and communications; track action, retest, closure and evidence retention. |

### General cybersecurity assurance

| Module | Capability outcome |
|---|---|
| `CYB-01` Asset, network and configuration assurance | Reconcile inventory, services, dependencies, data flows, exposure, segmentation, DNS, remote management and secure configuration. |
| `CYB-02` Identity and access | Assess identity lifecycle, privilege, federation, authenticators, workload identities, AD/GPO/ADCS paths and consent; distinguish configured or hypothetical privilege from effective access. |
| `CYB-03` Cloud and platform | Assess shared responsibility, control planes, IAM, storage, networks, logging, keys, serverless, containers/Kubernetes, virtualization, infrastructure as code, drift and resilience. |
| `CYB-04` Web, API, mobile and secure software | Use versioned requirements, threat models, architecture/code review, SAST/DAST and business-logic tests across the delivery lifecycle; verify remediation. |
| `CYB-05` Vulnerability and exposure | Keep inventory/applicability, reachability, CVSS severity, KEV evidence, EPSS probability, organizational impact, exceptions, priority and retest as distinct inputs. |
| `CYB-06` Logging, detection, response and DFIR | Trace telemetry prerequisites through detection strategy, analytic/rule, alert, triage, case response, forensic custody, recovery and lessons learned. |
| `CYB-07` Threat-informed validation | Turn a threat model or ATT&CK hypothesis into a safely authorized test; establish path prerequisites, observe defensive behavior, clean up and state coverage limits. |
| `CYB-08` Data, privacy and cryptography | Assess data lifecycle, purpose and consent, retention, residency, destructive/privacy risk, cryptography, keys and secrets. |
| `CYB-09` Third-party and supply chain | Assess vendors, products, open-source inputs, builds, artifacts, deployment and service dependencies through provenance, due diligence and lifecycle controls. |
| `CYB-10` AI, agent and MCP assurance | Assess model/data/system boundaries, prompt and tool injection, identity and authority, token/secret flow, egress, spend, memory, supply chain, evidence ownership, monitoring and containment. |
| `CYB-11` Governance and monitoring | Evaluate accountable roles, risk decisions, exception expiry, architecture, control monitoring, metrics, portfolio dependencies and reporting. |

### Telecom cybersecurity specialization

| Module | Capability outcome |
|---|---|
| `TEL-01` Telecom architecture and governance | Map services, assets, trust zones, management/O&M, roaming, suppliers, criteria and shared responsibility to a current threat and risk model. |
| `TEL-02` Subscriber identity and eSIM | Assess UICC/eUICC and SIM lifecycle, IMSI/SUPI protection, SUCI, temporary identifiers, authentication/key custody, remote provisioning, consumer/IoT eSIM and related fraud interfaces. |
| `TEL-03` Mobile core, SBA and slicing | Assess 4G/5G network functions, registration/authentication, NF discovery and authorization, service APIs, plane separation, slicing/tenant isolation, SEPP/N32 and their telemetry. |
| `TEL-04` Interconnect and roaming | Assess SS7/SIGTRAN, Diameter, GTP, IPX/GRX and applicable SIP/RCS/SMS controls, signalling firewalls, protocol correlation, partners, keys, and explicit consent for testing. |
| `TEL-05` RAN and O-RAN | Assess RU/DU/CU, transport, SMO, RIC, xApps/rApps, O-Cloud, interface PKI/mTLS, zero trust, component assurance, supply chain and telemetry. |
| `TEL-06` Telco cloud and network platforms | Assess NFV/NFVI, MANO, SDN, Kubernetes, virtualization, MEC/edge, microsegmentation, workload identity, images, secrets and management-plane isolation. |
| `TEL-07` OSS/BSS and network APIs | Assess provisioning, mediation, billing and exposure platforms; administration and service identities; CAMARA/Open Gateway authorization, purpose/consent, partner access, fraud controls, logging and data governance. |
| `TEL-08` Device, CPE, IoT and edge | Reconcile inventory, version, configuration, firmware/update trust, credentials, remote management, services, segmentation, telemetry and vendor lifecycle using safe device cases. |
| `TEL-09` Detection, fraud and resilience | Correlate signalling, API, cloud and RAN evidence; assess abuse/fraud controls, incident and crisis coordination, outage/denial, recovery, continuity, customer/privacy impact and post-incident assurance. |

### Capstones

`CAP-IA` is an internal-audit cybersecurity engagement spanning governance,
risk, controls, scoped technical reperformance, workpapers, findings or
supported non-findings, conclusion, action and retest. `CAP-TEL` is a telecom
multi-layer assurance engagement correlating subscriber or network-API
context, core/interconnect/RAN/telco-cloud controls and telemetry, business and
privacy impact, and recovery. Both must include at least one supported
non-finding and one genuinely inconclusive area; neither requires unsafe live
exploitation.

The [curriculum](CURRICULUM.md) turns this architecture into learner pathways
and module blueprints. Current runnable coverage is deliberately partial. Empty
or design-ready areas are program truth, not an invitation to overclaim the
existing telecom/AWS rehearsal as a complete telecom stack.

## Asset-association evidence practice

The [asset reconnaissance capability](docs/scope-recon.md) provides a bounded
inventory-association exercise across CT, DNS, certificate fingerprints,
ASN/registry and optional Shodan evidence. It supports `FND-*`, `AUD-*`,
`CYB-01/05/09` and synthetic telecom responsibility cases by making source
paths, exclusions, competing explanations and missing evidence reviewable.
Its separately armed observation action does not make discovered candidates
authorized targets. The offline analyst worksheet is available as teaching
material; it is not a new machine-scored challenge, a maintained-support
promotion or implementation of the proposed non-fixture grading bridge.

## Governance and learning lifecycle

Program, source, and runtime decisions live in three independent registers:

- the **module register** records outcome, audience, level, status, owner,
  dependencies, deliverables and validation evidence;
- the **source register** records the selected revision, authority, license or
  data rights, permitted use, currency review, limitations and replacement; and
- the **runtime register** records capability presence, action admission,
  authorization gates, support, versions and regression evidence.

No promotion in one register promotes the other two. In particular, a useful
source does not admit a tool, and an admitted action does not create sound
course material.

The lifecycle is: needs and risk analysis; module and assessment design; source
and asset admission; scenario development; technical, safety and content
review; dry-run and go/no-go; controlled delivery; evidence-backed assessment
and debrief; then evaluation, corrective action, source refresh or retirement.
This follows the learning-program and exercise lifecycle sources below without
claiming that this repository implements either source wholesale.

Every module specification includes versioned outcomes and prerequisites,
criteria and source pins, an evidence/scenario manifest, positive and benign
controls, at least one negative or inconclusive case where appropriate,
deliverables and grading, environment and safety boundaries, accessibility,
reset and retention, and an owner/currentness review. A module is not shipped
until its assets, learner brief, instructor key, grading, reset, refusal cases
and promotion evidence all exist and have been dry-run.

## Authoritative source spine

These sources organize criteria and teaching. They do not all apply to every
engagement, and none is proof that a deployed control operates. An authored
module pins the identifier or revision it actually uses; living pages and
`latest` links are reviewed rather than followed silently.

### Learning, audit and control assessment

- [IIA Global Internal Audit Standards (2024)](https://www.theiia.org/en/standards/2024-standards/global-internal-audit-standards/), particularly engagement planning and performance, and the [Cybersecurity Topical Requirement](https://www.theiia.org/en/standards/2024-standards/topical-requirements/cybersecurity/), effective 5 February 2026, anchor applicable assurance work in governance, risk management, controls, documented applicability and bounded conclusions.
- [NIST SP 800-50 Rev. 1](https://csrc.nist.gov/pubs/sp/800/50/r1/final), [NICE Framework Components v2.2.0](https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center/nice-framework-current-versions), and the [ENISA Cybersecurity Exercise Methodology](https://www.enisa.europa.eu/publications/the-enisa-cybersecurity-exercise-methodology) support program lifecycle, competency mapping, exercise design and evaluation.
- [NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20), [SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), [SP 800-53A Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/a/r5/final), and [SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) provide outcome, control-assessment and technical-test structures that must be tailored to the engagement.

### Identity, cloud, application, data and supply chain

- [NIST SP 800-63-4](https://csrc.nist.gov/pubs/sp/800/63/4/final), [SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final), and [SP 800-207A](https://csrc.nist.gov/pubs/sp/800/207/a/final) anchor identity, federation and zero-trust reasoning.
- [CSA Cloud Controls Matrix v4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) and the living [Kubernetes security guidance](https://kubernetes.io/docs/concepts/security/) support cloud and cloud-native cases; module pins and platform evidence remain necessary.
- [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/), [WSTG v4.2](https://owasp.org/www-project-web-security-testing-guide/), the [API Security Top 10 2023](https://owasp.org/www-project-api-security/), and [NIST SP 800-228](https://csrc.nist.gov/pubs/sp/800/228/upd1/final) supply versioned application and API criteria and test methods.
- The [NIST Privacy Framework 1.0](https://csrc.nist.gov/pubs/cswp/10/nist-privacy-framework-version-10/final), [SP 800-161 Rev. 1 Update 1](https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final), and [SP 800-218 SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) anchor privacy, supplier and secure-development reasoning.

### Vulnerability, detection, response and threat-informed validation

- [CVSS 4.0](https://www.first.org/cvss/v4.0/specification-document), [EPSS](https://www.first.org/epss/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc), and [NIST IR 8286D](https://csrc.nist.gov/pubs/ir/8286/d/final) keep technical severity, exploitation probability, known exploitation, applicability/exposure, decision context and business impact separate.
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) connects incident response to cybersecurity risk management.
- Current [MITRE ATT&CK data and tools](https://attack.mitre.org/resources/working-with-attack/) supply versioned techniques, Detection Strategies, Analytics and Data Components. ATT&CK's older Data Sources were deprecated in v18, so new modules do not build currentness claims around them.

### AI, agents and MCP

- The [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) and [NIST AI 600-1 Generative AI Profile](https://csrc.nist.gov/pubs/ai/600/1/final) organize AI risk and evaluation without replacing system-specific evidence.
- [MITRE ATLAS](https://atlas.mitre.org/) and the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) provide living adversarial and agent-risk taxonomies.
- The [MCP 2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28/) and official [security best practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices) are current research sources. They do not retroactively change this checkout's documented wire contract; repository code remains runtime truth.

### Telecom

- [3GPP TS 33.501](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3169) and [TS 33.117](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=2928), with the applicable 33.5xx SCAS, anchor 5G architecture and network-product assurance. Both are under change control, so a module records its chosen Release and version.
- [GSMA FS.40 5G Security Guide v3](https://www.gsma.com/solutions-and-impact/technologies/security/gsma_resources/5g-security-guide-version-3-0/), the [interworking-security index](https://www.gsma.com/solutions-and-impact/technologies/security/cybersecurity-knowledge-base/interworking-security/), [eSIM specification status](https://www.gsma.com/solutions-and-impact/technologies/esim/esim-specification/), and [NESAS documents](https://www.gsma.com/solutions-and-impact/technologies/security/nesas-documents/) connect 5G, SS7/Diameter/GTP/interconnect, subscriber provisioning and equipment assurance. Member access is not a right to redistribute material.
- The [ENISA 5G Security Controls Matrix](https://www.enisa.europa.eu/publications/5g-security-controls-matrix) and [NIST CSWP 36 A-E](https://csrc.nist.gov/news/2026/nist-releases-cswp-36-final-volumes-a-e) connect technical controls to evidence and demonstrated 5G privacy/security capabilities.
- The [O-RAN Alliance 2026 security update](https://www.o-ran.org/blog/o-ran-alliance-security-update-2026), current [ETSI NFV specifications](https://www.etsi.org/technologies/nfv), and [CAMARA Spring26 identity and consent material](https://github.com/camaraproject/IdentityAndConsentManagement) cover open RAN, telco cloud and network APIs.
- [CISA communications-infrastructure hardening guidance](https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure) and the [GSMA cybersecurity knowledge base](https://www.gsma.com/solutions-and-impact/technologies/security/cybersecurity-knowledge-base/) supply current defensive and threat context. They are not substitutes for engagement criteria or observed operator controls.

## Direction

**The strongest expansion path is trusted evidence integration, auditor
workpapers, and governed training corpora — not wholesale adoption of
pentesting agents.**

The differentiator here is already the relationship between bounded
capabilities, actual observations, evidence custody, explicit
limitations, and independently graded findings. Adding another large
autonomous framework does not strengthen that relationship; it weakens
per-action authorization, aggregate budget accounting, and evidence
ownership by hiding a nested agent behind one seemingly bounded row.
Making a few high-quality data sources and training cases participate
*correctly* in the existing relationship is worth more.

Concretely, that means: frozen local vulnerability context and exact
local detection-rule reads before any new executor; evidence-led
investigation methodology and skeptical review before another scanner;
declarative cloud action/permission/telemetry corpora before live cloud
dispatch; and audit-quality workpaper criteria before another
leaderboard. A broad agent framework is at most a *comparison*
candidate, evaluated once as an isolated challenger head after a
measured gap — never a default dependency.

## Research provenance and boundaries

- **Baseline:** commit `ed0404a5a6340f2f74008c6c436b2a24a6a163ba`, read
  through the repository's own README, capability catalog, dispatch
  implementation, curriculum, challenge catalog, and head-attempt
  grader.
- **Coverage:** 43 submitted positions yielding **42 unique
  candidates** — position 10 duplicates R05 (DFIR Dominican), so the
  register carries no R10. Plus **12 supplemental methodology and
  corpus families** (S01–S12).
- **What this research was not:** not an execution, not an
  installation, not a security audit, not a license clearance, not a
  benchmark, not a cloud operation, and not an implementation. No
  candidate tool, exploit, lab target, tenant API, or test suite was
  run, and no upstream performance claim was independently reproduced.
- **Review depth:** external resources were reviewed as served on the
  research date, generally through first-party documentation. Only the
  baseline commit is pinned. Candidate revisions, licenses, data
  rights, hashes, dependency trees, and actual runtime behavior remain
  admission prerequisites, not completed steps.

## Presence, handler, admission, and support are four different things

These distinctions already govern the shipped catalog and they govern
this register too. Collapsing them is the single easiest way to turn an
honest survey into a false promise.

- **Catalog presence** — a row in `extension/coverage.yaml` is survey
  coverage information. It is not a promise that an adapter exists.
- **A specialized/curated handler** — `curated` is a compatibility and
  handler distinction: curated arms never ride a generic transport. It
  is not a statement of maintenance.
- **Per-action admission** — each action carries its own safety, scope,
  side-effect, budget, cleanup, and version metadata, and each arm's
  own gate remains the enforcement point. Admission is metadata, not
  authority.
- **Maintained support** — an evidence-gated promotion with an owner, a
  repeatable regression case, a supported version range, and a stated
  known-limitations position.

**This research register is separate from
`extension/coverage.yaml` and from the runtime catalog.** No candidate
below becomes maintained, admitted, or shipped because it appears here.
Promotion into the frozen catalog is a deliberate, versioned change,
never a bulk edit or a reordering.

## Four forms of reuse

A candidate is useful in exactly one of these forms at a time. They are
not interchangeable, and picking the wrong one is how an unbounded
execution surface enters through a door labelled "integration".

| Form | What it is | What it does not grant |
|---|---|---|
| **Bounded adapter** | An exact, independently classifiable action behind the existing `invoke` surface. | Not the upstream application's whole tool surface. |
| **Evidence importer** | Normalizes captured output without rerunning its source tool. | Not permission to run the source tool. |
| **Methodology pack** | Reviewed procedures, criteria, and teaching material. | No execution authority whatsoever. |
| **Alternative head** | A different agent consumer of the same bounded surface. | No exemption from scope, custody, or budget controls. |

A read-only importer is usually the cheapest route to training value
while keeping the option of a narrowly scoped live adapter later.

## The grading boundary, and the proposed bridge

**Current, shipped behavior.** In the head-attempt lane, coverage comes
from the server's own record: only a successful, server-observed
`run_range` result and the fixture roster the server itself recorded
establish trusted fixture coverage. `invoke` arguments are the agent's
own strings and establish nothing; agent-supplied paths establish
nothing; `list`/`describe` tool listings establish nothing. This is a
claim-without-evidence tripwire, not proof of investigative depth, and
the lane refuses non-fixture contracts by design.

**Why that matters to expansion.** An imported directory graph, HTTP
capture, CVE record, or log packet cannot honestly name a synthetic
range fixture. Without a bridge, a new evidence source either sits
outside grading or gets credit it has not earned.

**Proposed bridge.** A versioned *trusted observation* contract plus a
separate adjudicator for non-fixture evidence — created or validated on
the trusted tool side, never merely asserted by the head. A trusted
observation would carry attempt id, producer identity and version,
action, exact subject and scope, collection time, raw artifact hash and
locator, an observed/declared/inferred classification, limitations, and
its association with an approved evidence source.

**The bridge extends the boundary; it does not weaken fixture
grading.** The existing fixture lane stays intact and keeps its refusal
tests until the new lane has equivalent ones. Counting tool calls,
accepting agent-supplied file paths, or granting every claimed finding
credit because one invocation succeeded are all explicitly out of
scope.

## First proposed vertical slice

One useful slice, proven end to end, beats breadth across the register.
The slice needs no new live scanner and no cloud credentials.

1. **Synthetic asset inventory** — declared products, versions, and
   exposure for a small estate.
2. **Frozen vulnerability record** — pinned local data, source
   timestamps preserved.
3. **An unaffected or blocked near miss** — a severe-looking issue that
   does not apply, or a path a control actually blocks.
4. **An incomplete enrichment case** — unknown stays unknown; absence of
   data is not an all-clear.
5. **A bounded local `vulnify` lookup** — exact query, read-only,
   snapshot digest in the result.
6. **A source-linked workpaper** — every conclusion tracing to an
   observation, with explicit uncertainty.

Rule intelligence and recorded telemetry follow as the second slice.
Live identity, cloud, and hypervisor mutation remain a separate,
explicitly approved decision — never carried along by a data or
curriculum change.

## Proposed T01–T08 release-wave seed map

The proposed T01–T08 progression in [CURRICULUM.md](CURRICULUM.md) is the
first design-ready content wave derived from the research package. It does not
replace the complete module architecture above, and it does not yet cover the
full telecom specialization. The table shows what each seed already stands on
in this checkout, which register entries could feed it, and the conclusion a
learner would have to defend.

The telecom/AWS sequence remains a useful shipped rehearsal anchor. It is a
synthetic cloud estate with telecom framing, not evidence that the repository
currently teaches subscriber identity, 5G core, interconnect, RAN, telco cloud,
OSS/BSS, network APIs, fraud, or telecom resilience. Those subjects belong to
`TEL-01` through `TEL-09` and require new governed cases.

Read the columns strictly:

- **Shipped anchor** — exists in this checkout today and can be run.
- **Proposed inputs** — register identifiers only. Nothing in this
  column is bundled, admitted, installed, licensed, validated, or
  maintained; each one is still subject to the admission checklist at
  the end of this document.
- **Conclusion practiced** — the audit judgement the track is meant to
  produce. It describes an exercise objective, not a claim about
  coverage of any real estate.

| Track | Shipped anchor (today) | Proposed inputs (not bundled) | Internal-audit / telecom conclusion practiced |
|---|---|---|---|
| **T01** Audit evidence and AI skepticism | Execution-result and capability-manifest envelopes, the HMAC-chained attempt traces, and exact grading. | R15, R28, R41; S01–S03. | Evidence sufficiency, bounded scope, stated uncertainty, and reperformability by an independent reviewer. |
| **T02** Cloud control and detection chain | `telecom-aws-01` through `telecom-aws-06`. | R33–R34. | The IAM / network / logging control chain read end to end: from condition, through the expected telemetry, to the action it should trigger. |
| **T03** Risk-based vulnerability prioritization | The telecom asset and version evidence in the shipped fixtures, plus the near-miss discipline drilled in the challenge sequence. | R01; S10. | Applicability, technical severity, exploitation evidence, exploitation probability, and business impact kept as five separate inputs. |
| **T04** Detection assurance and forensic triage | `telecom-aws-05` and `telecom-aws-06`, plus the grading evidence those attempts capture. | R23, R43; S07, S08, S12. | Rule existence, telemetry collection, alerting, triage, and response distinguished from one another — and from an honestly inconclusive coverage answer. |
| **T05** AD, Group Policy and application consent | `telecom-aws-03` as an identity-path precursor. | R02, R08, R25, R36, R38; S11. | Configured and hypothetical paths separated from applicable access and from demonstrated access, with no tenant credentials involved. |
| **T06** Web/API and code review | `lab-web-01` and `lab-code-01`. | S04–S06, plus bounded use of R14, R29, R40. | A versioned requirement actually tested, and an unsupported scanner or model claim rejected on the evidence. |
| **T07** Agent and MCP governance | The track-D dogfood worksheet and this suite's own MCP, dispatch, and evidence-custody boundaries. | R07, R16, R35. | Tool authority, untrusted instructions, secret flows, cost exposure, evidence ownership, and containment assessed as one surface. |
| **T08** Virtualization and edge-device assurance | `lab-edge-01`. | R32, plus bounded R14 patterns. | Appliance and virtualization management-plane exposure reconciled against version, configuration, expected telemetry, and the gaps in the evidence itself. |

Nothing in this map implies a bundled external resource or telecom coverage
beyond the shipped challenges named in the anchor column. The proposed column
names training applications of the register, and the register's gates apply to
every one of them.

## Candidate register (42 unique candidates)

Identifiers preserve original submission positions. **There is no R10:**
submission position 10 repeated position 5, so R05 is the duplicate
target and the register skips the identifier rather than reusing it for
something else. Low-fit, deferred, and unresolved candidates are listed
in full — omitting them would misrepresent the survey.

"Integrate" below always means *prototype or admit the specified subset
after gates are met*. It never means an upstream application was
installed or accepted wholesale.

| ID | Resource | Priority / fit | Proposed disposition and gate |
|---|---|---|---|
| R01 | [vulnify](https://github.com/mez-0/vulnify/) | P1 / High | Integrate bounded local reads. Gate: no network or database mutation during a lookup; unknown enrichment stays unknown; every record traces to a pinned snapshot digest. |
| R02 | [AD-PathFinder](https://github.com/NetSPI/AD-PathFinder) | P2 / High | Import exported results; adapt its data-requirement patterns. Gate: missing datasource reads as *not assessed*, never clean; no real hashes or credentials; a blocked path is never graded as demonstrated compromise. |
| R03 | [SpecterOps skills](https://github.com/SpecterOps/skills) | P1 / High | Curate a methodology-only subset. Gate: every retained instruction maps to a bounded tool or a human step; skill prose is untrusted input and grants no permission. |
| R04 | [Awesome LLMs for Vulnerability Detection](https://github.com/huhusmang/Awesome-LLMs-for-Vulnerability-Detection) | P2 / Medium | Use as a discovery index for a small code corpus. Gate: labels reviewed, splits grouped by project/variant, no score comparison across incompatible tasks. |
| R05 | [DFIR Dominican CTFs and Labs](https://dfirdominican.com/resources/ctfs-labs/) | P1 / High | Curate external training cases. Gate: per-case teaching rights established; evidence hashed and isolated; no malware execution. *(Duplicate target: submission position 10.)* |
| R06 | [NetDraw](https://mr-r3b00t.github.io/net_draw/) | P2 / Medium | Reference renderer for evidence-linked diagrams; resolve source access first. Gate: source, reuse terms, and offline/self-hosting behavior are **unresolved**; observed and inferred edges must stay visibly distinct; no sensitive topology leaves the approved environment. |
| R07 | [AgentHound](https://github.com/adithyan-ak/AgentHound) | P2 / High | Adapt its evidence and cleanup patterns; import sanitized output. Gate: upstream default posture is active and documents credential reuse; no real tokens; inferred edges are never graded as demonstrated access. |
| R08 | [GPOHound](https://github.com/cogiceo/GPOHound) | P2 / High | Import policy evidence; teach applicability limits. Gate: uncovered security/WMI filters, item-level targeting, and conflict simulation reported as limitations; a filtered-out policy is not effective access; no shared-graph writes. |
| R09 | [Open-Source Threat Intel Feeds](https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds) | P2 / Medium | Curate frozen snapshots, not an indiscriminate feed importer. Gate: no listed indicator is dereferenced; per-feed terms, expiry, and disagreement are explicit. |
| R11 | [CyberStrike](https://github.com/CyberStrikeus/CyberStrike) | P3 / Low | Defer core integration; optional isolated challenger head only. Gate: no host secrets, unrestricted shell, or unbounded network; attributable evidence and cost; measured improvement over the existing head. |
| R12 | [AppSecSanta AI pentesting agents survey](https://appsecsanta.com/research/ai-pentesting-agents-2026) | P2 / Medium | Use as a secondary discovery reference. Gate: every retained claim traced to a primary source with a testable criterion; a favorable survey description is never evidence of safety or effectiveness. |
| R13 | [pentest-harness](https://github.com/S1N6H/pentest-harness) | P3 / Medium | Adapt replay patterns; defer a replacement harness. Gate: replay cannot alter original evidence; agent text stays distinct from trusted observations; no new execution authority. |
| R14 | [TrustedSec SpooNMAP update](https://trustedsec.com/blog/spoonmap-grows-up-findings-local-llm-detection-and-a-whole-lot-less-waiting) | P2 / High | Enhance the existing nmap lane; do not blanket-wrap the project. Gate: no credential-collection or unapproved scripts in the profile; skipped probes visible; stale resume state refused. |
| R15 | [Collinear: cybersecurity simulated worlds](https://blog.collinear.ai/p/cybersecurity-simulated-worlds-agi) | P1 / High | Adapt the task/environment/verifier separation. Gate: learner and model cannot read expected findings or trace keys; forged or truncated evidence fails closed. |
| R16 | [Auto-research-red-teaming / AHA](https://github.com/henrymao2004/Auto-research-red-teaming) | P2 / High | Adapt scenario contracts and held-out evaluation, not autonomous campaign generation. Gate: no real secrets or unauthorized targets; held-out and development results reported separately. |
| R17 | [numasec](https://github.com/FrancescoStabile/numasec) | P2 / Medium | Adapt the finding lifecycle; defer a second executor. Gate: status changes are attributable and reversible without overwriting evidence; no model-only status change creates a verified finding. |
| R18 | [SILENTCHAIN Community Edition](https://github.com/silentchainai/SILENTCHAIN/tree/main) | P2 / Medium | Optional candidate-finding enrichment through the existing Burp lane. Gate: passive toward the target is not absence of egress — verify with canary secrets; suggestions stay candidates until independently verified. |
| R19 | [xalgorix](https://github.com/xalgorix/xalgorix) | P3 / Low | Inspect UI and scope patterns only; defer the executor. Gate: documented setup includes privileged containers — no host or grader privilege, no runtime tool downloads, egress enforced outside the agent. |
| R20 | [Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) | P3 / Medium | Reference shared-task coordination only. Gate: no duplicate target actions, unbounded fan-out, or unattributed evidence; global budgets still enforced. |
| R21 | [Cybermes](https://github.com/Zyrexnn/Cybermes) | P2 / Medium | Curate playbook structure and read-only diagnostics. Gate: no client configuration is registered, installed, or repaired; missing dependencies degrade honestly rather than silently. |
| R22 | [Fire HD ownership retrospective](https://ericpardee.github.io/fire-hd-ownership/) | P2 / Medium | Use as an instructor-led reasoning case. Gate: build-specific limits stated; no device altered; no exploit binary required or redistributed. |
| R23 | [THOR Finding Triage Benchmark](https://nextron-labs.github.io/thor-ai-benchmarks/#models) | P1 / High | Independently implement analogous risk-sensitive metrics. Gate: the expert-labeled finding corpus is **not public** — do not assume a downloadable test set; report critical misses and false review burden separately; the leaderboard is not head-selection evidence. |
| R24 | [cyberkimi-benchmarks](https://github.com/lordx64/cyberkimi-benchmarks) | P2 / Medium | Reference attempt and assistance disclosure. Gate: every reported denominator reconstructable from preserved attempts; human assistance disclosed; no case silently dropped. |
| R25 | [Claude-AD](https://github.com/ADScanPro/Claude-AD) | P2 / High | Curate an auditor-oriented AD methodology pack. Gate: prerequisites, observed facts, and inference separated; no action authorized by a skill; framework mappings never asserted as compliance. |
| R26 | [Awesome Red Teaming](https://github.com/0xMrNiko/Awesome-Red-Teaming) | P2 / Medium | Use as a curated instructor index. Gate: each selected item maps to a teachable objective with reviewed evidence; directory inclusion is not endorsement; stale material flagged. |
| R27 | [Blackstorm Security research](https://www.blackstormsecurity.com/research/) | P3 / Conditional | Hold pending access and artifact review. Gate: **full-page retrieval failed on the research date**, so only the indexed first-party description was seen; stays link-only until the actual series and any companion artifacts are reviewed and independently verified. |
| R28 | [YesWeHack LLM series: Codex](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex) | P1 / High | Adapt an evidence-backed hypothesis ledger to the existing heads. Gate: every conclusion cites observations; disconfirming evidence and rejected claims retained; no prompt widens tool access. |
| R29 | [deep-eye](https://github.com/zakirkun/deep-eye) | P2 / Medium | Import sanitized results; adapt baseline and retest patterns. Gate: *not retested* stays distinct from *fixed*; tool and model configuration preserved; stable IDs never merge unrelated conditions. |
| R30 | [exploitarium](https://github.com/bikini/exploitarium) | P3 / Low | Quarantine as reference; no bulk execution or ingestion. Gate: no unreviewed payload enters the training runtime; each case needs a disclosure/advisory trail and explicit reuse permission, otherwise it stays link-only. |
| R31 | [METATRON](https://github.com/sooryathejas/METATRON) | P3 / Low | Use as a simple architecture case; defer integration. Gate: local inference is not offline operation; generated prose is never promoted to source evidence; avoid duplicating existing heads and network arms. |
| R32 | [Virtual//Attack](https://github.com/ReversecLabs/virtual.attack) | P2 / High | Adapt technique and log-source cases into a methodology pack. Gate: reviewed criteria plus a negative control per case; a documented expected log source is not evidence that logging was enabled or retained; no production virtualization action. |
| R33 | [Leonidas](https://github.com/reverseclabs/leonidas) | P1 / High | Import the declarative corpus; keep executors separate. Gate: import treats executor bodies as inert text and touches no cloud credentials; positive, benign, and missing-telemetry variants graded separately. |
| R34 | [Detection in the Cloud](https://detectioninthe.cloud) | P1 / High | Use as companion methodology, not a second detection engine. Gate: pages pinned to the corresponding definition revisions; a rule listing is never read as operating effectiveness. |
| R35 | [AgentSeal](https://github.com/getagentseal/agentseal) | P1 / High | Prototype static fixture analysis; keep active modes separate. Gate: the offline boundary must be verified rather than assumed — no registry or network calls, server launches, or quarantine writes on the read path; every result cites specific configuration evidence. |
| R36 | [Rubeus](https://github.com/ghostpack/rubeus) | P2 / Medium | Use deweaponized telemetry and methodology only. Gate: no real tickets, hashes, or secrets distributed; legitimate administration is not automatically classified as compromise. |
| R37 | [CVE MCP Server](https://github.com/mukul975/cve-mcp-server) | P2 / Medium | Consider only as a bounded remote alternative to R01 when current enrichment is genuinely needed. Gate: approved providers only, no silent fallback, no internal asset identifiers disclosed, missing sources explicit. |
| R38 | [M365Pwned](https://github.com/OtterHacker/M365Pwned) | P2 / Medium | Build a synthetic consent and data-access case; no default live wrapper. Gate: upstream performs live Graph reads and writes; permission claims verified against the API owner's documentation (see S11); no real tenant, mailbox, or file accessed. |
| R39 | [AI-Pentest / Hacking Articles](https://github.com/Ignitetechnologies/AI-Pentest) | P2 / Medium | Curate tutorial reading, not a new toolkit. Gate: every step maps to an admitted action or an explicit manual instructor step; nothing is installed on the learner's behalf. |
| R40 | [Hetty](https://github.com/dstotijn/hetty) | P2 / Medium | Optional capture importer; ZAP and Burp remain the primary web lanes. Gate: no unintended listener exposure or persistent trust-store change; raw capture custody protected; capture distinguished from replay. |
| R41 | [SANS AI-assisted, human-led investigations](https://www.sans.org/go/ai-assisted-human-led-trusted-investigations) | P1 / High | Adapt the human-accountability and validation methodology into an AI-use record. Gate: the **linked full framework downloads were not reviewed**; link rather than bundle; author an original verification checklist. |
| R42 | [pentestkit](https://github.com/lordx64/pentestkit) | P1 / High | Adapt complete experiment accounting; challenger head only later. Gate: first-pass, tuned, and held-out results separated; every failure stays in the denominator; a headline score is not generalization evidence. |
| R43 | [Security-Detections-MCP](https://github.com/mhaggis/security-detections-mcp) | P1 / High | Integrate exact local rule reads over pinned indexes. Gate: no rule generation, index mutation, deployment, or hosted fallback on the read path; per-corpus licensing reviewed; every result source-attributable. |

## Supplemental methodology and corpus resources (S01–S12)

Twelve additional source families support the proposals above. They are
governed by the same rule: reading a source establishes nothing about
the right to redistribute or execute it.

| ID | Resource | Role | Governed use and gate |
|---|---|---|---|
| S01 | [NIST SP 800-53A Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/a/r5/final) | Control-assessment methodology | Bind each exercise to a control objective, an assessment procedure, evidence requirements, and a bounded conclusion. Gate: criteria, scope, population, and period explicit; a clean scan or a successful exploit is never an organization-wide verdict; mapping is not certification. |
| S02 | [IIA evidence guidance / Standard 14.1 explanation](https://www.theiia.org/en/content/podcast/getting-started-with/2025/ep-0030/) | Audit evidence and workpaper quality | Grade the human workpaper on relevant, reliable, sufficient evidence rather than technical success alone. Gate: a reviewer can reconstruct the test and its limitations; the rubric does not claim to reproduce or replace professional standards. |
| S03 | [NICE Framework Resource Center](https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center) | Role and competency mapping | Map course objectives to versioned tasks and skills. Gate: each outcome has a graded deliverable; a CTF result is never presented as a professional certification. |
| S04 | [OWASP ASVS and WSTG](https://owasp.org/www-project-application-security-verification-standard/) | Application-security criteria and test methods | Pair a versioned requirement with a specific test procedure and captured evidence. Gate: the test addresses the selected requirement, not a broad category; protected behavior and absent coverage remain distinguishable. |
| S05 | [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | Deployable isolated web training target | Run a pinned private instance for selected existing web and review exercises. Gate: no public demo is scanned; reset and containment verified; the application's MIT terms and the companion guide's more restrictive terms are not the same license. |
| S06 | [NIST SARD](https://samate.nist.gov/SARD/) | Labeled software-weakness corpus | Select small documented code cases, including paired vulnerable/fixed variants and suspicious-but-unreachable code. Gate: labels checked; duplicate variants never cross the split; per-suite distribution terms verified. |
| S07 | [NIST CFReDS](https://www.nist.gov/programs-projects/computer-forensic-reference-data-sets) | Forensic reference evidence | A direct evidence-corpus route for custody, timeline, and tool-validation exercises. Gate: files match the case manifest; source and custody recorded; the answer key is unreachable in assessment mode; no malware execution required. |
| S08 | [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | Recorded defensive telemetry | Pair one permitted dataset with a rule and an analyst workpaper, including a plausible benign explanation. Gate: raw telemetry preserved; labels independently checked and withheld from the learner; the LICENSE/README licensing discrepancy resolved at a pinned revision. |
| S09 | [XBOW validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks) | Historical web challenge corpus | Retain for historical teaching and integration regression only. Gate: **the suite's own README describes it as saturated and no longer discriminating between models or frameworks** — results must be labeled historical/regression, and rotating flags does not erase public knowledge of a task's solution. |
| S10 | [FIRST EPSS and CISA KEV semantics](https://www.first.org/epss/) | Prioritization source semantics | Teach that exploitation probability, confirmed exploitation, technical severity, applicability, and business impact are different inputs. Gate: probability and percentile not confused; low EPSS never substituted for absence of exposure; missing data explicit. |
| S11 | [Microsoft Graph sendMail documentation](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0) | Authoritative permission and response semantics | The source-validation counterexample for the R38 case: verify permissions against the API owner, not a third-party tool's claim. Gate: read and send authority distinguished correctly; an accepted request is not graded as completed delivery. |
| S12 | [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma) | Detection-rule corpus and schema | Supply pinned rule examples with required log fields, status, and false-positive context. Gate: rule text, converted query, and observed events separately traceable; absent logs are not negative results; rule existence is not operating effectiveness. |

### Standing cautions

- **NetDraw (R06):** offline and source behavior is unresolved. An
  inspected browser UI establishes neither a reusable source license
  nor an offline contract.
- **Blackstorm (R27):** the full research page could not be reviewed.
  The entry stays deliberately conditional rather than being quietly
  omitted or filled in from search snippets.
- **THOR (R23):** the actual expert-labeled findings are not public.
  The metric design is reusable; the corpus is not available.
- **XBOW (S09):** the project describes its own public suite as
  saturated and regression-oriented. Treat it accordingly.
- **SANS (R41):** the landing overview was reviewed; the linked full
  framework downloads were not.
- **Source visibility is not reuse clearance.** Being able to read a
  repository, article, or dataset says nothing about the right to
  redistribute, bundle, or execute it. A missing permissive license
  means permission has not been established.
- **Promotion evidence remains candidate-specific:** selected revisions,
  licenses, data rights, hashes, dependency trees, and actual runtime
  behavior must be verified for the exact material a module would use.

## Proposed roadmap

The eleven exit intents remain open. Ten items are entirely **proposed**.
`GOV-01` now has an additive, checkout-only [partial
foundation](governance/README.md) for the PR 97 reader slice: it binds the
accepted capability inventory and records deliberately incomplete module,
source, runtime, relationship, currentness, and promotion state. It does not
satisfy the full `GOV-01` exit intent, establish currentness or promotion
evidence, change runtime admission, or edit the catalog. Sequence further work
by the dependency order below rather than by dates; continue one vertical
slice at a time.

Four program workstreams travel through this dependency graph rather than
creating a second roadmap: `GOV-01` owns the module/source/currentness
registers and governance of the `TEL-01`–`TEL-09` blueprints; `AUDIT-01` and
`EVAL-01` own instructor calibration and program evaluation; `SAFE-01` owns
operator environment profiles and safety cases; and the `PACK-*` work owns
accessible, maintained learning assets and retirement. Their public definitions are the
[curriculum](CURRICULUM.md), [instructor guide](INSTRUCTOR_GUIDE.md),
[operations guide](OPERATIONS.md), and [challenge authoring
contract](challenges/README.md#authoring-contract-for-new-content).

| ID | Priority | Title | Depends on | Exit intent |
|---|---|---|---|---|
| EVID-01 | P0 | Trusted observation and grading bridge | None | Tampered, missing, replayed, and unrelated observations fail; each finding cites valid evidence; current fixture-only grading stays compatible. |
| SAFE-01 | P0 | Assessment isolation and hard containment | None | Out-of-scope redirects, DNS, and subresources plus direct grader access are blocked; escaped or truncated attempts cannot pass; cleanup failures stay visible. |
| GOV-01 | P0 | Versioned resource and promotion register | None | No candidate becomes maintained merely by appearing in a survey; each promoted action has an owner, a regression case, and an explicit side-effect and egress contract. |
| DATA-01 | P1 | Frozen local vulnerability intelligence | EVID-01; GOV-01 | Read-only and denied-egress tests pass; unknown and stale data stay explicit; source and snapshot digests appear in evidence. |
| DATA-02 | P1 | Read-only rule intelligence | EVID-01; GOV-01 | No generation, index mutation, deployment, or hosted fallback; source-accurate results and missing-telemetry cases pass regression tests. |
| AUDIT-01 | P1 | Human workpaper and hypothesis rubric | EVID-01 | Independent reviewers can reperform the work; false assurance and unsupported claims fail; rubric weights are calibrated rather than claimed as an external standard. |
| PACK-01 | P1 | Foundation, cloud, web, and recorded-telemetry packs | AUDIT-01; SAFE-01; GOV-01 | Each pack has a learner brief, evidence manifest, instructor key, benign control, limitations, rubric, and reset/retention instructions. |
| EVAL-01 | P1 | Risk-sensitive metrics and all-attempt ledger | EVID-01; AUDIT-01 | Initial, tuned, and held-out results — and assisted versus unassisted — stay separate; every attempt remains in the denominator; saturated public benchmarks are labeled regression-only. |
| PACK-02 | P2 | AD/GPO and M365 evidence pack | PACK-01; EVID-01 | Filtered-GPO, stale-graph, and permission-misstatement controls are handled correctly; no real credentials or tenant data are required. |
| PACK-03 | P2 | Agent/MCP and virtualization packs | PACK-01; SAFE-01 | Tool-instruction injection and missing-telemetry cases are graded correctly; no active quarantine, cloud, or hypervisor action is implied by the course. |
| HEAD-01 | P3 | One controlled challenger-head experiment | EVAL-01; SAFE-01; PACK-01 | Benefit demonstrated on a frozen new holdout without worse safety, unsupported findings, or cost — otherwise do not integrate. |

**HEAD-01 is one experiment, not an adoption plan.** It runs at most
once, only after a specific gap has been *measured*, and only after
EVAL-01, SAFE-01, and PACK-01 exist. It runs as an isolated head under
the same approved capabilities, evidence rules, and aggregate budget as
the existing heads. A candidate that cannot produce a bounded action or
trustworthy evidence stays instructor reading; deferral does not erase
its useful method, and relevance does not force a runtime integration.

## Admission checklist

Before any candidate action becomes usable — and again, more strictly,
before it is promoted to maintained:

- **Pinned upstream revision and hashes** for the exact source used.
- **License and data-rights review** covering the code, any bundled
  corpus, and every upstream feed or dataset it depends on.
- **A named owner** accountable for the action.
- **Data classification** for everything the action reads, produces, or
  retains.
- **The exact action surface** — inputs, outputs, and the specific
  operations admitted, not the upstream tool's whole surface.
- **Side effects, egress destinations, cost behavior, and cleanup
  semantics**, stated rather than assumed.
- **Offline and denied-egress tests** where the action claims local or
  read-only behavior.
- **Provenance and uncertainty semantics** — observed, declared, and
  inferred stay distinguishable; unknown stays unknown.
- **Negative and inconclusive cases** exercised, not only the happy
  path: malformed input, missing dependency, denied scope, source
  drift, partial results, timeouts, unexpected tool listings, hostile
  content, and forged evidence.
- **A repeatable regression case** bound to a supported version range.
- **Explicit promotion evidence** that the actual deployed path works,
  with a stated known-limitations position.

A dependency appearing on PATH, or an MCP server listing a tool, never
arms anything by itself. **Documentation grants no execution
authority** — including this document.
