# Offline evidence learning: source decisions

Owner: specaudit-ctf maintainers. Decision and currency review: 2026-10-03.
Next review: 2027-01-03, or earlier on upstream schema, rights, safety, or
criteria changes. These references inform independently authored synthetic
cases. A source decision does not admit execution, install a dependency, attest
an observation, or promote a catalog support tier. The exact runnable formats
and constraints are specified by the local exercise and import contracts.

| Source and selected revision | Rights and selected use | Boundary and drift trigger |
|---|---|---|
| [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill/commit/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8), `c1c8a8c`, MIT | Methodological reference for a separately written coverage ledger and independent claim review; no skill text or examples copied. | Methodology-only catalog row, no agent workflow execution. Recheck phases and license before quoting or incorporating source material. |
| [OpenAI codex-security threat-model skill](https://github.com/openai/codex-security/blob/c0f5a5b/plugins/codex-security/skills/threat-model/SKILL.md), repository `c0f5a5b`, Apache-2.0 | Methodological reference for bounded architecture, attacker and trust-boundary hypotheses; synthetic workpaper and case independently written. | The upstream skill grants neither scanning authority nor an authoritative model for this repository. Recheck pinned file on method changes. |
| [autonomous-offensive-llm-handbook](https://github.com/mouteee/autonomous-offensive-llm-handbook/commit/23121579ff2d1236ffa0c6ca0cf219b26ff1d599), `2312157`, MIT with NOTICE | Deterministic fixture-harness design reference; original events, action policy and grader. No payload or prose copied. | A trusted software adapter is not an OS sandbox. Revisit if fixture semantics or licensing change. |
| [mubix/ai-ctf](https://github.com/mubix/ai-ctf/commit/33e2a21a551328fde8a968fef8fbb0b4b63835a3), `33e2a21`, MIT code | Scenario design reference for separately recorded attempts and tool actions; original offline exercise, no model, personas, flags, or external content copied. | Model/content rights are distinct from code rights. Revisit if importing upstream assets is proposed. |
| [GreyNoise, “Agents Gone Wild”](https://www.greynoise.io/blog/ai-orchestrated-campaign-against-papercut-ng-mf), 2026-09-09, TLP:CLEAR | Public incident analysis as context for observed behavior versus attribution; no campaign indicators or payloads copied. | Publisher's sensor account and attribution are source claims, not independently reproduced facts. Recheck corrections or new evidence before teaching those claims. |
| [Purple-Team-Automation](https://github.com/joshuagodwin7929/Purple-Team-Automation/commit/198ec33e), `198ec33e`, no root license found | Linked methodology only; an original synthetic event/rule/analyst packet supplies the exercise. | No source rule, report, screenshot or lab artifact redistributed. Rights review and format verification required before any source import. |
| [k8scout](https://github.com/k8scout/k8scout/commit/031c8bc4fc6579aab9d1df2e781697968028a427), `031c8bc`, MIT | Permission-path reasoning reference; original synthetic Kubernetes case and bounded captured-output parser where the pinned format is verified. | Live cluster collection and optional model egress are excluded. Format drift is a hard failure. |
| [Thunderstorm](https://github.com/ustayready/Thunderstorm/commit/c75a3d7d33626de36d7e7814cd8902c0d60469ad), `c75a3d7`, GPL-3.0 | Graph reasoning reference; synthetic data independently authored. | Collector output may include raw secrets. No collector, secret-bearing export, or GPL source bundled; any importer pins a verified format and refuses unknown sensitive fields. |
| [siftrank](https://github.com/noperator/siftrank/commit/03e7afe3289a204ea3dcc51613cea91877a651de), `03e7afe`, MIT | Offline evaluation of the documented captured ranking result shape, with original synthetic packets and custodian-held input/result hashes. The opt-in subprocess mode uses CLI flags verified against this pinned README. | Scores order review only and are not calibrated probabilities or accepted evidence. A caller-supplied hashed executable, provider credentials, explicit endpoint, external spend authority and containment are required for active ranking; no provider was called during this validation. Review model rights and backend egress before an experiment. |

All synthetic cases are E1: local files, no live credentials, target, service,
cloud account, cluster, network action, or third-party model call. A permitted
recorded export is source-declared until separately admitted and independently
verified; it does not enter the existing fixture-only finding grader.
