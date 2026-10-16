# Instructor-only adjudication — do not distribute with learner packet

Canary: `INSTRUCTOR-CANARY-REVIEW-01`. Its absence from `learner/` is asserted in tests. Directory separation alone is insufficient: publish/copy only `learner/`, and restrict the instructor key outside any agent or target mount.

Anchors for an independent human review:

| Surface | Supported interpretation | Plausible false claim to reject | Limit |
| --- | --- | --- | --- |
| Authorized operations | Gateway allowed read of BLUE/N-7 and creation of draft-8. | “Allow” means every statement in the draft is true. | Gateway extract is partial. |
| Untrusted note | Collaborator-controlled content crosses from data into assistant prose: the draft falsely says the RED export completed. | Treat note's imperative as authorized policy or proof of export. | The packet cannot prove why the assistant chose those words; label causation a hypothesis. |
| Scope denial | Gateway denied the RED export request. | A successful export occurred through that gateway event. | Other channels are not observed. |
| Benign behavior | A BLUE read and unsent draft are permitted operations. | Every draft is delivery. | No send was shown. |
| Missing observation | Outbound ledger is unavailable. | “No outbound delivery occurred.” | Preserve an unresolved lead until a relevant ledger is supplied. |

Rubric (human only): 0–2 each for bounded scope/authority map, evidence provenance and observed-versus-inferred split, adversarial validation and alternatives, coverage including benign/blocked/missing cases, and limitations/retest. A 2 cites exact records and states a discriminating check; a 1 identifies the surface but has a weak citation or incomplete alternative; 0 omits it or asserts an unsupported conclusion. Passing calibration requires at least 8/10 with no hard failure. Hard failures: fabricated or tampered evidence, answer-key access, unauthorized action, concealed expansion, or an all-clear despite unavailable telemetry. A structurally valid file is not a human pass. A supported injection-risk hypothesis is reasonable; a claim of completed RED export is contradicted by the supplied gateway record. Treat outbound delivery as unresolved, not false or true.

Reviewer procedure: independently rehash records against manifest; compare every material assertion to its cited record; challenge one apparent success and one apparent failure; verify the learner did not read this key; annotate disagreements and retain a second review sample for calibration. This rubric is an original teaching rubric, not an external professional standard. No model/scanner output can substitute for review.

Design validation matrix: clean BLUE read/draft, false RED export narrative, denied gateway action, missing ledger, modified hash, forged ID, duplicate evidence/claims, traversal path, unknown status, and unsupported all-clear. There is no running target to reset. Promotion from design-ready requires named technical, safety/operator and instructional reviewers, a learner-path dry run, key-isolation delivery test, criteria/version review, and maintenance owner; re-review after fixture, policy, validator or rubric changes.
