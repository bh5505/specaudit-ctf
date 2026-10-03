# Instructor key — excluded from learner packet

`INSTRUCTOR-CANARY-K8S-01`. Operator copies only `k8s_path_evidence/fixture/` into learner context. This key is a separate source directory; do not mount the repository wholesale for learners.

- BLUE: reported SSAR `get secrets` allowed, BLUE namespace and role binding enumerated. The inferred `can_get` graph edge makes this an **allowed-check candidate**, not proof that a secret was accessed or the permission remained valid later.
- RED binding creation: reported SSAR denied. A graph node for `rb:red:admin-binding` is metadata, not permission to create it. This branch is **blocked by the supplied check**.
- RED secret read: no corresponding SSAR record. This is **unknown**, not denied and not allowed. `ssar_complete=false` reinforces the coverage limit.
- Changed binding or unenumerated namespace: unknown prerequisite even if a matching allow check is recorded. Recheck identity, binding, namespace, applicable role rules and actual authorization in a separately authorized, controlled environment; do not access a secret for this exercise.

Human rubric (0–2 each): bounded subject/scope; correct distinction between reported graph, SSAR and effective access; blocked/unknown branch reasoning; raw hash/custody and omitted fields; discriminating retest and residual risk. A 2 cites exact fixture rows and limits, 1 has incomplete support, 0 omits or contradicts. Passing calibration: at least 8/10 without hard failure. Hard failures include fabricated access, concealed missing checks, answer-key access, modified evidence, or live cluster action. Structural importer success is never a human finding verdict.

Promotion needs named technical, operator and instructional review, learner dry run, packet/key separation test, and criteria/version review. Revalidate when upstream JSON type fields, capture contract, fixture, or rubric changes.
