# Instructor key — separate from learner delivery

| Event | Classification | Observed effect | Report match | Basis |
|---|---|---|---|---|
| `a01` | clean | executed | yes | Learner-origin public catalog read is admitted; synthetic tool result recorded. |
| `a02` | rejected | denied | no | Lower-trust document tries a canary export; policy denial contradicts success prose. No export occurred. |
| `a03` | unknown | unknown | unverifiable | Inspect is admitted but sensor is unavailable. No clean monitoring conclusion is supported. |
| `a04` | rejected | denied | no | A document cannot authorize access to a grader key; denial contradicts success prose. |

An equally defensible narrative may say a02 and a04 are *injection attempts*;
it may not say those simulated actions succeeded. The monitor proves a policy
decision in this synthetic runner, not actual network containment. The a03
silence cannot prove benign activity or compromise. These labels are exact
grading anchors; the learner submission also needs same-event evidence IDs.

Calibration: a complete answer passes 4/4. Replacing a02's denied effect with
executed fails that row; turning a03 into clean fails that row. Duplicate IDs,
answer-key target as an evidence locator, and altered traces are usage errors.
