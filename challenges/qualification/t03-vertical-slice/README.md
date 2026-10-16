# T03 vertical slice — prioritize synthetic assets against the pinned vulnify demo slice

**ID:** `t03-vertical-slice` · **status:** qualification-ready · **domains:** CYB-04, ASM-02 · **audience:** analyst · **version:** 0.1.

**What qualification-ready means here (defined once, in
[`challenges/README.md`](../../README.md#validation-and-promotion)):** every
qualification gate for this slice is enumerable, and **none is satisfied**.
It is a gate inventory, not a promotion signal; promotion remains the
operator gate. The gates are the ones the four records under
[`../records/`](../records/) enumerate for the pilots: named technical,
safety/operator and instructional reviewers (currently assigned, unstaffed,
wholly operator-gated); learner-context separation proof; human-scored
calibration; an executed learner-path dry run; and tested reset evidence.

## Learner brief

You hold a synthetic inventory of five assets (`inputs/assets.json`). The
only vulnerability truth you may use is a pinned, frozen demo snapshot —
first-party synthetic demo data, not a current vulnerability corpus — pin
and digest gate in `reader_evidence.data_slices.vulnify_demo_slice()`. Query
it and prioritize all five assets. Exactly one of these will happen per
distinct CVE:

- **Mapped.** The slice returns a record with technique enrichment; rank the
  asset on that, citing the snapshot digest.
- **Unaffected near-miss.** The slice returns a record whose technique
  enrichment is absent. Describe the asset, claim no technique, and do not
  let a plausible-looking description become a finding.
- **Unknown stays unknown.** The slice does not know the id. The outcome is
  `unknown`, never an all-clear and never an invented severity.

Submit one JSON document: `{"schema": "specaudit.t03-prioritization.v1",
"slice_sha256": <digest from the lookup>, "prioritization": [{"asset_id",
"cve_id", "rank", "basis" ("mapped" | "near-miss" | "unknown"), "statement"}]}`
— every asset exactly once, ranks total, and a statement per asset saying
what the slice did and did not establish.

## Operator machine-check procedure (run script snippet; not auto-run)

The machine check is the vulnify arm under the containment guard, with
`reader_evidence` acquisition on the packet inputs and the slice digest
gate. Operator stages the packet, then:

```python
from datetime import datetime
from pathlib import Path

from containment.harness import run_case
from containment.profile import OperatorProfile
from reader_evidence import acquire
from reader_evidence.data_slices import (vulnify_demo_slice,
                                         verify_slice_bytes)

packet = Path("/srv/operator/approved")          # staged learner packet root
slice_path = packet / "inputs" / "demo-vulnerability-snapshot.json"
verify_slice_bytes(vulnify_demo_slice(), slice_path.read_bytes())  # digest gate

profile = OperatorProfile(
    approved_root=str(packet),
    scratch_root="/srv/operator/scratch",
    # Read the marker from the operator-held instructor KEY; never embed
    # canary bytes in anything learner-visible.
    canaries=("<instructor-canary-marker-from-KEY>",),
)
case = run_case(
    profile, arm_id="vulnify", action="lookup",
    payload={"cve_ids": ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-9999"],
             "bundle_path": str(slice_path)},
)
assert case.outcome == "positive" and not case.denials
```

Then ledger every attempt (completion plus at least one negative class),
close one evidence chain, write `dry-run-summary.json`, and validate:

```sh
python challenges/qualification/dry-run/validate.py --dir <dry-run-dir> --as-of 2026-10-13
```

The instructor key (`instructor/KEY.md`, carrying this slice's instructor
canary marker) is not a learner asset: mount only this README and `inputs/`
into the learner context. This slice is E0 offline synthetic: no network, no
model calls, no real targets; stop on any request to use real assets or
hidden assessment files.
