# Data notice — demo-enterprise-sample.json

© 2026 The MITRE Corporation. This work is reproduced and distributed
with the permission of The MITRE Corporation.

This file is a small verbatim SAMPLE of the MITRE ATT&CK STIX 2.1
corpus, shipped as offline demo data for the `attack-stix-data` read
arm. It is data, not code, and it is not maintained here: the
authoritative corpus lives upstream.

Provenance:

- Source: https://github.com/mitre-attack/attack-stix-data
- File: `enterprise-attack/enterprise-attack.json` (latest unmarked
  snapshot at sampling time)
- ATT&CK version sampled: 19.2 (collection modified 2026-08-05)
- Sampled 2026-09-04

Sampling criteria (55 objects, verbatim content):

- 18 `attack-pattern` objects: the cloud/identity technique families
  this suite rehearses (valid accounts, cloud account manipulation,
  cloud storage and infrastructure discovery, unsecured credentials,
  cloud logs impairment, and related sub-techniques).
- 2 `tool` objects and 2 `intrusion-set` objects that use those
  techniques in the upstream corpus.
- 31 `relationship` objects (`uses`, `subtechnique-of`) between the
  sampled objects only.
- The bundle's `identity` and `marking-definition` provenance objects.

The bundle id is a synthetic placeholder
(`bundle--00000000-0000-4000-8000-000000000001`): the file is a subset,
not the upstream bundle. Object contents and STIX ids are verbatim.

To refresh the sample: re-download the upstream file, re-apply the
sampling criteria above, and update this notice. Lookups against a
current corpus should use an operator-supplied bundle, not this demo
subset.
