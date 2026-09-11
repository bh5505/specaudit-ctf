# attack-stix-data arm

Offline, exact ATT&CK STIX reads. `cvelookup` accepts JSON arguments only,
uses no shell or network, and defaults to the bundled demo when `bundle_path`
is omitted.

```text
python -m extension invoke attack-stix-data cvelookup \
  '{"cve_ids":["CVE-2099-0001","CVE-2099-9999"]}'
```

Input:

```json
{"bundle_path":"/local/enterprise-attack.json","cve_ids":["CVE-2099-0001"]}
```

`bundle_path` is optional. Output is the execution envelope whose `output`
contains one result per requested id:

```json
{
  "reason": null,
  "results": [
    {
      "cve_id": "CVE-2099-0001",
      "status": "matched",
      "reason": null,
      "matched_objects": [{"stix_id":"...","type":"attack-pattern","name":"...","description":"...","external_references":[],"x_mitre_version":"..."}],
      "count_matched": 1
    }
  ],
  "count_matched": 1
}
```

Every invocation writes one JSON custody-receipt line to stderr. It contains
only normalized identifiers or hashes—not the raw argument vector—and records
the normalized argument hash, bundle hash when readable, per-query status,
match count, and output digest.

| Reason code | Meaning |
|---|---|
| `unknown_cve` | A well-formed CVE id has no matching object in the bundle. |
| `malformed_id` | A list item is not `CVE-YYYY-NNNN...`. |
| `bundle_missing` | The selected local bundle is absent or refused by path policy. |
| `bundle_invalid_json` | The bundle is unreadable, invalid JSON, or not a valid STIX bundle. |
| `cve_ids_not_a_list` | `cve_ids` is absent or is not a JSON list. |
| `input_refusal` | Caller arguments contain keys outside the closed schema. |
| `output_too_large` | Matched projections exceed the arm output cap. |

The demo's fake CVE mappings are documented in [NOTICE.md](NOTICE.md); use a
current operator-supplied ATT&CK bundle for real mappings.
