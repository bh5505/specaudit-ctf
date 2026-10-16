# vulnify arm

`vulnify` performs exact CVE-ID lookups over a frozen, operator-supplied local JSON snapshot. It is a stdlib-only in-process reader: no subprocess, endpoint, network access, database access, or lookup-time mutation.

Invoke `lookup` with `bundle_path` and a `cve_ids` list. The snapshot is an object keyed by canonical CVE IDs. Each value may contain `description` or `descriptions`, must contain `references`, and may contain `technique_mappings`. Missing enrichment is returned as `null` and is never inferred.

Every lookup outcome emits one canonical JSON custody receipt on stderr. The receipt binds normalized arguments, the loaded snapshot SHA-256 when available, per-ID status/reason, and the output SHA-256. The file is read once into a capped byte snapshot before parsing.

`data/demo-vulnerability-snapshot.json` contains fake deterministic records for tests and demos. It is not a current vulnerability corpus.
