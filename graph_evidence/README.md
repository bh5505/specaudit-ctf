# Offline graph evidence review (research slice)

This is an original, synthetic AWS permission-path exercise inspired by
Thunderstorm's permission/trust graph. It imports a **narrow subset** of RAGE v0.1 NDJSON records for offline
review. The standalone importer is also called by the research-tier
`learning-operator.graph_path` arm with inline evidence. It is not a full RAGE
parser, a trusted observation, an actual cloud/cluster test, or grading credit.
It never runs a collector.

The shape was checked against Thunderstorm
[`c75a3d7d33626de36d7e7814cd8902c0d60469ad`](https://github.com/ustayready/Thunderstorm/tree/c75a3d7d33626de36d7e7814cd8902c0d60469ad)
(`collectors/README.md`: `engagement.zip` contains `graph.rage.ndjson`) and its
RAGE producer contract, plus the pinned RAGE
[`edcbd1508ebadae7b414b0c1c82bab964d06cffb`](https://github.com/trustedsec/RAGE/blob/edcbd1508ebadae7b414b0c1c82bab964d06cffb/spec/format.md)
format, [schemas](https://github.com/trustedsec/RAGE/tree/edcbd1508ebadae7b414b0c1c82bab964d06cffb/schemas),
and [example](https://github.com/trustedsec/RAGE/blob/edcbd1508ebadae7b414b0c1c82bab964d06cffb/examples/minimal.rage.ndjson).
RAGE uses a line-one manifest, then `kind`-tagged records; `evidence → fact →
edge` is its provenance chain. The sample here is independently authored and
uses that wire shape; it is not an actual Thunderstorm scan or a copied export.
No upstream collector-produced sanitized sample has been validated.

From the repository root, using Python 3.11+:

```text
python3 -m graph_evidence graph_evidence/fixtures/synthetic-aws.rage.ndjson \
  --sha256 c09cc7d617c082dbf42b27bca63007a9d84d0290894499e10e67208b7445f496 \
  --source 'aws|000000000000|aws:iam:role|trainee' \
  --target 'aws|000000000000|aws:s3:bucket|practice-data'
```

The result has three branches: a configured candidate, an explicitly blocked
edge, and a route whose second receipt says collection was denied. The last is
`unknown`, not an allow or a clean bill of health. Even the configured branch
does not prove effective permission: SCPs, conditions, session policy, resource
policy, authentication, and runtime reachability are outside this packet. The
separate Kubernetes exercise handles k8scout's pod/service-account prerequisites;
this importer does not claim k8scout export compatibility.

An explicit projection mode accepts the second, independently authored,
source-shaped fixture with RAGE optional `conditions`, `permissions`, `weight`,
empty `attributes`, and auxiliary `surface`, `path`, and `finding` records:

```text
python3 -m graph_evidence graph_evidence/fixtures/synthetic-aws-projection.rage.ndjson \
  --sha256 5362a030dd5ddaa688f3d80f941b6962d7e82461b6557ed6c471f441bf1323ef \
  --source 'aws|000000000000|aws:iam:role|trainee' \
  --target 'aws|000000000000|aws:s3:bucket|practice-data' --project
```

`--project` validates the hash of the original bytes, makes a closed field
projection, validates the projected graph, and reports the original/projected
hashes and an omission ledger. It drops only enumerated auxiliary record fields
and known optional metadata. Any omitted edge field that affects permission,
condition, scope, derivation, or rule interpretation downgrades a non-blocked
edge to `UNKNOWN`; the configured branch in this fixture therefore becomes
unknown. A `BLOCKED` edge remains blocked. The importer does not run RAGE's
rule engine or interpret permission strings. Missing permission context is never
treated as an allow. A `path` record names edges but does not prove them;
those edges also become unknown when the record is omitted. Nonempty
`attributes`/`detail` objects are dropped without inspecting or echoing their
contents, and conservatively downgrade every non-blocked edge in this small
graph because their relevance is not known. Object-shaped `conditions` are
similarly dropped with their edge marked unknown.

The importer accepts only the closed manifest/node/evidence/fact/edge fields
used here (plus selected harmless RAGE sample metadata), one synthetic AWS realm,
an external exact SHA-256 for the file,
bounded UTF-8 NDJSON, explicit edge states and matching fact/receipt references.
It rejects unknown kinds and fields, duplicate keys or identifiers, drifted
versions, mismatched scope or digest, unbound references, and all raw-data
`pointer`, `detail`, `attributes`, `finding`, `surface`, and `path` records.
The pinned upstream example contains a free-text path `narrative`, which this
projection refuses. It also refuses raw `pointer`, `value_ref`, `location`,
unknown extensions, non-object free bags, and mismatched auxiliary
counts. Omissions have named counts, not a silent "ignore unknown" path. Even
with `--project`, most valid RAGE/Thunderstorm exports (especially secret-bearing
material) are rejected. A collector-produced sanitized export has not been
validated against this projection. The CLI reads
direct NDJSON only, not a zip or blobs,
and writes JSON to stdout only on success (invalid input exits 2). The caller's
expected digest binds supplied bytes, but does not authenticate the producer,
the collection, or the declared receipt hashes; no raw response bytes are
available to verify those hashes. Never treat a self-selected digest as custody
evidence.
