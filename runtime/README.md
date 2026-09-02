# X3 deployable runtime

This directory builds the first deployable `agent-wiz.list_tools` runtime for
the SpecAudit validator. It is a real Linux x86-64 GNU Python runtime, not a
synthetic interpreter. `synthetic_only` remains the initial authorization
scope of the capability the validator may invoke.

The bundle contains a real CPython 3.11.16 ELF launcher, the exact eager
standard-library import closure, PyYAML 6.0.3, the complete eagerly imported
`extension` source closure, and their licenses. Since the stdio-MCP rebuild
the measured closure is the **union of both sealed invocations** — the CLI
one-shot (`-S -m extension invoke agent-wiz list_tools {}`) and the X4-VAL
stdio-MCP server (`-S -m extension.mcp_server`) — with `lock.json` recording
each invocation's own module names under `invocations`. The external Agent Wiz binary
is deliberately absent: `list_tools` reads bundled policy/catalog data, while
`extract`, `visualize`, and `analyze` remain unavailable without that binary.

## Platform contract

The only supported v1 target is Linux x86-64 GNU with glibc 2.17 or newer.
The launcher is dynamically dependent on the host GNU loader/glibc; the
lock records `/lib64/ld-linux-x86-64.so.2`, the six required glibc library
names, and the highest referenced `GLIBC_2.17` symbol version instead of
calling the bundle fully static.
Broader platform support requires a separate measured dependency update.

Artifact signing and SBOM/provenance generation or verification are not part
of this development phase. Their later operational design remains default
off and does not gate this runtime's build, installation, or validator pins.

## Build and verify

The builder itself uses only the Python standard library. Network access is
confined to the explicit fetch step; every subsequent step fails closed if a
locked cache input is absent or has the wrong size or SHA-256.

```text
python3 -m runtime.build fetch
python3 -m runtime.build lock-check --full
python3 -m runtime.build build
python3 -m runtime.build selfcheck
```

`build` creates ignored outputs below `runtime/.cache/build-out/`:

- `bundle/`: normalized runtime tree;
- `bundle.tar.gz`: normalized deterministic archive;
- `bundle.reextracted/`: archive round-trip used for verification/smoke;
- `bundle.manifest.json`: deterministic digest/input/source metadata;
- `bundle.timings.json`: intentionally separate measured timings.

The build re-extracts the archive, reapplies the strict mode contract, checks
the exact locked file inventory, recomputes the canonical tree and launcher
digests, then runs the validator-shaped Mode-A command: absolute bundled ELF,
bundle-root cwd, `-S`, cleared environment except `PYTHONHOME`,
`PYTHONNOUSERSITE=1`, and `PYTHONDONTWRITEBYTECODE=1`, plus a fresh attempt id
and artifact directory. The smoke test requires a complete envelope and a
digest-matching custody artifact. It has no `PATH`, `AGENT_WIZ_BIN`, home, user
site, ambient credentials, or network bootstrap.

`selfcheck` discards staged extractions between two assemblies and requires
identical launcher digest, canonical tree digest, and archive bytes. The
archive fixes gzip/tar ordering, timestamps, uid/gid, owner/group names, and
modes. The `availability` host command is deliberately NOT part of the sealed
bundle: it is a read-only operator report, not a sealed invocation, so
`extension/availability.py` stays outside the traced producer closure.

The tree digest is the cross-language
`specaudit.ctf.producer-tree.v1` algorithm in `tree_hash.py`; the committed
`tree-v1-vector.json` is the handoff vector for the Rust consumer.

Measured on the 2026-08-26 build host with verified inputs already cached:
offline build wall time was 10.49 s, cold and warm full-tree verification were
0.271 s and 0.270 s, cold and repeat Mode-A launch were 0.570 s and 0.568 s,
and the two archive-backed selfcheck was 17.06 s. Re-measured 2026-09-01 on
the WSL Ubuntu 26.04 rebuild host after the stdio-MCP closure landed (96
producer files): assemble 2.61 s, pack 4.09 s, cold/warm full-tree
verification 0.197 s / 0.196 s, cold and repeat Mode-A CLI launch 0.484 s /
0.435 s, cold and repeat sealed stdio-MCP server launch 0.410 s / 0.410 s.
The resulting launcher, tree, and normalized-archive SHA-256 values are
respectively `bba9c526…8c94` (unchanged — same locked CPython input),
`e09fef70…2451`, and `68e41710…7d58` (2026-09-02: page-fetch.fetch admission — ten dispatch profiles; catalog-note caveat; registry + X2-PUB docstring repairs). A 5 s cold startup
verification ceiling is the conservative initial handoff recommendation for
the validator packet; it is operator-configured there, not silently enforced
by this producer. Re-measure before changing the platform or dependency lock.

## Locks and dependency updates

`lock.json` fixes input URLs, names, versions, sizes and SHA-256s, the ELF
launcher digest, the full traced module/file closure with per-file SHA-256s,
all 96 producer source files, license/metadata bytes, and the public
`agent-wiz.list_tools` capability-manifest bytes. The lock and runtime
metadata stay outside the measured tree to avoid self-reference.

For an intentional source/dependency update:

1. update and independently verify the input record;
2. run `fetch` explicitly;
3. run `python3 -m runtime.build lock-write`;
4. inspect every closure/content change;
5. run the runtime tests, `build`, and `selfcheck` before review.

Do not hand-edit a digest to silence drift. An unexpected import, source byte,
extra/missing file, write bit, link, non-regular file, archive difference, or
custody mismatch is a refusal.

## Installation and rollback

The runtime producer does not choose a host path. An operator installs one
complete verified bundle at a privileged, non-user-writable versioned path,
then points the validator's atomic pin object at that version. Rotation stages
and verifies a new complete directory before switching the pin/config unit.
Rollback switches back to the retained prior complete directory and prior
complete pin unit; never mix launcher, tree, manifest, or config fields across
versions.

After installation, run `python3 -m runtime.build verify /absolute/bundle`
from a trusted checkout and compare the launcher/tree values with
`bundle.manifest.json` and the validator configuration. The subsequent
AuditPack runtime-pin packet owns host path/owner/ancestor checks and startup
time policy.
