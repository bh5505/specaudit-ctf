# CTF tool campaign source record

This records the sources checked for the HostBadger, IDWolf, OSV, and Solidity-review additions in PRs #14–#19 and the follow-up alignment work. It describes the shipped **synthetic** readers and challenge; it does not establish the accuracy of an upstream security finding or authorize collection against any target.

| Source and pinned revision | Observed contract and excluded effects | Rights and retained material |
|---|---|---|
| [HostBadger `30129c6`](https://github.com/g4bri-3l3/HostBadger/tree/30129c62808074ab0cad589a49563d9c958f2bde) | [JSONL writer](https://github.com/g4bri-3l3/HostBadger/blob/30129c62808074ab0cad589a49563d9c958f2bde/lib/Reporting.ps1#L47-L114) emits finding/resolved rows and one `host_summary` per host. Its summary derives `findings` and severity counts from current findings; `not_evaluated` and its check list report coverage gaps. The CTF reads JSONL only; upstream collection, remediation, AI, and network paths are outside this arm. There is no signed export manifest or total expected host count. | [MIT](https://github.com/g4bri-3l3/HostBadger/blob/30129c62808074ab0cad589a49563d9c958f2bde/LICENSE). Public CTF fixture is original synthetic data, not a copy of upstream demo output. |
| [IDWolf `82b95c9`](https://github.com/g4bri-3l3/IDWolf/tree/82b95c9a5bc81944f44eaa838c422624f4ae0937) | [JSONL writer](https://github.com/g4bri-3l3/IDWolf/blob/82b95c9a5bc81944f44eaa838c422624f4ae0937/lib/Reporting.ps1#L29-L105) emits finding/resolved rows and a summary per run, preserving `source_kind`, domain and Entra tenant identity. Its summary derives total and severity counts from current findings and carries coverage/unevaluated fields. The CTF reads local JSONL only; AD/Entra collection, password-quality, AI, and network paths are outside this arm. No external run inventory proves that a file contains every run. | [MIT](https://github.com/g4bri-3l3/IDWolf/blob/82b95c9a5bc81944f44eaa838c422624f4ae0937/LICENSE). Public AD, Entra, and partial fixtures are original synthetic data. |
| [OSV schema](https://ossf.github.io/osv-schema/) and [v1 query API](https://google.github.io/osv.dev/post-v1-query/) | A record has an OSV `id` and `modified` value; `aliases` are not identity. `affected` package/version or commit evidence and pagination tokens determine query scope. The CTF snapshot is a deliberately narrower versioned container; its offline version helper compares only dotted-numeric versions or explicit `versions` entries. The live client sends bounded package/version or commit queries to the fixed official host, never a repository scan. A snapshot cannot prove freshness; a live match cannot grade the Solidity defect. | OSV aggregates sources with differing rights; there is no blanket redistribution decision for all records. The public snapshot is original synthetic OSV-shaped data. No verbatim live advisory is retained in this repository. |
| [Cloudflare security-audit-skill `c1c8a8c`](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8) and [Pashov skills `eacfc09`](https://github.com/pashov/skills/tree/eacfc09b365d2697b83355909d0300607e596ffc) | Methodology references only; the catalog cannot invoke or install these skills. The [challenge workflow](../challenges/lab-contract-01-solidity-review/METHODOLOGY.md) is original CTF prose and maps candidate, witness, coverage, and verified finding artifacts to the structural grader. | Both repositories carry MIT licenses at the pinned revisions ([Cloudflare](https://github.com/cloudflare/security-audit-skill/blob/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/LICENSE), [Pashov](https://github.com/pashov/skills/blob/eacfc09b365d2697b83355909d0300607e596ffc/LICENSE)); no skill text or generated report is copied into the CTF. |

The reader parser contracts are scoped to the observed pinned serializers. Unknown tool versions, missing run summaries, malformed rows, or count mismatches cannot certify complete source coverage. Even a complete file establishes only what that file says about its listed hosts or runs.

## Synthetic fixture pins

These SHA-256 values freeze the public demo inputs. Names, identities, findings, and timestamps in the files were written for this CTF; they are not collected host or tenant data.

| Input | SHA-256 |
|---|---|
| `extension/arms/hostbadger/data/demo-hostbadger-report.jsonl` | `1d86375af2ee5297b699b93ff08d40d5b979f68a662e9ea0dd7e0dc16ce82be2` |
| `extension/arms/idwolf/data/demo-idwolf-ad.jsonl` | `1a3b6213a19846032fd23514577b41797cfef45c8edc83bc3ed131acce79e560` |
| `extension/arms/idwolf/data/demo-idwolf-entra.jsonl` | `11886a9cc71fa9425daf18958ed8a783be4abfa4cd53b55dba52150d96797320` |
| `extension/arms/idwolf/data/demo-idwolf-partial.jsonl` | `452010fa57a0930769df11070a045a0f8d988e3164ed73e8ed6deccfd26ce284` |
| `extension/arms/osv/data/demo-osv-snapshot.json` | `1e6de48be94b2110d11a9543289d0b2e54a26f01b6d0b3ab485c7a52892e2480` |

## Exploit-watch research boundary

The [archive manifest at `4388315`](https://github.com/dinosn/exploit-watch-archive/blob/438831543b4a26bf432fa78336e274bb098bf88c/MANIFEST.json) says it was generated `2026-10-22T11:51:58Z` and lists **15** sources: 14 marked `ok` and one `OWNER/REPO` placeholder marked `unreachable`. That is an index snapshot, not proof of exploit validity or current reachability. The archive root at this revision has no license file; each candidate requires its own rights check. No archive content, payload, downloader, or executable is included in the CTF.

One **future** synthetic scenario candidate is an advisory-triage exercise inspired by the manifest's `mandiant/Vulnerability-Disclosures` entry at upstream commit [`ec2c625`](https://github.com/mandiant/Vulnerability-Disclosures/tree/ec2c62514545f6f412695a7debc0a28254a2f959). The direct [Mandiant advisory `MNDT-2026-0001`](https://github.com/mandiant/Vulnerability-Disclosures/blob/ec2c62514545f6f412695a7debc0a28254a2f959/2026/MNDT-2026-0001.md) identifies a web-application input-validation case and a CVE; this check establishes only that the upstream advisory exists, not that its claims or any exploit were independently reproduced. The upstream [README](https://github.com/mandiant/Vulnerability-Disclosures/blob/ec2c62514545f6f412695a7debc0a28254a2f959/README.md) assigns CC BY-SA 4.0 to advisory information and MIT to source code. Any later CTF exercise should write its own synthetic service, evidence, and ground truth; it must separately verify vendor facts and any proposed verbatim reuse before importing them.

## Live OSV smoke

A single benign query was sent from the feature worktree to `https://api.osv.dev/v1/query` on `2026-10-24T02:05:25Z`:

```json
{"package":{"ecosystem":"PyPI","name":"jinja2"},"version":"3.1.4"}
```

The arm returned `complete`, HTTP 200, one page, six contextual advisory records, and no continuation token. The page request SHA-256 was `9d3697bfb1c12d9efedfa5537ca79c0f0c1efd7316cdaddb15db8267053a6f69`; the response SHA-256 was `a7a32451061fc05670bccd7401c54be3af6e7a5d5f95d91cf8e3d71ef63c385b` over 14,597 bytes. This is a witnessed live transport result at that time, not a frozen expected answer or challenge grade. The test suite uses fake transports and does not contact OSV.
