# Asset reconnaissance — scope, evidence and learning

`asset-recon` is the unified asset-association capability. It combines bulk
certificate-transparency (CT) and reverse-DNS (PTR) evidence with forward DNS,
certificate fingerprints, ASN/registry context and optional Shodan records.
The result is a bounded, explainable candidate graph for inventory review.
An association is neither legal ownership proof nor permission to test a host.

This is the capability's operator and teaching reference. The [extension
contract](../extension/README.md), [operations](../OPERATIONS.md),
[curriculum](../CURRICULUM.md) and [instructor guide](../INSTRUCTOR_GUIDE.md)
link here rather than maintaining separate CT and PTR procedures. This is a
runtime capability and an analyst exercise, not an agent skill.

## Actions and authority

Use the existing CLI or MCP `invoke` tool; no additional MCP tool is required.

| Action | Purpose | Authority boundary |
|---|---|---|
| `list_tools` | Inspect the supported actions and arguments. | Local metadata only. |
| `plan` | Normalize seeds, exclusions and limits before collection. | No evidence-file reads or network requests. |
| `parse` | Import explicitly supplied local provider fixtures. | Offline; input provenance is a supplied claim, not independently authenticated provider evidence. |
| `discover` | Traverse associations from seeds using fixtures, or explicitly armed providers. | Offline by default; provider access requires explicit live selection and provider grants. |
| `ct` | Collect bounded CT evidence for the supplied seed batch. | Provider collection must be explicitly armed. |
| `ptr` | Collect bounded PTR evidence for supplied IPs. | DNS provider collection must be explicitly armed. |
| `probe` | Observe only a separately supplied list of literal-IP targets. | Independently armed, non-recursive target contact; discovery never invokes it. |

Provider reads are not zero-egress operations. Query names, fingerprints and
addresses are disclosed to the selected provider; DNS resolvers may consult
authoritative infrastructure. Specify permitted providers, purposes, costs,
data handling and the time window in the rules of engagement. A provider grant
does not authorize service contact with a candidate, and a probe grant does not
authorize additional providers. Offline exercises require neither grant.
Live acquisition runs in bounded worker processes, so its declared effects
include both subprocess execution and network egress. This is not a
network-only metadata read.

The public surface is deliberately narrower than a general scanner. Discovery
does not open candidate web pages, connect to their service ports, launch a
scan, crawl links, test credentials, exploit a vulnerability or provision
infrastructure. Keep external containment and independent monitoring required
by [Operations](../OPERATIONS.md#enforce-containment-outside-the-workload).

Inspect the interface and a no-egress plan from the checkout root, using the
installed Python 3.11+ environment (`python3` here):

```sh
python3 -m extension describe asset-recon
python3 -m extension invoke asset-recon list_tools
python3 -m extension invoke asset-recon plan '{"seeds":{"domains":["example.test"],"ips":["192.0.2.10"]},"exclusions":{"domains":["shared.example.test"],"networks":["192.0.2.0/24"]},"limits":{"max_depth":2}}'
```

Arguments are closed JSON objects. `seeds` contains `domains`, `fingerprints`
(64 hexadecimal SHA-256 characters), `ips`, `asns` and bounded `networks` lists; `exclusions`
contains `domains` suffixes and `networks` CIDRs. Unknown fields and invalid
values are refused. `plan` does not read fixtures. `parse` requires explicit
local `fixtures` entries with `source` and an absolute regular JSON-file `path`.
`discover` uses supplied fixtures without `live: true`; live collection requires
the selected `providers` and matching `ASSET_RECON_PROVIDERS` grants. `ct` and
`ptr` are explicit live-collection actions and require `live: true`; `ct`
accepts only domain seeds, while `ptr` accepts literal-IP seeds (including
bounded expansion from `networks` or `targets_file`). Use `parse` to process
recorded CT or PTR evidence offline.

For bulk input, `seeds.domains_file` is an absolute regular JSON file containing
an array of domain strings; `seeds.targets_file` contains an array of IP strings.
These are JSON arrays, not line-delimited files. File and inline values together
are capped at 64 domains and 256 IPs. Up to 16 seed CIDRs are accepted, each with
at most 256 addresses; expansion is capped at 512 seed nodes. IPv4 network and
broadcast addresses count toward expansion. Exclusions still apply. `plan`
refuses both file fields because planning does not read files. Reports retain
the byte hashes in `context.domains_file_sha256` and
`context.targets_file_sha256`; preserve the original files for reperformance.

### Provider selection

`ASSET_RECON_PROVIDERS` is a comma-separated list of exact provider IDs. Select
providers again in the request; no endpoint URL or silent provider fallback is
accepted. `ct` defaults to `crtsh`, `ptr` to `google`; live `discover` requires
an explicit selection. Use `organization_hints` for up to 16 declared business
names to help interpret registry associations, never as verified ownership.

| Provider | Action family | Collection boundary |
|---|---|---|
| `crtsh` | `ct`, `discover` | Exact-domain and subdomain queries; returned snapshot is not exhaustive coverage. Live fingerprint queries are unsupported. |
| `certspotter` | `ct`, `discover` | Unexpired issuances, subdomains and matching wildcards, paginated by opaque `after` cursor until empty or bounded. Optional `CERTSPOTTER_TOKEN`. |
| `google`, `cloudflare` | `ptr`, `discover` | Fixed DoH endpoints; A/AAAA forward and PTR reverse evidence, with CNAME answers retained. |
| `registry` | `discover` | RIPEstat network/ASN context, holder and announced-prefix evidence; prefixes do not become automatic address sweeps. |
| `shodan` | `discover` | Optional seed/host/fingerprint evidence using `SHODAN_API_KEY`; no scan submission. Bounded result pages remain qualified. |
| `dns` | Offline fixtures only | Normalized recorded DNS rows; never a live provider grant. |

All live provider IDs are also fixture source IDs. The shipped teaching packet
uses `crtsh`, `dns`, `registry`, and `shodan`. Reserved documentation domains,
IPs and ASNs are allowed offline and omitted from live queries. Certificate
fingerprint seeds work with recorded evidence or optional Shodan associations;
they do not imply a crt.sh fingerprint API. There is no persistent cache or
`cache_dir` argument. Archive approved evidence explicitly through custody.

Cert Spotter's unexpired search is not historical coverage of every certificate.
Wildcard matches remain patterns rather than generated hosts. Every cursor page
and retry spends the same request budget; a stopped traversal remains partial.
Provider rate errors are limitations, not authority to bypass quotas or create
another account. [SSLMate CT Search API](https://sslmate.com/help/reference/ct_search_api_v1)

## Seed and exclusion decisions

Begin with justified root domains or SHA-256 certificate fingerprints; explicit
IP and ASN seeds provide additional starting context. Preserve why the operator
selected each seed. A seed is a declaration of investigative interest, not a
verified asset-ownership assertion. A fingerprint identifies certificate bytes;
it does not identify a unique tenant or the host currently serving those bytes.

Domain exclusions match the named suffix and its descendants at label
boundaries. IP-range exclusions remove covered addresses. Exclusions override
starting seeds as well as subsequently encountered candidates. For example,
include an operator egress address range in exclusions even if an imported
record or initial IP list also contains it. Record the reason and reviewer for
an exclusion: excluded means intentionally outside this procedure, not secure,
unreachable or absent from the real estate.

Do not use a graph's high-confidence candidates as a probe allowlist. An analyst
must review a candidate, obtain the action-specific authorization, and enter
the explicit target separately. Excluding a candidate IP does not exclude the
provider infrastructure used to query public evidence; network egress policy
must cover that separate channel.

## Reading the graph

Follow each candidate back through its edges to a seed and the source evidence.
Keep three layers distinct: provider-reported observations, operator seed
declarations, and the engine's inferred owned-or-managed association. Repeated
copies of one record are not independent corroboration. Confidence explains
the evidence supporting an association; it is not a calibrated probability,
a legal determination, a control-effectiveness verdict or an arming decision.

Each node's `association` contains the deterministic score, grade and supporting
signals/reasons. Grades are `strong` at 80+, `moderate` at 55–79, `weak` at
25–54 and `unassessed` below 25. Relation-specific caps and path decay qualify
certificate, forward-DNS, reverse-DNS, registry and provider signals; repeated
records do not contribute an unlimited vote. Follow signal evidence identifiers
to retained evidence and review the alternative explanation before using a
grade in a workpaper. `organization_hints` remain operator declarations.

| Signal | Useful inference | Counterexample the analyst must consider |
|---|---|---|
| CT name / certificate fingerprint | A certificate record connects names or a known certificate to other evidence. | Issuance is historical; renewal, revocation, misissuance, shared certificates and retired names complicate attribution. |
| Forward A/AAAA or alias | A name was reported as pointing to an address or another name. | CDN, anycast, shared hosting and outsourced services do not make the whole address range an owned asset. |
| PTR | The reverse zone reports a name for an address. | The address holder or its delegate can configure PTR; a customer-looking name need not prove the named organization controls the host. |
| Forward/reverse agreement | Two DNS directions are consistent in the evidence. | Agreement can be configured by one party, be stale, or refer to shared infrastructure; it is corroboration, not ownership proof. |
| ASN / registry | Resource registration and network context help identify potential operators or suppliers. | A registered allocation, routing relationship and customer-service responsibility are different facts. Never enumerate an entire ASN as an automatic target expansion. |
| Shodan record | A provider observation connects a host, service or certificate to the investigation. | Observation age, incomplete coverage and provider classification affect applicability; absence is not proof of no service. |

Wildcard certificates describe an identity pattern; they do not enumerate
existing hosts. For TLS service identity, RFC 9525 allows a wildcard to match
one leftmost label under its matching rules. That is distinct from wildcard
DNS behavior. A CT parser recognizing `*.example.test` must not invent all
possible subdomains. [RFC 9525, section 6.3](https://www.rfc-editor.org/rfc/rfc9525.html#section-6.3)

CT supplies append-only certificate history rather than a current service
inventory. Preserve source validity and observation times when supplied; the
time this run collected a record is not its issuance or last-seen time.
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html)

PTR authority follows reverse-DNS delegation. Forward/reverse consistency is a
useful operational check, but missing PTR is not evidence that an IP is unused.
[ARIN reverse DNS](https://www.arin.net/resources/manage/reverse/),
[RFC 1912, section 2.1](https://www.rfc-editor.org/rfc/rfc1912.html#section-2.1)

## Bounds, partial results and custody

Choose a depth, graph size, request count, record count, output-byte and wall-time
budget before collection. Recursive here means bounded association traversal,
not an unbounded Internet crawl or recursive service probing. A reached bound,
provider error or malformed source must remain visible as a limitation. A
usable partial graph is useful work, but is not a complete inventory.

| `limits` field | Default | Accepted range |
|---|---:|---:|
| `max_depth` | 3 | 0–5 |
| `max_nodes` | 500 | 1–1000 |
| `max_edges` | 1000 | 1–2000 |
| `max_requests` | 16 | 1–32 |
| `max_records` | 2000 | 1–4000 |
| `max_output_bytes` | 262144 | 4096–1048576 |
| `wall_seconds` | 30 | 1–60 |
| `min_interval_ms` | 250 | 50–2000 |
| `retries` | 0 | 0–2 |

These are per-invocation bounds, not permission to multiply a campaign's total
budget by launching more invocations. Pin separate aggregate rate/cost limits
in the operator environment. Provider restrictions and incompleteness remain
relevant even when no local budget is reached.

The report's compact `context` records effective limits, provider/fixture-source
selection and hashes/counts for effective seeds and organization hints.
`context.exclusions.policy_sha256` binds normalized exclusion policy without
echoing suppressed values. Retain the original request with its own custody:
these digests identify policy, but do not reconstruct it. `plan` additionally
shows normalized policy and excluded-seed count and states
`collection_performed: false`.

Preserve the returned document, effective seeds/exclusions/limits, action,
provider selection, request accounting, source locators and available record
timestamps. Keep input file hashes and the exact checkout revision with offline
exercises. Evidence identifiers connect graph claims to retained source data;
a locally calculated hash proves byte identity, not that a provider signed or
independently verified those bytes. Never promote a provider label into an
observed business-owner claim without corroborating evidence.

The outer CLI/MCP result uses `specaudit.ctf.execution-result.v1`. Interpret its
status and limitations, not only process or transport success. Normal CLI
stdout contains the envelope and artifact digest, not the graph bytes. Use
the existing Mode A `--attempt-id` and `--artifact-dir` channel to retain the
`policy-report` artifact in a fresh empty directory. The capability report
inside that artifact uses `specaudit.ctf.asset-recon.v1`; inspect its own
completeness and limitations too. The existing fixture grader does not turn a reconnaissance
graph into trusted `run_range` coverage. Use the human worksheet below unless
a separately implemented challenge contract explicitly admits this evidence.

The inner report statuses are `complete`, `partial`, and `failed`. Only complete
reports produce a successful arm result. The outer envelope reports a partial
arm result as `failed`, with nonzero CLI exit; this does not discard a retained
partial graph. Mode A can materialize its artifact even on that failure. Missing
or truncated evidence must never be treated as a complete empty inventory.

## Separately authorized observations

`probe` takes an explicit, bounded target list with literal IPs and ports. It
never accepts a discovery result as a recursive work queue. GET, banner and
literal-hello observations are evidence collection, not exploitation, but still
contact a service and can consume resources or create server-side logs.
Use recorded observations for the offline teaching exercise; real services
require E4 authority.

The shipped probe gate requires global unicast IPs, so it refuses loopback,
private and documentation addresses. An ordinary private E2/E3 service cannot
be probed through this gate; use recorded observations for that lesson unless
a separately authorized eligible target is supplied. Do not weaken the gate
to make an example run. Screenshots are intentionally absent: native fixed GET
provides bounded HTTP observations without browser rendering or subresources.

The following is a complete invocation template for an operator who already
has target authority. Set `RECON_APPROVED_IP` and `RECON_APPROVED_PORT` to the
exact approved service before running it. It is not part of the offline
exercise. Choose one method per invocation; the template defaults to a TCP
connect observation.

```sh
# Set these only from the approved target/action record:
# export RECON_APPROVED_IP=...
# export RECON_APPROVED_PORT=...
export RECON_METHOD=tcp
export ASSET_RECON_PROBE_SCOPE="$RECON_APPROVED_IP"
python3 - <<'PY'
import json, os, subprocess, sys
ip, port = os.environ['RECON_APPROVED_IP'], int(os.environ['RECON_APPROVED_PORT'])
method = os.environ['RECON_METHOD']
target = {'ip': ip, 'port': port, 'method': method}
if method == 'http':
    authority = '[' + ip + ']' if ':' in ip else ip
    target['url'] = 'http://' + authority + ':' + str(port) + '/'
elif method in ('tcp-hello', 'udp-hello'):
    target['hello'] = 'hello\r\n'
elif method == 'zgrab2':
    target['module'] = 'banner'
request = {'live': True, 'targets': [target], 'limits': {'max_requests': 1}}
raise SystemExit(subprocess.call([sys.executable, '-m', 'extension', 'invoke',
                                 'asset-recon', 'probe', json.dumps(request)]))
PY
```

Set `RECON_METHOD` to `http` for that fixed GET, `tls` for a ClientHello and
certificate observation, `tcp` for a connect observation, `tcp-hello` for one
literal greeting and bounded reply on TCP, or `udp-hello` for one bounded
greeting datagram and reply. Hello accepts only `hello`, `hello\n` or
`hello\r\n` (default CRLF), not arbitrary protocol commands. HTTP is a fixed
root-path GET; URLs prohibit other paths, credentials, queries and fragments.
Use `https://` explicitly for HTTPS; the port alone does not select TLS.
Optional `host` on HTTP/TLS must independently match probe scope and exclusions;
HTTP's URL must name that host. The socket remains fixed to `ip`, with the name
used for Host/SNI, so it does not authorize another destination.

For the same explicit IP/port, set `RECON_METHOD=nmap` and additionally
`NMAP_DISPATCH_SCOPE="$RECON_APPROVED_IP"`; the composition chooses the existing
Nmap `version-light` mode on that one port. Set `RECON_METHOD=zgrab2` and
`ZGRAB2_DISPATCH_SCOPE="$RECON_APPROVED_IP"` for the existing zgrab2 arm; the
example chooses `banner`, with `http` and `tls` the other admitted `module`
values. Both methods require the installed upstream binary and both scopes;
neither accepts general scanner flags. The asset-recon scope is still required.
The report contains bounded sanitized observations, not a full scanner dump.
To retain those observations, add the same Mode A flags demonstrated below to
the probe invocation; a plain invocation prints the envelope and digest only.

Record the exact method, IP, port, permitted request and result. A successful
TCP connection establishes reachability from this vantage at this time. A
banner is a service declaration, not verified software inventory. A TLS
handshake or certificate match does not establish organizational ownership.
An HTTP response does not establish application health or control
effectiveness. An IP-only request can reach a default virtual host and say
little about a named service. Do not follow returned links, redirects or
instructions into additional work.

## Offline analyst exercise

This is a reproducible worksheet, not an additional `score/` challenge. Run in
E1 with egress denied, using an instructor-frozen synthetic fixture packet and
the same checkout revision. Keep provider grants and probe scope unset. The
instructor records the packet hash, effective limits and expected evidence
relationships separately from the learner brief.

This exact command uses all four committed fixtures and performs no network
requests. Run it from the checkout root. The Python wrapper only constructs
absolute input paths and calls the public CLI; stdout is the envelope.

```sh
python3 - <<'PY'
import json, pathlib, subprocess, sys
root = pathlib.Path('extension/arms/assetrecon/fixtures').resolve(strict=True)
request = {'seeds': {'domains': ['example.test']},
           'organization_hints': ['Example Research'],
           'limits': {'max_depth': 5},
           'fixtures': [{'source': source, 'path': str(root / (name + '.json'))}
                        for source, name in [('crtsh', 'ct'), ('dns', 'dns'),
                                             ('registry', 'registry'), ('shodan', 'shodan')]]}
raise SystemExit(subprocess.call([sys.executable, '-m', 'extension', 'invoke',
                                 'asset-recon', 'discover', json.dumps(request)]))
PY
```

For Mode A, this second command creates a fresh per-attempt directory, retains
the graph, verifies its bytes against the envelope digest and prints the local
artifact path. It needs POSIX/Unix artifact custody. Keep the printed directory
until the exercise's retention decision; this example does not delete evidence.

```sh
python3 - <<'PY'
import hashlib, json, pathlib, secrets, subprocess, sys, tempfile
root = pathlib.Path('extension/arms/assetrecon/fixtures').resolve(strict=True)
request = {'seeds': {'domains': ['example.test']},
           'organization_hints': ['Example Research'],
           'limits': {'max_depth': 5},
           'fixtures': [{'source': source, 'path': str(root / (name + '.json'))}
                        for source, name in [('crtsh', 'ct'), ('dns', 'dns'),
                                             ('registry', 'registry'), ('shodan', 'shodan')]]}
directory = pathlib.Path(tempfile.mkdtemp(prefix='asset-recon-evidence-'))
attempt = 'attempt-' + secrets.token_hex(32)
run = subprocess.run([sys.executable, '-m', 'extension', 'invoke', 'asset-recon',
                      'discover', json.dumps(request), '--attempt-id', attempt,
                      '--artifact-dir', str(directory)], capture_output=True, text=True)
print(run.stdout, end='')
print(run.stderr, end='', file=sys.stderr)
envelope = json.loads(run.stdout)
digest = next(a['digest'] for a in envelope['artifacts'] if a['kind'] == 'policy-report')
matches = [p for p in directory.iterdir() if p.is_file()
           and 'sha256:' + hashlib.sha256(p.read_bytes()).hexdigest() == digest]
if len(matches) != 1:
    raise SystemExit('artifact digest verification failed')
report = json.loads(matches[0].read_bytes())
print(json.dumps({'artifact': str(matches[0]), 'digest_verified': True,
                  'report_status': report['status'], 'requests': report['requests'],
                  'counts': report['counts']}))
raise SystemExit(run.returncode)
PY
```

Repeat the custody command with `max_depth: 1` to inspect the intentional
partial-result case. A nonzero exit is expected; the digest check and retained
artifact still permit analysis. Counts are not a grading key and may change
with an explicitly revised fixture or ranking contract.

1. Write the investigative question, declared seed justification and exclusion
   rationale. Include an operator-egress IP that is both a seed and excluded.
2. Run `plan`; explain what remains in scope before reading any evidence.
3. Parse the supplied packet and traverse the offline discovery graph. Trace
   one candidate through CT, forward DNS, PTR and registry or Shodan evidence.
4. Compare a corroborated association with a shared-hosting near miss, a
   wildcard-only name, stale evidence and a conflicting PTR. Retain reasons
   for rejecting or qualifying each claim.
5. Repeat with a lower depth or graph budget and with a deliberately missing
   evidence source. Explain the coverage lost; do not rewrite it as an all-clear.
6. Propose one follow-up evidence request. If it would contact a service, write
   the exact separate authorization it needs, but do not execute it in E1.
7. Submit an evidence-linked candidate ledger, responsibility hypotheses,
   exclusions, limitations and a bounded audit conclusion. Another learner
   must be able to reproduce the graph and challenge the inference.

Use a second fixture variant with a removed corroborating record to test
whether learners notice a weaker case. Renaming a known answer is not a new
holdout. A partial, correctly qualified answer can meet the learning objective;
fabricated evidence, scope expansion or unsupported assurance fails it.

## Audit and telecom learning outcomes

| Program mapping | Performance demonstrated |
|---|---|
| `FND-01`–`03`, `AUD-01`–`04` | Bound an investigative population, preserve reproducibility, separate fact from inference and defend a workpaper conclusion. |
| `CYB-01`, `CYB-05`, `CYB-09` | Reconcile declared inventory with externally visible associations; identify shared-service dependencies and evidence gaps before vulnerability assessment. |
| `TEL-01`, `TEL-06`, `TEL-07`, `TEL-08` | Distinguish operator, hosting supplier, partner and customer responsibility for synthetic management, edge and network-API assets. |
| `CAP-IA`, `CAP-TEL` | Turn candidate associations into a justified request for authoritative inventory, contracts or control evidence; preserve unresolved ownership and scope. |

A telecom-looking hostname, ASN or certificate is not proof of a network
function, subscriber system, exposed signalling path or control failure. Use
synthetic partner/hosting and operator-egress cases to teach responsibility
boundaries. This capability does not implement a 5G core, signalling lab,
subscriber-data assessment or a full telecom capstone.

Grade scope and exclusions, traceable evidence, alternative explanations,
honest limitations and a useful next evidence request. Do not grade the number
of discovered hosts or a confidence score as assurance. Preserve the separate
machine-verdict and human-workpaper boundary in the
[instructor assessment guide](../INSTRUCTOR_GUIDE.md#assessment).

## Research basis and implementation boundaries

Primary documentation was checked on 2026-09-08; only documentation pages were
retrieved. No provider data query, target connection, scan, installation or
live performance measurement formed part of this research. These are design
and teaching references, not bundled dependencies or claims of feature parity.

- [Censys discovery paths](https://docs.censys.com/docs/asm-understand-investigate-attack-surface)
  explains seed-to-asset paths, confidence thresholds, exclusions and ambiguity
  for certificates spanning unrelated names. This motivates reviewable paths
  and cautious attribution here; Censys itself is not an adapter in this arm.
- [Subfinder overview](https://docs.projectdiscovery.io/opensource/subfinder/overview)
  separates modular passive-source enumeration as a purpose. This informs
  provider separation, without importing its toolchain or permission model.
- [dnsx usage](https://docs.projectdiscovery.io/opensource/dnsx/usage) exposes
  PTR/forward records, resolver selection, response codes, rate controls and
  wildcard handling as distinct concerns. Its whole execution surface is not
  exposed by this capability.
- [Google JSON DoH](https://developers.google.com/speed/public-dns/docs/doh/json)
  and [Cloudflare DNS JSON](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
  document response status and answer formats. HTTP success, DNS success,
  an empty answer and truncation are different conditions; a resolver's
  response is not proof of the absence of an asset.
- [Shodan API](https://developer.shodan.io/api) distinguishes retrieval of
  existing host observations, including update times, from scan-submission
  endpoints. Only evidence lookup/import is relevant to the Shodan adapter;
  scan submission is outside this capability.
- [ARIN Whois/RDAP](https://www.arin.net/resources/registry/whois/) documents
  registration queries for Internet resources. Treat those records as registry
  context, not a service owner's approval or an observed routing proof.
- [RIPEstat Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info)
  and [AS Overview](https://stat.ripe.net/docs/data-api/api-endpoints/as-overview)
  distinguish the announcing ASN/containing prefix from the holder description
  and announcement state. Their data is an observation window, not a live
  statement of customer ownership.
- [SSLMate CT Search API](https://sslmate.com/help/reference/ct_search_api_v1)
  defines cursor pagination, certificate/precertificate issuance identity and
  validity fields. These contracts explain why a bounded page and a record
  fingerprint alone cannot establish exhaustive certificate coverage.
- CT, wildcard identity and reverse-DNS semantics are grounded in the RFC and
  ARIN references beside the corresponding caveats above.

When extending adapters, keep acquisition, normalization, graph reasoning and
target probing separable. A new provider needs explicit admission, endpoint and
data-use review, bounded requests, attributable records, and offline malformed,
negative and partial-result cases. A new probe needs its own exact-target and
side-effect review. Adding an adapter never makes discovered assets authorized
targets or changes the declared support tier by itself.
