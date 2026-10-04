# Security scan triage and remediation

The Codex Security static scan reviewed revision `3904880e2f7ebae25fe3bb4dffa06aeecc92faaa`.
This follow-up is based on the subsequent merged main branch. All six reported
items were actionable at their actual trust boundary; no finding was dismissed
as a false positive. Tests use synthetic local inputs and stubs, not live targets.

| Finding | Disposition and change |
| --- | --- |
| Authenticated Caldera and ZAP redirects | Confirmed. Native clients now refuse HTTP redirects before a secret-bearing request can reach a second origin. |
| Path-taking pipeline MCP tools | Confirmed for the attached MCP surface. `pack_run` and `prioritize_targets` are no longer advertised or callable over MCP. The operator-controlled Python pipeline and underlying CLI workflows remain available for approved evidence and destinations. |
| URI scopes ignore ports | Confirmed. URL scopes now bind the effective service port, including implicit HTTP/HTTPS defaults. Invalid ports and userinfo are refused. Hostname and CIDR scopes retain their intentional host-wide semantics. |
| Unbounded subprocess capture | Confirmed across admitted CLI arms. Captures now use a shared byte-capped runner with a deadline and POSIX process-group cleanup; the RPZ transfer also caps disk output and stderr. A result exceeding its cap fails instead of parsing a partial response. Asset recon retains its separate bounded worker protocol. |
| Attack STIX bundle limits | Confirmed. The reader opens and checks one regular-file descriptor, reads at most the configured cap plus one byte, and limits JSON nesting, container/separator counts, and indexed objects. Unsupported no-follow/nonblocking platforms refuse the read. |
| Live-fire `dig` name syntax | Confirmed in the operator-only utility. A DNS name is validated before becoming a `dig` argument, and one terminal dot is normalized in the UDP wire encoding. |

The bounded subprocess runner needs POSIX process groups. It refuses execution
on other platforms and stops descendants that remain in the same group; it is
not a sandbox against processes that deliberately detach. Existing operational
authorization, custody, identity, egress, and cleanup controls in
[`OPERATIONS.md`](../OPERATIONS.md) still apply. This scan covered selected
runtime boundaries, not every repository file.

The separately locked Linux x86-64 runtime requires its source lock to be
re-traced and rebuilt under the pinned Linux interpreter after these changes.
That trace/build/selfcheck cannot run on the macOS development host. The
runtime lock remains unchanged until its Linux verification is completed;
the source-lock checks will intentionally report drift in the meantime.
