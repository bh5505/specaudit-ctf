# Lab: WSL Kali dev/test instance + ephemeral target host

Local, single-host lab tooling for developing and testing this suite
against a real Kali instance and a real (inert) target host. Everything
machine-specific lives in environment variables or `lab/local.conf`
(gitignored; see `local.example.conf`) — the scripts themselves are
generic.

All scripts run from **Windows (Git Bash)** and orchestrate `wsl.exe`.

## Layout

| Script | Purpose |
|---|---|
| `setup-kali.sh` | Provision the Kali dev/test WSL instance (idempotent): distro, apt packages, repo clone, venv, editable install. |
| `install-zgrab2.sh` | Build zgrab2 into the dev instance from a pinned upstream tag (`go install`; Kali does not package it). |
| `install-zdns.sh` | Build zdns into the dev instance from a pinned upstream tag (`go install`, /v2 module path) + apt dnsmasq for the loopback lab zone. |
| `zdns-measure.sh` | Measure the admitted `zdns lookup` against a loopback lab zone under a namespace-scoped resolver overlay (host resolver untouched). |
| `build-golden.sh` | One-time: configure a fresh Debian WSL distro into the golden lab-target rootfs and export it to a tar. |
| `spawn-target.sh` | Register a **disposable** target instance from the golden tar, start its services, print its IP + arming commands. |
| `teardown-target.sh` | Unregister the instance and drop its state dir. |
| `target/` | Inert content + the service starter baked into the golden image. |
| `local.example.conf` | The knobs; copy to `local.conf` (gitignored) to override defaults. |

## One-time setup

```text
lab/setup-kali.sh                       # Kali dev/test instance
wsl --install -d debian --no-launch     # fresh Debian for the golden build
lab/build-golden.sh                     # exports lab/ctf-target-base.tar
```

## Per-session flow

```text
lab/spawn-target.sh    # prints the target IP and ready-to-paste arming commands
# ... from the Kali instance: arm *_DISPATCH_SCOPE to the IP, invoke ...
lab/teardown-target.sh
```

The target is deliberately boring: an SSH banner (port 22) and two
plain-HTTP listeners (8000, 8080) serving static content with one inert
form. No real vulnerability exists or is needed — the point is a
reachable single host so the scope-gated dispatch arms (nmap scan,
wapiti scan, page-fetch fetch, …) exercise their real plumbing: gate,
audit line, stamp, envelope. The target answers only on the WSL-internal
NAT network; nothing is published off-host.

Ephemerality: each spawn is a fresh `wsl --import` from the golden tar
and teardown is an unregister — no state survives. (Consequence: every
instance shares the golden's SSH host keys. Fine for a lab target;
never for anything real.)

## Hermeticity note

The test suite strips PATH for every test (`tests/conftest.py`), so a
scanner-equipped Kali behaves like a scanner-less host and the suite
stays hermetic everywhere. To see what the real host lights up, run
`python -m extension availability` — on Kali with the default package
set, nmap/wapiti/routersploit/commix rows resolve from PATH; installing
a binary never arms anything (the `*_DISPATCH_SCOPE` gate is separate).

## Lab-measured rows (2026-09-04)

The transport-gate campaign's five usable rows got their measured
evidence on 2026-09-04. Two rows were validated end-to-end inside the
dev instance (executable templates below, recorded exactly as run);
three are **operator-gated** — they need operator-provided assets the
lab does not own, are never exercised from the lab, and never spend
operator credentials in a lab run.

### semgrep-mcp — validated in the dev instance (first-party CLI)

semgrep 1.176.1 into the dev venv (`/opt/ctf/bin/pip install semgrep`),
a scan root with a planted finding (`vuln.py` containing an `eval`
call) and a clean file, then the admitted dispatch through the CLI:

```text
export SEMGREP_SCAN_ROOT=/root/semgrep-demo/scanroot
export SEMGREP_BIN=/opt/ctf/bin/semgrep
python -m extension invoke semgrep-mcp semgrep_scan \
  '{"config": "rules:\n  - id: lab-planted-eval\n    languages: [python]\n    message: planted\n    pattern: eval(...)\n    severity: ERROR\n", "target": "vuln.py"}'
```

Healthy outcome (as measured): a `specaudit.ctf.execution-result.v1`
envelope with `status: complete`, `transport_ok: true`, side effects
`["subprocess"]`, and
`approval_ref: operator://dispatch-scope/SEMGREP_SCAN_ROOT`; the
materialized policy-report artifact carries the planted finding
(`check_id: tmp.lab-planted-eval` — semgrep prefixes rules by their
temp-config path — at `vuln.py:3`, severity ERROR, `total: 1`,
`errors: []`). The inline rule pack is mandatory: registry refs,
URLs, and omitted configs are refused by the arm's egress gate, and
the child env disables version-check and metrics phone-home. There is
no `[dispatch]` stderr line for this action by design: its gate is
containment (the scan-root env), not a network scope.

### metasploit-mcp — validated in the dev instance (loopback SSE)

The upstream wrapper (GH05TCREW/MetasploitMCP, pinned commit
`afc792d9ee17540f8a94349b20a3b203e6961a92`, 2026-02-05, no tags) run
against Kali's `metasploit-framework` 6.4.135-dev, everything on
loopback:

```text
msfdb init                                            # one-time DB init
msfrpcd -P <lab-password> -S -a 127.0.0.1 -p 55553    # loopback, no SSL
git clone https://github.com/GH05TCREW/MetasploitMCP /opt/MetasploitMCP
python3 -m venv /opt/msmcp-venv
/opt/msmcp-venv/bin/pip install -r /opt/MetasploitMCP/requirements.txt
/opt/msmcp-venv/bin/pip install 'mcp<2'   # see the dependency note below
export MSF_PASSWORD=<lab-password> MSF_SERVER=127.0.0.1 MSF_PORT=55553 MSF_SSL=false
/opt/msmcp-venv/bin/python /opt/MetasploitMCP/MetasploitMCP.py \
  --transport http --host 127.0.0.1 --port 8085
export METASPLOIT_MCP_ENDPOINT=http://127.0.0.1:8085/sse   # /sse path required
python -m extension invoke metasploit-mcp list_tools
python -m extension invoke metasploit-mcp list_exploits
python -m extension invoke metasploit-mcp list_payloads
python -m extension invoke metasploit-mcp list_active_sessions
python -m extension invoke metasploit-mcp list_listeners
```

Dependency note, recorded honestly: upstream's requirements are lower
bounds (`mcp>=1.6.0`), and a fresh resolve pulls mcp 2.x, whose API
rename (`mcp.server.fastmcp` → `mcp.server.mcpserver`) breaks the
wrapper at import. Resolving `mcp<2` (1.29.1) satisfies upstream's own
declared range — a version-resolution choice in a separate venv, not
an upstream patch. Preflight the dialect before invoking:
`curl -sN http://127.0.0.1:8085/sse` must answer an SSE `endpoint`
event.

Healthy outcome (as measured): all five reads return `complete`
envelopes over the hardened loopback SSE client. `list_tools` reports
the upstream 12-tool inventory — four listings plus eight execution
tools, exactly the arm's read/dispatch tiers (the display is capped at
200 rows by the client). `list_exploits` and `list_payloads` return
the wrapper's own 100-entry module lists (an upstream cap, not this
client's). `list_active_sessions` and `list_listeners` return the
honest empty success shape (`{"status": "success", "sessions": {},
"count": 0}`). Execution tools stay an unadmitted dispatch tier:
`METASPLOIT_DISPATCH_SCOPE` gates the handler, but no registry
profile exists for them.

### zdns — measured against a loopback lab zone (namespace-scoped resolver)

The zdns arm's argv is fixed (`[zdns, <rtype>, <domain>]` — no
`--name-servers` passthrough, by the same no-caller-fragments policy
as every fixed-argv arm), so the resolver is whatever the system
resolver config names. `lab/zdns-measure.sh` gives the measured
lookup a lab authority without touching the distro's resolver:

- dnsmasq binds one **unoccupied loopback IP** (default `127.0.0.2`;
  `127.0.0.53`/`127.0.0.54` are typically held by systemd-resolved)
  authoritative for `lab.ctf` only, with `--no-resolv` — no upstream
  forwarding, so a public name queried under the overlay is REFUSED
  (verified as a containment control: the overlay cannot leak to the
  internet);
- the armed invoke runs inside a **private mount namespace** with a
  `resolv.conf` overlay bind-mounted over `/etc/resolv.conf`, so only
  the measurement's process tree resolves through the lab zone — the
  distro's own resolver is never modified (verified after each run);
  a trap-guarded global swap to the loopback resolver is the fallback
  if `unshare -m` is unavailable.

Measured 2026-09-04 (zdns v2.1.1 built by `install-zdns.sh`, dnsmasq
on `127.0.0.2:53`, zone `lab.ctf`): `ZDNS_DISPATCH_SCOPE=probe.lab.ctf`,
`python -m extension invoke zdns lookup '{"domain": "probe.lab.ctf",
"record_type": "A"}'` returned a `complete` envelope with the
`[dispatch]` audit line and a materialized policy-report artifact
answering `probe.lab.ctf A 192.0.2.10` from resolver `127.0.0.2:53`
(NOERROR). Honesty note the script exists to preserve:
`ZDNS_DISPATCH_SCOPE` authorizes the **queried name** (the dispatch
target), not the resolver transport — where the packets actually go
is decided by resolv.conf, which is why the script pins the resolver,
runs it on loopback, and reports which one answered.

### Operator-gated rows — validation runbooks (never run from the lab)

These three rows are usable catalog capabilities whose validating
assets only the operator holds. The lab has no Burp installation, no
Google credentials, and no Prowler endpoint, and it must never spend
operator credentials. A validating operator runs from their own host
with their own assets:

**burp-mcp — loopback reads over the official BApp.** Install the
PortSwigger "MCP Server" BApp into Burp (Community Edition is fully
usable; scanner/Collaborator tools simply do not appear on a
Community server's surface), start it, and note its listener (default
`http://127.0.0.1:9876`):

```text
export BURP_MCP_ENDPOINT=http://127.0.0.1:9876   # literal loopback only
python -m extension invoke burp-mcp list_tools
python -m extension invoke burp-mcp url_encode '{"content": "a b"}'
python -m extension invoke burp-mcp get_proxy_http_history '{}'
```

Healthy: `complete` envelopes; `list_tools` returns the BApp's tool
inventory with the detected edition; the read actions return their
data. Hostname endpoints (including `localhost`) are refused — the
endpoint must be a literal loopback address.

**google-mcp-security — GTI remote-read.** The operator runs the
official server (google/mcp-security `gti-mcp`) where their Google
application-default credentials and any server-side keys live; this
client's environment never carries them. Arm the endpoint (https
only) and read:

```text
export GTI_MCP_ENDPOINT=https://<operator-fronted-gti-endpoint>
python -m extension invoke google-mcp-security list_tools
python -m extension invoke google-mcp-security get_domain_report \
  '{"domain": "<domain>"}'
```

Healthy: `complete` envelopes with R1 / `network-egress` side effects
and `approval_ref: operator://endpoint/GTI_MCP_ENDPOINT`; the eleven
lookup reads answer report documents.

**prowler-mcp — operator-configured https endpoint.** Prowler's
admitted shape is discovery (`list_tools`) over an
operator-configured https endpoint speaking HTTP+SSE, with the
Prowler install itself gated on cloud credentials being present in
the environment (`AWS_ACCESS_KEY_ID` or `AWS_PROFILE`). There is no
API-key environment variable and no hosted-endpoint default — an
earlier story claiming both was withdrawn (PR #41):

```text
export PROWLER_MCP_ENDPOINT=https://<operator-configured-endpoint>
python -m extension invoke prowler-mcp list_tools
```

Healthy: a `complete` envelope from the hardened SSE client — the
arm's transport policy is explicitly remote-https (loopback and
plain-http endpoints are refused fail-closed, pinned by a gate test)
— with the endpoint's tool inventory rows. Read tools beyond
`list_tools` stay handler-level (prefix allowlist, mutation keywords
refused) until upstream documents individual tool names.
