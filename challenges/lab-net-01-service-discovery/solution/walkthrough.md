# Walkthrough — lab-net-01-service-discovery (worked pass, 2026-09-06)

Recorded against the spawned golden target at `172.19.89.77`
(WSL-internal NAT only), nmap + zgrab2 present on the kali lab host.
The scopes were armed first (`NMAP_DISPATCH_SCOPE`,
`ZGRAB2_DISPATCH_SCOPE`); installing never arms.

## 1. The reads

- `nmap scan {"target": "172.19.89.77"}` — envelope `complete`;
  the planted port inventory is 22, 8000, 8080.
- `zgrab2 scan {"target": "172.19.89.77", "module": "ssh", "port": 22}`
  — envelope `complete`; the module grabs the SSH identification
  string.
- Plain observation read (for the walkthrough's evidence only): a
  direct banner read on tcp/22 returns
  `SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4`.

## 2. The planted services (exactly the contract's three)

1. `demo-net-ssh-22` — SSH administrative service on tcp/22, banner
   disclosing the implementation and package version.
2. `demo-net-http-8000` — cleartext HTTP listener (python
   http.server).
3. `demo-net-http-8080` — second cleartext HTTP listener serving the
   same tree.

## 3. The graded pass

`python -m score --grade net-found.json --expected
challenges/lab-net-01-service-discovery/artifacts/expected-findings.json`
→ `passed: true, score: 1.0` (`net-found.json` in
`lab/records/lab-live-lanes-2026-09-06/` is the found document this
walkthrough shipped).

## 4. The runner cell

One runner command composed grading + arms lanes (`net-report.json`
in the same records directory):

```
python -m exercise --challenge lab-net-01-service-discovery \
  --found lab/records/lab-live-lanes-2026-09-06/net-found.json \
  --expected challenges/lab-net-01-service-discovery/artifacts/expected-findings.json \
  --arms '[{"arm_id":"nmap","action":"scan","args":{"target":"172.19.89.77"}},{"arm_id":"zgrab2","action":"scan","args":{"target":"172.19.89.77","module":"ssh","port":22}}]'
```

Result: `complete`; grading 1.00; arms 2/2 (`nmap`, `zgrab2` both
`complete`). Scope discipline held throughout: only the
operator-spawned target was ever named.
