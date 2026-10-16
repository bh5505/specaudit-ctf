# Lab Edge 01 — walkthrough

The device-posture lens over the lab target. Every row below traces to
planted device content; nothing is invented.

## 1. Offline declaration

`lab/target/start-services.sh` is the device image's declared service
set: `/usr/sbin/sshd` on tcp/22, `python3 -m http.server` on tcp/8000
and tcp/8080. Read it first — reconciliation needs the declared side
before the probe.

## 2. Armed reads

With the scope envs armed on the kali host (`NMAP_DISPATCH_SCOPE`,
`ZGRAB2_DISPATCH_SCOPE`, `PAGE_FETCH_DISPATCH_SCOPE`, each naming the
target IP):

- `nmap scan` returns the live port inventory: 22, 8000, 8080 open —
  exactly the declared set.
- `zgrab2 scan` (module `ssh`, port 22) returns the handshake banner;
  it names the SSH implementation and version.
- `page-fetch fetch` on `http://<ip>:8000/notes/` returns the
  auto-indexed directory listing (the `notes/` tree ships no
  `index.html`, so the listener's own directory render IS the listing)
  and the redeploy checklist it exposes.

## 3. The four rows

1. **demo-edge-mgmt-version-disclosure (low).** The management plane
   answers unauthenticated probes with its implementation and version.
   Control vocabulary is posture (disclosure), not exposure — net-01
   already inventories the listener; this row grades what the banner
   gives away.
2. **demo-edge-admin-planes-cleartext (medium).** One row across both
   admin planes: no TLS anywhere on the device's administrative web
   surface. Two listeners, one transport-protection verdict.
3. **demo-edge-ops-docs-exposed (medium).** The checklist inventories
   the device's listeners and its rotation procedure — configuration
   facts disclosed through the served tree. This is the
   config-artifact lens; web-01 grades the same file's staleness and
   the listing mechanism separately.
4. **demo-edge-image-reconciliation (none).** Declared set equals live
   set: no undeclared listener, no dark listener. An absence-shaped
   verdict stated explicitly — the rationale says what was NOT found;
   it is never left as silence.

## 4. Grade and run

Ship the four rows as `found-findings.json`, grade against
`artifacts/expected-findings.json`, then compose the runner cell with
the three arms (nmap, zgrab2 ssh, page-fetch) as the live evidence
lane. Grading 1.0 with arms 3/3 and a `complete` envelope is the full
cell.
