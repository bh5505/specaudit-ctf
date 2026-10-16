# Lab Net 01 — service discovery rehearsal

## Scenario

You are rehearsing the **network recon lane** against the repository's
disposable lab target. The golden rootfs plants exactly three
services — SSH on 22 and two cleartext HTTP listeners on 8000 and
8080 — and those planted services ARE the fixture: the expected
findings contract is the planted service inventory, nothing more.

This is a **live-service lane** challenge (the contract declares
`lane: live-service`): findings trace to planted target content, the
standalone found-vs-expected lane grades them, and the runner's arms
lane records the nmap/zgrab2 reads as the run's live evidence. The
head-attempt lane refuses this contract by design.

## What you need

This checkout with Python 3.11+, the lab target built and spawned
(`lab/build-golden.sh` once, `lab/spawn-target.sh` per session), and
nmap/zgrab2 binaries present on the invoking host (they are on the
kali lab host). Scans run only after you arm them.

## Objectives

1. **Arm the network reads, then read.**
   From the kali lab host (`export NMAP_DISPATCH_SCOPE=<ip>`,
   `export ZGRAB2_DISPATCH_SCOPE=<ip>`; the scope env is the arming
   decision), run:
   - `python -m extension invoke nmap scan '{"target": "<ip>"}'`
   - `python -m extension invoke zgrab2 scan '{"target": "<ip>", "module": "ssh", "port": 22}'`
   The nmap envelope inventories the open ports; the zgrab2 envelope
   carries the SSH handshake banner for the port-22 finding.

2. **Inventory the planted surface.**
   From the envelopes, identify the three planted services. For each,
   note what the evidence shows: port state from nmap, and the
   application banner where the module grabbed one.

3. **Ship the found-findings document.**
   Produce `found-findings.json` in the graded schema — one entry per
   planted service, each with `finding_key`, `control`, `severity`,
   a one-sentence `rationale`, and a `traces_to` naming the planted
   service definition. Track: `lab-net-01-service-discovery`.

4. **Grade, and run the runner cell.**
   Grade:
   `python -m score --grade found-findings.json --expected challenges/lab-net-01-service-discovery/artifacts/expected-findings.json`
   Then compose the runner cell:
   `python -m exercise --challenge lab-net-01-service-discovery --found found-findings.json --expected challenges/lab-net-01-service-discovery/artifacts/expected-findings.json --arms '[{"arm_id":"nmap","action":"scan","args":{"target":"<ip>"}},{"arm_id":"zgrab2","action":"scan","args":{"target":"<ip>","module":"ssh","port":22}}]'`

## Correspondence (live-service lane)

Every finding traces to a planted service in `lab/target/
start-services.sh`; the graded verdict measures the finding set and
the arms envelopes prove the reads happened. The target listens only
on the WSL-internal NAT — scope discipline still applies: no scan
ever names anything but the operator-spawned target.

A worked pass is included (`solution/walkthrough.md`).
