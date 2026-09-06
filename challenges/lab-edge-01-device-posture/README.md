# Lab Edge 01 — device posture rehearsal

## Scenario

You are reviewing the posture of a **subscriber-edge-class device** —
an appliance image with a management plane, administrative web planes,
and an operational-documentation tree — as a rehearsal of the
edge-device / network-appliance audit lane. The device under review is
the repository's disposable lab target: the golden rootfs plants an SSH
management listener on tcp/22, two cleartext HTTP admin listeners on
tcp/8000 and tcp/8080, and a `notes/` tree with an operational redeploy
checklist.

The lane's analytical frame (device planes, version-disclosure
posture, config-artifact exposure, and offline-image vs live-surface
reconciliation) is the deliverable — the same target evidence feeds a
different audit lens than `lab-net-01` (service inventory) or
`lab-web-01` (web hardening).

This is a **live-service lane** challenge (the contract declares
`lane: live-service`): findings trace to planted device content, the
standalone found-vs-expected lane grades them, and the runner's arms
lane records the nmap/zgrab2/page-fetch reads as the run's live
evidence. The head-attempt lane refuses this contract by design.

## What you need

This checkout with Python 3.11+, the lab target built and spawned
(`lab/build-golden.sh` once, `lab/spawn-target.sh` per session), and
nmap/zgrab2 binaries present on the invoking host (they are on the
kali lab host). Scans run only after you arm them. The offline side of
the reconciliation needs only this checkout: `lab/target/start-services.sh`
is the image's declared service set.

## Objectives

1. **Read the offline image's declaration.**
   Open `lab/target/start-services.sh` — the device image declares
   exactly three listeners (sshd on 22; `python3 -m http.server` on
   8000 and 8080). This declared set is one side of the
   reconciliation.

2. **Arm the reads and probe the live device.**
   From the kali lab host (`export NMAP_DISPATCH_SCOPE=<ip>`,
   `export ZGRAB2_DISPATCH_SCOPE=<ip>`, `export PAGE_FETCH_DISPATCH_SCOPE=<ip>`;
   the scope envs are the arming decisions), run:
   - `python -m extension invoke nmap scan '{"target": "<ip>"}'` — the live port inventory (reconciliation side two, and the evidence for the admin-plane transport finding).
   - `python -m extension invoke zgrab2 scan '{"target": "<ip>", "module": "ssh", "port": 22}'` — the SSH handshake banner (evidence for the version-disclosure finding).
   - `python -m extension invoke page-fetch fetch '{"url": "http://<ip>:8000/notes/"}'` — the auto-indexed directory listing and the redeploy checklist it exposes (evidence for the config-artifact finding).

3. **Reconcile and decide.**
   Compare the declared set against the live inventory: every declared
   listener live? any live listener undeclared? Then phrase the four
   posture rows — the version-disclosure row, the admin-plane
   transport row, the operational-docs row, and the reconciliation
   verdict itself (severity `none` when the sets match; the rationale
   must state the reconciliation outcome explicitly).

4. **Ship the found-findings document.**
   Produce `found-findings.json` in the graded schema — one entry per
   posture row, each with `finding_key`, `control`, `severity`, a
   one-sentence `rationale`, and a `traces_to` naming the planted
   device content. Track: `lab-edge-01-device-posture`.

5. **Grade, and run the runner cell.**
   Grade:
   `python -m score --grade found-findings.json --expected challenges/lab-edge-01-device-posture/artifacts/expected-findings.json`
   Then compose the runner cell:
   `python -m exercise --challenge lab-edge-01-device-posture --found found-findings.json --expected challenges/lab-edge-01-device-posture/artifacts/expected-findings.json --arms '[{"arm_id":"nmap","action":"scan","args":{"target":"<ip>"}},{"arm_id":"zgrab2","action":"scan","args":{"target":"<ip>","module":"ssh","port":22}},{"arm_id":"page-fetch","action":"fetch","args":{"url":"http://<ip>:8000/notes/"}}]'`

## Notes

- The three planted listeners are inert by construction; the checklist
  content is placeholder lab material. The exercise grades the audit
  lens, not exploit depth.
- The reconciliation row is an absence-shaped finding (telecom-aws-01-reachability
  precedent): phrase what was NOT found (no undeclared listener) as an
  explicit verdict, never as silence.
