# Lab Web 01 — DAST surface rehearsal

## Scenario

You are rehearsing the **web/DAST lane** against the repository's
disposable lab target: a spawned single-host WSL instance serving
inert web content. The golden rootfs plants honest, inert web
findings on purpose — a directory that ships no `index.html` (so the
server auto-indexes it), a stale file reachable through that listing,
and the server implementation's default identification header. Those
planted items ARE the fixture. Nothing on the target executes input;
there is no real vulnerability and none is needed.

This is a **live-service lane** challenge: its contract
(`artifacts/expected-findings.json`, `lane: live-service`) traces to
planted content on the spawned target, not to the synthetic range
fixtures. It grades through the standalone found-vs-expected lane;
the runner's arms lane records the live reads as the run's evidence,
and the evidence-doctrined head-attempt lane refuses this contract by
design (its coverage doctrine verifies range-fixture touches, which
no live finding can honestly name).

## What you need

This checkout with Python 3.11+, the golden target built
(`lab/build-golden.sh`, once) and spawned (`lab/spawn-target.sh`).
The spawned instance's IP is printed by the spawn script; it listens
on 22 / 8000 / 8080 and is reachable only inside the WSL NAT.

## Objectives

1. **Arm the DAST reads, then read.**
   From a WSL distro with the checkout (`export WAPITI_DISPATCH_SCOPE=<ip>`,
   `export PAGE_FETCH_DISPATCH_SCOPE=<ip>`; installing never arms — the
   scope env is the arming decision), run:
   - `python -m extension invoke wapiti scan '{"url": "http://<ip>:8080/"}'`
   - `python -m extension invoke page-fetch fetch '{"url": "http://<ip>:8080/notes/"}'`
   The wapiti envelope is the crawl/scan record; the page-fetch
   envelope shows the `/notes/` auto-index HTML verbatim.

2. **Read the response surface like an auditor.**
   From the envelopes (and a plain fetch if you want the raw
   headers), identify the three planted findings: the directory
   listing at `/notes/`, the stale file the listing exposes, and the
   default `Server` identification header every response carries.

3. **Ship the found-findings document.**
   Produce `found-findings.json` in the graded schema — one entry per
   planted finding, each with `finding_key`, `control`, `severity`,
   a one-sentence `rationale`, and a `traces_to` naming the planted
   target content it came from. Track: `lab-web-01-dast-surface`.

4. **Grade, and run the runner cell.**
   Grade:
   `python -m score --grade found-findings.json --expected challenges/lab-web-01-dast-surface/artifacts/expected-findings.json`
   Then compose the runner cell so the live reads are recorded as run
   evidence (arms requests ride the same admission path as the CLI):
   `python -m exercise --challenge lab-web-01-dast-surface --found found-findings.json --expected challenges/lab-web-01-dast-surface/artifacts/expected-findings.json --arms '[{"arm_id":"wapiti","action":"scan","args":{"url":"http://<ip>:8080/"}},{"arm_id":"page-fetch","action":"fetch","args":{"url":"http://<ip>:8080/notes/"}}]'`

## Correspondence (live-service lane)

Every finding traces to planted target content (`lab/target/`); a
finding you cannot trace is wrong, and a planted item with no finding
is a miss. The graded verdict measures the finding set; the runner's
arms envelopes are the proof the reads happened. Findings without a
matching recorded read are invalid by lane rule even where the
document grader alone would pass them.

A worked pass is included (`solution/walkthrough.md`).
