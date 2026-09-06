# Lab Emu 01 — emulation-server listing rehearsal

## Scenario

You are rehearsing the **adversary-emulation listing lane**: standing
up the first-party emulation server locally (Apache Caldera — the
successor home of MITRE CALDERA — release 5.3.0) and reading its
listings the way an operator does, then grading the exposure posture
those listings reveal. This is a **live-service lane** challenge: the
planted content is the server's own shipped stockpile ability catalog,
declared in the contract's fixtures; findings grade through the
standalone found-vs-expected lane with the caldera arm's reads as the
live evidence.

## What you need

A Linux host with ~6GB free RAM, git, python3 (3.10+), and pip. The
helper script `lab/install-caldera.sh` pins the release tag, installs
into a venv, and starts the server without the UI build step (the
`--build` flag shells out to `npm run build`, which needs Node; the
API plane does not need it — verified on the Ubuntu lab lane
2026-09-06):

```text
lab/install-caldera.sh          # clone 5.3.0 + venv + deps + start (loopback :8888)
```

The shipped default red key is `ADMIN123` (conf/default.yml
`api_key_red` as shipped) — the default-credential posture finding
grades exactly this. Rotate it on any server that isn't disposable.

## Objectives

1. **Start the server and arm the reads.**
   `export CALDERA_ENDPOINT=http://127.0.0.1:8888` and
   `export CALDERA_API_KEY=ADMIN123`, then:
   - `python -m extension invoke caldera adversaries '{}'`
   - `python -m extension invoke caldera agents '{}'`
   - `python -m extension invoke caldera operations '{}'`
   The adversaries envelope inventories the shipped adversary-profile
   catalog; the agents envelope lists the enrolled population (empty
   on a fresh server); the operations envelope lists operation history
   (empty on a fresh server).

   Client-containment note, observed live: the FULL ability catalog
   (`caldera abilities`) is ~2.8MB of shipped stockpile data and
   honestly trips the arm's response cap — the catalog-exposure row
   therefore grades the adversary-profile catalog, which lists
   completely.

2. **Probe the access-control boundary.**
   Repeat the agents read with a wrong key
   (`CALDERA_API_KEY=wrong-key`): the server must refuse with 401.
   That observation is the access-control attestation row.

3. **Ship the found-findings document.**
   Four rows — the ability-catalog exposure, the default red-key
   posture (the shipped value, not your rotated one), the
   401 attestation, and the no-agents absence verdict — each with
   `finding_key`, `control`, `severity`, a one-sentence `rationale`,
   and a `traces_to` naming the shipped stockpile catalog. Track:
   `lab-emu-01-caldera-listings`.

4. **Grade, and run the runner cell.**
   Grade:
   `python -m score --grade found-findings.json --expected challenges/lab-emu-01-caldera-listings/artifacts/expected-findings.json`
   Then compose the runner cell:
   `python -m exercise --challenge lab-emu-01-caldera-listings --found found-findings.json --expected challenges/lab-emu-01-caldera-listings/artifacts/expected-findings.json --arms '[{"arm_id":"caldera","action":"adversaries","args":{}},{"arm_id":"caldera","action":"agents","args":{}},{"arm_id":"caldera","action":"operations","args":{}}]'`

## Notes

- Determinism: the stockpile catalog is shipped data pinned by the
  release tag; the ability COUNT drifts between releases, so the
  findings grade the exposure shape (a full authenticated catalog
  listing), never a specific count.
- The head-attempt lane refuses this contract by design (live-service
  lane); the runner cell is the matrix-exercisable surface.
