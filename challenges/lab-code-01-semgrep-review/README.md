# Lab Code 01 — static-analysis review rehearsal

## Scenario

You are rehearsing the **code-audit lane**: a static security review
of a planted Python module through the semgrep arm with an inline
rule pack you author. The planted file
(`planted/app.py` — inert by construction, never executed) carries
exactly four planted issues; they are the expected-findings contract.
This is a **planted-code lane** challenge (a third declared lane):
static planted artifacts inside the challenge, graded through the
standalone found-vs-expected lane, with the runner's arms lane
recording the semgrep scans as evidence. The attempt lane refuses
this lane by design.

## What you need

This checkout, Python 3.11+, and the `semgrep` binary on PATH (the
arm runs it with `--metrics=off` and a disabled version check — no
registry rules, no network rule sources; the rule pack is inline by
design).

## Objectives

1. **Arm the scan root and read the target.**
   `export SEMGREP_SCAN_ROOT=$(pwd)/challenges/lab-code-01-semgrep-review/planted`
   — the containment boundary (targets must resolve inside it).
   Read `planted/app.py` and author an inline rule pack (YAML) that
   detects each planted issue class: hardcoded-credential assignment,
   shell interpolation of untrusted input, eval of untrusted input,
   and uncontained path join.

2. **Run the scan through the arm.**
   `python -m extension invoke semgrep-mcp semgrep_scan '{"config": "<your YAML rule pack>", "target": "app.py"}'`
   The envelope carries the scan result (JSON) with one result row
   per rule hit — verify each planted issue is hit and nothing else
   is (the file has exactly four).

3. **Ship the found-findings document.**
   Four rows — one per planted issue — each with `finding_key`,
   `control`, `severity`, a one-sentence `rationale`, and a
   `traces_to` naming the planted file and the exact construct. The
   severities in the contract reflect exploitability: eval and shell
   injection are critical; the credential and traversal are high.
   Track: `lab-code-01-semgrep-review`.

4. **Grade, and run the runner cell.**
   Grade:
   `python -m score --grade found-findings.json --expected challenges/lab-code-01-semgrep-review/artifacts/expected-findings.json`
   Then compose the runner cell with the scan as the arms lane:
   `python -m exercise --challenge lab-code-01-semgrep-review --found found-findings.json --expected challenges/lab-code-01-semgrep-review/artifacts/expected-findings.json --arms '[{"arm_id":"semgrep-mcp","action":"semgrep_scan","args":{"config":"<your YAML rule pack>","target":"app.py"}}]'`

## Notes

- The planted credential is not real and the module is never
  executed; the exercise grades the review pass, not exploitation.
- An example rule pack shape (one rule per planted class, anchored to
  the constructs rather than the variable names):

```yaml
rules:
  - id: hardcoded-credential
    languages: [python]
    severity: ERROR
    message: credential assigned from a string literal
    patterns:
      - pattern: $T = "..."
      - metavariable-regex:
          metavariable: $T
          regex: (?i).*(token|key|secret|password).*
  - id: shell-injection
    languages: [python]
    severity: ERROR
    message: untrusted input interpolated into a shell command
    pattern: subprocess.run([...,"sh","-c",f"...{$X}"], ...)
  - id: eval-input
    languages: [python]
    severity: ERROR
    message: eval of untrusted input
    pattern: eval(...)
  - id: path-traversal
    languages: [python]
    severity: WARNING
    message: user-named file joined without containment
    pattern: os.path.join($BASE, $USERINPUT)
```
