# Lab Code 01 — walkthrough

## 1. Containment first

`SEMGREP_SCAN_ROOT` names the planted directory; the arm refuses any
target that resolves outside it. The file has exactly four planted
issues — read it before writing rules.

## 2. The rule pack

Author one rule per planted class (an example pack ships in the
README). Anchor rules to constructs (literal-into-credential-assign,
`sh -c` interpolation, `eval`, uncontained `os.path.join`), not to
variable names — that generalizes beyond the fixture.

## 3. The scan

`semgrep_scan` writes the inline pack to a temp config and runs
`semgrep scan --config <temp> --json --metrics=off app.py` with the
version check and metrics disabled in the child env. Four rule hits
are the expected shape — verify the JSON result rows.

## 4. The four rows

1. **demo-code-hardcoded-credential (high).** Repository readers hold
   the credential; rotation needs a code change.
2. **demo-code-command-injection (critical).** Shell operator
   injection through `sh -c` interpolation.
3. **demo-code-eval-input (critical).** Direct arbitrary code
   execution.
4. **demo-code-path-traversal (high).** `../` escapes the base
   directory.

## 5. Grade and run

Grade the found document, then the runner cell with the scan as the
arms lane. Grading 1.0 with the scan envelope complete is the full
cell.
