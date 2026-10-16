"""Planted vulnerable review target (lab-code-01-semgrep-review).

Inert by construction: this file is NEVER executed by the exercise —
it exists so a static-analysis pass (the semgrep arm with an inline
rule pack) has honest planted issues to find. The four planted issues
are the challenge's expected findings; each traces to the exact lines
below.
"""

import os
import subprocess


# Planted issue 1: hardcoded credential (demo-code-hardcoded-credential)
SERVICE_TOKEN = "AKIA-PLANTED-NOT-REAL-0000"


def run_report_generator(user_input: str) -> str:
    # Planted issue 2: shell command injection via unsanitized input
    # (demo-code-command-injection)
    return subprocess.run(
        ["sh", "-c", f"report-tool {user_input}"],
        capture_output=True,
        text=True,
    ).stdout


def evaluate_expression(expression: str):
    # Planted issue 3: eval of untrusted input (demo-code-eval-input)
    return eval(expression)


def read_user_file(filename: str) -> str:
    # Planted issue 4: path traversal via unchecked join
    # (demo-code-path-traversal)
    base = "/srv/lab-www"
    path = os.path.join(base, filename)
    with open(path, encoding="utf-8") as fh:
        return fh.read()
