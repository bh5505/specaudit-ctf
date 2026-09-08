# specaudit-ctf agent guidance

Start with [README.md](README.md) for the public runtime/package map,
[OPERATIONS.md](OPERATIONS.md) for operational authorization and containment,
[extension/README.md](extension/README.md) for adapter contracts, and
[tests/](tests/) for executable expectations. This is a standalone public repo;
keep private host paths, credentials, and internal artifacts out of commits.

## Package constraints and validation

- Preserve fail-closed scope/dispatch admission and synthetic-range containment.
  Do not target live engagements, cloud accounts, networks, or third-party
  systems without the explicit scope required by the operational contract.
- Survey/catalog presence is not a shipping, support, installation, or capability
  claim. Preserve distinctions among research, experimental, maintained, and
  held support tiers; use the current catalog and tests as authority.
- Runtime head profiles and extension skills are product integration surfaces,
  separate from development-agent workflow. Verify their contracts before editing.
- Use the existing Python environment and commands from the README/pyproject.
  Run targeted `python -m pytest tests/<relevant-test>.py` for behavior changes,
  and broader tests when affected contracts warrant it. For docs-only changes,
  check links, command accuracy, consistency, and whitespace.
- Keep generated results, local builds, credentials, and unrelated in-progress
  changes out of the deliverable. Review scope includes added files.

## Shared agent workflow

This `AGENTS.md` is the workflow source of truth for every harness in this
repository. Named agent entry files are pointers only. Keep project/runtime
instructions in their own relevant docs; do not copy agent policy into them.
Historical plans and handoffs are evidence, not current provider mandates.

Inspect the branch, worktree, remotes, and existing configuration first.
Preserve unrelated changes; use disjoint ownership or isolated worktrees for
parallel edits. Complete the authorized work and appropriate validation, and
report evidence, limitations, and separately deferred work honestly.
Use a feature branch for code changes; docs-only changes may use main.
Remote writes (including pushes, PR/MR actions, posted reviews, deployments,
and branch deletion) require authorization covering the outcome. State the
instruction authorizing a remote mutation before doing it. Hosted CI/build
side effects require authorization too; default to local checks. Reuse existing
accounts and credentials; never print or commit secrets or invent parallel auth.

### Collaboration and token offload

Claude is generally the primary agent, followed by Codex. They can collaborate
for independent perspectives or distinct capabilities, but more Claude/Codex
sessions are not the default bulk token offload. For substantial bounded work,
consider currently available third-party agents or alternate-provider routes.
Grok, Meta Muse Code, Google Antigravity/AGY, Command Code, and configured
OpenCode/pi routes are known candidates, not a required roster or fixed ranking.
Choose by demonstrated capability, current availability, quota/cost, task/data
constraints, and verification cost. Harness names do not identify the underlying
model/provider; verify the resolved route before claiming offload or diversity.

Delegate implementation, exploration, research, testing, or review when useful;
small or tightly coupled work may stay with the lead. Give each delegate the
workspace, owned paths, this guidance, context, scope/exclusions, read/write
permissions, acceptance criteria, validation commands, budget where supported,
and expected report. Keep independent tasks parallel and dependencies sequential.
The lead can implement too and owns diff inspection, integration, and verification.
Use durable handoffs when useful; no specific bus or agent count is mandatory.

Discover actual tools and inspect CLI help/doctor results before dispatch. A
ping is not proof of file access, editing, testing, or a usable review result.
Probe unfamiliar/failing routes with a small representative task. On unavailable
auth/quota, timeout, or empty output, inspect partial changes and choose another
candidate, narrow the task, or continue directly. Do not repeatedly retry an
unavailable provider. Return changed/inspected files, evidence, check results,
limitations, and unfinished work. Delegate scope never grants remote authority.

### Candidate interfaces

Use existing native subagent tools or MCP registrations when available; read
the session's actual schemas. No private tooling checkout is required to work
on this repository. If the AuditPack delegation tools are already available,
set `TOOLS_ROOT` to that checkout's `tools` directory, `TASK_ROOT` to this repo,
and `PROMPT_FILE` to a self-contained prompt file. Inspect wrapper help and
configuration first; do not copy dated model pins or account paths into docs.

| Candidate | Existing interface or command |
|---|---|
| Grok | `grok_build` (`acp-agents`), or `python3 "$TOOLS_ROOT/grok-build-acp.py" --cwd "$TASK_ROOT" --prompt-file "$PROMPT_FILE" --output-format json`. Uses the installed Grok CLI defaults. |
| Meta Muse Code | `muse_build`, or the shared ACP invocation below with `muse-acp.py`. The adapter bridges `muse exec --json`; `muse serve` speaks MSP. |
| Google Antigravity / AGY | `agy_build`, or the shared invocation below with `agy-acp.py`. Verify real file reads and nonempty results before relying on a review. |
| Command Code | Existing `command_code` MCP `doctor`/`build`, or `COMMAND_CODE_WORKSPACE="$TASK_ROOT" python3 "$TOOLS_ROOT/command-code-delegate.py" doctor`, then the same prefixed invocation with `build --cwd "$TASK_ROOT" "bounded task"`; add `--write` only for authorized edits. |
| OpenCode / pi | Inspect `opencode --help` / `pi --help` and working provider configuration. Use a currently usable route, not a hard-coded model list. |
| Claude | Native subagents or `python3 "$TOOLS_ROOT/claude_delegate.py" --cwd "$TASK_ROOT" --prompt-file "$PROMPT_FILE" --output-format json`; inspect wrapper defaults. |
| Codex | Native subagents or `codex_build`; shell: shared driver with `--agent-executable codex-acp --no-default-agent-args --skip-authenticate --no-reasoning-effort` plus cwd/prompt/output arguments. Reuses existing login. |
| Other available agents | Current native tool schemas/CLI help and the same scope/verification requirements. |

```bash
# Set ACP_ADAPTER to muse-acp.py or agy-acp.py after choosing a usable candidate.
python3 "$TOOLS_ROOT/grok-build-acp.py" --cwd "$TASK_ROOT" \
  --agent-executable python3 --agent-arg "$TOOLS_ROOT/$ACP_ADAPTER" \
  --skip-authenticate --no-reasoning-effort \
  --prompt-file "$PROMPT_FILE" --output-format json
```

`COMMAND_CODE_WORKSPACE` must be set on each Command Code wrapper invocation;
`--cwd` alone cannot escape its configured workspace root.

`acp_doctor` on an existing `acp-agents` server reports availability/auth presence.
Use current adapter source for configuration and containment: `MUSE_PATH` /
`AGY_PATH` select launchers, and `MUSE_ACP_RUN_AS_USER` /
`AGY_ACP_RUN_AS_USER` select the established unprivileged account for root callers.
Muse refuses UID 0; its delegated adapter defaults to `MUSE_ACP_SANDBOX=full`
(OS sandbox disabled), while `default` restores the sandbox. Driver path guards
are not shell isolation. Inspect permissions and provider/data-use settings;
reuse existing auth and never expose native keys in argv. ACP results require
checking `ok`, `stopReason`, `output`, and `clientErrors` plus the actual work.

### Independent review

Before merge, obtain evidence-backed review from a fresh context or human
independent of the authoring context. Same-model fresh contexts can qualify;
a different provider can add perspective. The author's own reread, linter pass,
acknowledgement, or empty report is not independent review. No vendor, fixed
pair, or mandatory number of tools is required; add specialists when risk warrants.

Provide the exact base/head or working-tree snapshot, full changed-file inventory
including new files, diff, this guidance, acceptance criteria, and access to
source/callers/tests. Require findings with location, impact and evidence, or a
clear no-findings conclusion, plus scope, checks performed and coverage gaps.
Incomplete facets or failed/empty runs do not clear a gate. Resolve material
findings and re-review the final changes; bind the verdict to that revision.
When no independent reviewer is available, report the unmet merge gate while
continuing useful local implementation and validation.

Potential entry points (check availability and current help):

- Fresh native reviewer agent/human or an installed review skill, with the brief
  above. Use real source inspection rather than relying only on the author's summary.
- `pi-review <diff-file-or-PR/MR-URL> --repo <checkout> --out <new-run-dir>`:
  report-only by default; inspect verdict and coverage. `--post` or
  `pi-review post <run-dir>` publishes only when authorized.
- `opencode-review-pr <PR-number> --repo-root <checkout> --repo <owner/repo>
  --dry-run --no-post`: check the installed forge support and provider consent
  requirements before a real run. Retain `--no-post` for local-only review;
  versions may otherwise publish by default.
- `zreview` / an installed ZCode review skill: use that host's current help and
  instructions, not a path or command copied from another machine.
- Installed forge reviewers (Kilo, Copilot, Codex, Greptile, Gemini Code Assist,
  or others): inspect actual installation, trigger, quota and returned review.
  Do not assume automatic review or trigger an absent integration repeatedly.

Select another available reviewer if a candidate fails. Check the actual remote:
use `gh`/PRs on GitHub and `glab`/MRs on GitLab. GitHub Apps are not automatically
available on GitLab. Keep review evidence local until posting is authorized;
use the forge's supported surface (PR review or MR note, as applicable).
