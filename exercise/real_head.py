"""Operator-armed real-head execution: the runner spawns the named
agent CLI headless, wired to this checkout's stdio MCP server.

Arming discipline (same pattern as every dispatch arm — default-off,
operator-armed, audited): the mode exists per head only when the
head's arming env names its binary:

- ``EXERCISE_HEAD_CLAUDE_CODE_CMD`` (claude-code)
- ``EXERCISE_HEAD_CODEX_CLI_CMD`` (codex-cli)
- ``EXERCISE_HEAD_QWEN_CODE_CMD`` (qwen-code)

Unset → the runner refuses exactly as before (the fake head stays the
only ``--head-execute`` driver on unarmed hosts — CI and hermetic
tests never spawn a real CLI). The value is the bare command/path; the
runner composes the headless incantation itself, because the wiring
differs per CLI in a load-bearing way:

- claude-code gets a PRIVATE ``--mcp-config`` JSON (0600, inside the
  attempt directory, deleted after the run) whose per-server ``env``
  map carries the three trace vars — documented as "environment
  variables passed to the server", so no project ``.mcp.json`` is
  touched and no parent-env inheritance is assumed;
- codex-cli forwards parent env to stdio MCP servers only through an
  allowlist in the USER-GLOBAL config, so the runner preflights
  ``~/.codex/config.toml`` (``mcp_servers.specaudit-ctf`` present,
  ``env_vars`` naming all three trace vars) and exports the vars into
  the child env. A missing allowlist fails closed BEFORE the spawn —
  a zero-call trace must never masquerade as an agent failure.
- qwen-code (gemini-lineage) rides the claude-shaped transport: the
  same PRIVATE ``--mcp-config`` (same shared launcher, per-server
  ``env`` map, same deletion discipline) with no child-env mutation,
  driving the CLI's documented one-shot positional prompt under
  ``--yolo`` with the four MCP tools plus ``write_file`` allowlisted.

Evidence stays server-side: the spawn is context, never proof; the
attempt grades through the same ``grade_attempt`` chain as the fake
path (HMAC-chained trace + close record + coverage roster), and the
agent's self-report is not evidence. The attempt prompt is operator
supplied (``--attempt-prompt`` file); the runner appends a fixed
trailer naming the deliverable and the four tools, records only the
prompt's hash and size in the report, and never records the trace key.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

HEAD_TIMEOUT_ENV = "EXERCISE_HEAD_TIMEOUT_SECONDS"
DEFAULT_TIMEOUT_SECONDS = 900
MCP_SERVER_NAME = "specaudit-ctf"
MCP_TOOL_NAMES = ("list", "describe", "invoke", "run_range")
HEAD_MAX_TURNS = 40
PROMPT_MAX_BYTES = 65_536
TRACE_VARS = (
    "SPECAUDIT_CTF_MCP_TRACE",
    "SPECAUDIT_CTF_MCP_TRACE_KEY",
    "SPECAUDIT_CTF_MCP_TRACE_ATTEMPT",
)

# Per-head arming envs. Presence (non-blank) arms that head only;
# absence of all three is the mode's kill-switch.
ARMING_ENVS = {
    "claude-code": "EXERCISE_HEAD_CLAUDE_CODE_CMD",
    "codex-cli": "EXERCISE_HEAD_CODEX_CLI_CMD",
    "qwen-code": "EXERCISE_HEAD_QWEN_CODE_CMD",
}

# The runner-owned trailer appended to every operator prompt: the
# deliverable contract and the tool surface, identical for every head.
PROMPT_TRAILER = (
    "\n\nDeliverable: write your claimed findings as valid JSON to "
    "found.json in your current working directory (this is the attempt "
    f"directory). Use only the {MCP_SERVER_NAME} MCP tools "
    + ", ".join(MCP_TOOL_NAMES)
    + ". Your prose is never the evidence - the server records what "
    "you actually did.\n"
)


class RealHeadError(Exception):
    """Fail-closed real-head arming/wiring error (usage error class)."""


def arming_env_for(head: str) -> str:
    env = ARMING_ENVS.get(head)
    if env is None:
        raise RealHeadError(
            f"unknown real head: {head} (armed heads: {', '.join(sorted(ARMING_ENVS))})"
        )
    return env


def armed_cmd_for(head: str) -> str | None:
    """The armed command for a head, or None when the head is unarmed."""
    value = os.environ.get(arming_env_for(head), "")
    return value.strip() or None


def resolve_timeout() -> int:
    raw = os.environ.get(HEAD_TIMEOUT_ENV, "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = int(raw)
    except ValueError:
        raise RealHeadError(
            f"{HEAD_TIMEOUT_ENV} must be an integer number of seconds, got {raw!r}"
        ) from None
    if value <= 0:
        raise RealHeadError(f"{HEAD_TIMEOUT_ENV} must be positive, got {raw!r}")
    return value


def load_prompt(prompt_path: str) -> tuple[str, str, int]:
    """Read the operator's attempt prompt; return (text, sha256, chars)."""
    path = Path(prompt_path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RealHeadError(f"attempt prompt unreadable: {path} ({exc})") from None
    if not data.strip():
        raise RealHeadError(f"attempt prompt is empty: {path}")
    if len(data) > PROMPT_MAX_BYTES:
        raise RealHeadError(
            f"attempt prompt exceeds {PROMPT_MAX_BYTES} bytes: {path}"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise RealHeadError(f"attempt prompt is not valid UTF-8: {path}") from None
    return text, hashlib.sha256(data).hexdigest(), len(text)


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _codex_config_path() -> Path:
    return Path.home() / ".codex" / "config.toml"


def codex_preflight() -> dict[str, Any]:
    """Fail closed before spawning codex unless the host config will
    forward the three trace vars to the MCP server."""
    path = _codex_config_path()
    if not path.is_file():
        raise RealHeadError(
            f"codex host config missing: {path} - add an "
            "[mcp_servers.specaudit-ctf] block with env_vars naming the "
            "SPECAUDIT_CTF_MCP_TRACE* vars (see extension/heads/codex-cli.md)"
        )
    try:
        config = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RealHeadError(f"codex host config unreadable: {path} ({exc})") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise RealHeadError(f"codex host config unparsable: {path} ({exc})") from None
    servers = config.get("mcp_servers")
    if not isinstance(servers, dict) or MCP_SERVER_NAME not in servers:
        raise RealHeadError(
            f"codex host config {path} has no [mcp_servers.{MCP_SERVER_NAME}] "
            "block - the trace vars would never reach the MCP server"
        )
    if not isinstance(servers[MCP_SERVER_NAME], dict):
        raise RealHeadError(
            f"codex host config {path}: [mcp_servers.{MCP_SERVER_NAME}] is "
            "not a table - the env_vars allowlist cannot be verified"
        )
    forwarded = servers[MCP_SERVER_NAME].get("env_vars")
    if not isinstance(forwarded, list):
        raise RealHeadError(
            f"codex host config {path} does not allowlist env_vars for "
            f"[mcp_servers.{MCP_SERVER_NAME}] - add the three "
            "SPECAUDIT_CTF_MCP_TRACE* names"
        )
    missing = [name for name in TRACE_VARS if name not in forwarded]
    if missing:
        raise RealHeadError(
            f"codex host config {path} env_vars allowlist is missing: "
            + ", ".join(missing)
        )
    return {
        "kind": "host-config",
        "source": str(path),
        "env_vars_forwarded": list(TRACE_VARS),
    }


def _write_claude_mcp_config(
    attempt_dir: Path, key: str, attempt_id: str
) -> tuple[Path, str]:
    """Private --mcp-config: 0600, attempt-dir resident, deleted by the
    caller in a finally block. Returns (path, sha256)."""
    directory = Path(attempt_dir)
    config_path = directory / "mcp-config.json"
    document = {
        "mcpServers": {
            MCP_SERVER_NAME: {
                "command": sys.executable,
                "args": [
                    str(
                        _repo_root()
                        / "extension"
                        / "heads"
                        / "claude-code"
                        / "launch_mcp.py"
                    )
                ],
                "env": {
                    "SPECAUDIT_CTF_MCP_TRACE": str(directory / "trace.ndjson"),
                    "SPECAUDIT_CTF_MCP_TRACE_KEY": key,
                    "SPECAUDIT_CTF_MCP_TRACE_ATTEMPT": attempt_id,
                },
            }
        }
    }
    payload = json.dumps(document, indent=2).encode("utf-8")
    # O_EXCL (plus O_NOFOLLOW where the platform has it): the config
    # carries the minted key, so an existing file or symlink at this
    # path must fail closed, never be silently followed or overwritten.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is not None:
        flags |= nofollow
    try:
        descriptor = os.open(config_path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
    except FileExistsError:
        raise RealHeadError(
            f"refusing to overwrite an existing {config_path.name} in the "
            "attempt directory (leftover from an earlier run?)"
        ) from None
    except OSError as exc:
        # A partial write must not leave key material behind; a
        # hostile filesystem must not mask the RealHeadError below.
        try:
            config_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise RealHeadError(
            f"cannot write the private mcp-config into {directory}: {exc}"
        ) from None
    return config_path, hashlib.sha256(payload).hexdigest()


def _claude_argv(cmd: str, prompt_text: str, config_path: Path) -> list[str]:
    return [
        cmd,
        "-p",
        prompt_text,
        "--output-format",
        "json",
        "--max-turns",
        str(HEAD_MAX_TURNS),
        "--allowedTools",
        f"mcp__{MCP_SERVER_NAME}__*",
        "Write",
        "--mcp-config",
        str(config_path),
        "--strict-mcp-config",
    ]


def _codex_argv(cmd: str, prompt_text: str, attempt_dir: Path) -> list[str]:
    return [
        cmd,
        "exec",
        "--sandbox",
        "workspace-write",
        "--skip-git-repo-check",
        "-C",
        str(attempt_dir),
        prompt_text,
    ]


# qwen-code (gemini-cli lineage) speaks MCP through the same mcpServers
# config shape claude uses, so it rides the private temp-config path and
# the shared stdio launcher (extension/heads/other-agent-cli.md blesses
# exactly that attachment). The four MCP tools are allowlisted by their
# per-server names and write_file is the CLI's own file-write tool; the
# positional prompt is the CLI's documented one-shot form.
QWEN_ALLOWED_TOOLS = ",".join(
    [f"mcp__{MCP_SERVER_NAME}__{tool}" for tool in MCP_TOOL_NAMES] + ["write_file"]
)


def _qwen_argv(cmd: str, prompt_text: str, config_path: Path) -> list[str]:
    return [
        cmd,
        "--mcp-config",
        str(config_path),
        "--allowed-tools",
        QWEN_ALLOWED_TOOLS,
        "--yolo",
        prompt_text,
    ]


# Internal marker for the prompt position inside an argv list; never
# leaves this module (the spawn materializes the prompt there, the
# record elides it to the prompt hash).
PROMPT_TRAILER_MARKER = "\0prompt\0"


def _elide_argv(argv: list[str], prompt_sha256: str) -> list[str]:
    marked = f"<prompt sha256:{prompt_sha256}>"
    return [marked if element == PROMPT_TRAILER_MARKER else element for element in argv]


def _compose(
    head: str, cmd: str, prompt_text: str, attempt_dir: Path, key: str, attempt_id: str
) -> tuple[list[str], dict[str, str] | None, dict[str, Any], Path | None]:
    """Per-CLI wiring. Returns (composed_argv, child_env_extra, mcp_fact, temp_path).

    ``composed_argv`` carries the marker at the prompt position; the
    caller materializes the real prompt for the spawn and elides it
    with the prompt hash for the record.
    """
    if head == "claude-code":
        config_path, config_sha256 = _write_claude_mcp_config(
            attempt_dir, key, attempt_id
        )
        argv = _claude_argv(cmd, prompt_text, config_path)
        argv[2] = PROMPT_TRAILER_MARKER
        return argv, None, {"kind": "temp-mcp-config", "sha256": config_sha256}, config_path
    if head == "qwen-code":
        # Same config file, same launcher, same deletion discipline as
        # claude-code (the shared stdio launcher; the per-server env map
        # carries the trace vars, so no child env is touched).
        config_path, config_sha256 = _write_claude_mcp_config(
            attempt_dir, key, attempt_id
        )
        argv = _qwen_argv(cmd, prompt_text, config_path)
        argv[-1] = PROMPT_TRAILER_MARKER
        return argv, None, {"kind": "temp-mcp-config", "sha256": config_sha256}, config_path
    if head == "codex-cli":
        mcp_fact = codex_preflight()
        argv = _codex_argv(cmd, prompt_text, attempt_dir)
        argv[-1] = PROMPT_TRAILER_MARKER
        # Export the MINTED trace facts: codex forwards these named vars
        # from its own environment through the host config's env_vars
        # allowlist (the vars are not assumed to pre-exist in os.environ).
        child_env = {
            "SPECAUDIT_CTF_MCP_TRACE": str(attempt_dir / "trace.ndjson"),
            "SPECAUDIT_CTF_MCP_TRACE_KEY": key,
            "SPECAUDIT_CTF_MCP_TRACE_ATTEMPT": attempt_id,
        }
        return argv, child_env, mcp_fact, None
    raise RealHeadError(f"unknown real head: {head}")  # pragma: no cover - gated


def execute_real_head(
    *,
    head: str,
    cmd: str,
    attempt_dir: str,
    expected_path: str,
    prompt_text: str,
    prompt_sha256: str,
    prompt_chars: int,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Spawn the armed head, then grade whatever the SERVER recorded.

    Mirrors the fake-head lane: the runner mints the trace key and
    attempt id (they travel by env/config, never into the report),
    waits under the head timeout, and grades through the same
    fail-closed attempt path. The head's exit code is recorded as
    context; grading decides the lane (evidence is server-side, so a
    non-zero exit with a valid gradable attempt is still judged on the
    evidence, and a clean exit with no trace is still a failure).
    """
    from exercise.attempt import AttemptError, grade_attempt
    from extension.trace import mint_key

    directory = Path(attempt_dir)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RealHeadError(f"cannot create the attempt directory {directory}: {exc}") from None
    key = mint_key()
    attempt_id = os.urandom(32).hex()
    composed_argv, child_env_extra, mcp_fact, temp_path = _compose(
        head, cmd, prompt_text, directory, key, attempt_id
    )
    # The child gets the real prompt; the record gets the hash marker.
    spawn_argv = argv_and_prompt(composed_argv, prompt_text)
    recorded_argv = _elide_argv(composed_argv, prompt_sha256)

    child_env = dict(os.environ)
    # Whatever the transport (config file for claude, exported vars for
    # codex), a STALE trace key from the operator's own shell must
    # never ride into the child: pop first, then re-add per path.
    for name in TRACE_VARS:
        child_env.pop(name, None)
    if child_env_extra:
        child_env.update(child_env_extra)

    print(
        f"[head-spawn] head={head} attempt={attempt_id} "
        f"cmd={cmd} timeout={timeout_seconds}s",
        file=sys.stderr,
        flush=True,
    )
    started = time.monotonic()
    try:
        proc = subprocess.run(
            spawn_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            cwd=str(directory),
            env=child_env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        # A timed-out head was killed by the runner: its trace has no
        # close record and can never grade — fail the lane immediately
        # with the timeout as the reason.
        duration_s = round(time.monotonic() - started, 1)
        print(
            f"[head-reap] head={head} exit=killed duration={duration_s}s",
            file=sys.stderr,
            flush=True,
        )
        return _failed_real_lane(
            directory,
            head,
            {
                "argv": recorded_argv,
                "exit_code": None,
                "duration_s": duration_s,
                "timeout_s": timeout_seconds,
                "prompt_sha256": prompt_sha256,
                "prompt_chars": prompt_chars,
                "mcp": mcp_fact,
            },
            f"head exceeded {timeout_seconds}s timeout and was killed",
            "",
            None,
        )
    except OSError as exc:
        # Missing binary, missing cwd, spawn failure: fail-closed lane,
        # never a traceback — and the grading side sees no trace at all.
        duration_s = round(time.monotonic() - started, 1)
        print(
            f"[head-reap] head={head} exit=spawn-error duration={duration_s}s",
            file=sys.stderr,
            flush=True,
        )
        return _failed_real_lane(
            directory,
            head,
            {
                "argv": recorded_argv,
                "exit_code": None,
                "duration_s": duration_s,
                "timeout_s": timeout_seconds,
                "prompt_sha256": prompt_sha256,
                "prompt_chars": prompt_chars,
                "mcp": mcp_fact,
            },
            f"head spawn failed: {exc}",
            "",
            None,
        )
    finally:
        # The temp mcp-config carries the minted key: it is deleted on
        # EVERY exit from the spawn (success, timeout, OSError). A
        # hostile filesystem must not mask the lane outcome.
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
    exit_code: int | None = proc.returncode
    stderr_tail = _scrub_secrets(
        (proc.stderr or "").strip()[-400:], directory, key, attempt_id
    )
    duration_s = round(time.monotonic() - started, 1)
    print(
        f"[head-reap] head={head} exit={exit_code} duration={duration_s}s",
        file=sys.stderr,
        flush=True,
    )

    spawn_fact = {
        "argv": recorded_argv,
        "exit_code": exit_code,
        "duration_s": duration_s,
        "timeout_s": timeout_seconds,
        "prompt_sha256": prompt_sha256,
        "prompt_chars": prompt_chars,
        "mcp": mcp_fact,
    }
    try:
        document = grade_attempt(
            directory,
            expected_path=Path(expected_path),
            key_env=key,
        )
    except AttemptError as exc:
        lane = _failed_real_lane(
            directory, head, spawn_fact, str(exc), stderr_tail, exit_code
        )
        return lane
    lane = dict(document)
    lane.update(
        {
            "head": head,
            "mode": "executed",
            "status": "passed" if document.get("passed") is True else "failed",
            "spawn": spawn_fact,
        }
    )
    if exit_code not in (0, None):
        # Context for the measured record, never a verdict: grading
        # already decided the lane from server-side evidence.
        lane["spawn_note"] = f"head exited {exit_code}: {stderr_tail}"
    return lane


def argv_and_prompt(argv: list[str], prompt_text: str) -> list[str]:
    """Materialize the spawn argv: the marker position gets the real
    prompt text (operator prompt + the runner-owned trailer)."""
    return [
        prompt_text + PROMPT_TRAILER if element == PROMPT_TRAILER_MARKER else element
        for element in argv
    ]


def _scrub_secrets(text: str, directory: Path, key: str, attempt_id: str) -> str:
    """The head's own output must never become the report's leak path:
    the minted trace facts are scrubbed from anything the child printed
    before it can reach a persisted lane field."""
    for secret in (key, attempt_id, str(directory / "trace.ndjson")):
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def _failed_real_lane(
    directory: Path,
    head: str,
    spawn_fact: dict[str, Any],
    reason: str,
    stderr_tail: str,
    exit_code: int | None,
) -> dict[str, Any]:
    lane: dict[str, Any] = {
        "head": head,
        "mode": "executed",
        "attempt_dir": str(directory),
        "status": "failed",
        "passed": False,
        "reason": reason + (f" (head stderr tail: {stderr_tail})" if stderr_tail else ""),
        "spawn": spawn_fact,
        "trace": {
            "chain_ok": False,
            "close_ok": False,
            "records": 0,
            "tool_calls": 0,
            "attempt_id": None,
            "reasons": [reason],
        },
    }
    if exit_code not in (0, None):
        lane["spawn_note"] = f"head exited {exit_code}"
    return lane
