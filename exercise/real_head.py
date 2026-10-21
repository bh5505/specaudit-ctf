"""Run a selected agent CLI against the CTF MCP server and grade its findings.

The operator chooses the head, prompt, target inputs, and process environment.
The runner supplies MCP wiring and records the subprocess outcome.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import posixpath
import re
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

# Optional per-head command overrides. Selecting --head-execute is the
# operator's explicit request to run a head.
HEAD_COMMAND_ENVS = {
    "claude-code": "EXERCISE_HEAD_CLAUDE_CODE_CMD",
    "codex-cli": "EXERCISE_HEAD_CODEX_CLI_CMD",
    "qwen-code": "EXERCISE_HEAD_QWEN_CODE_CMD",
}
DEFAULT_HEAD_COMMANDS = {
    "claude-code": "claude",
    "codex-cli": "codex",
    "qwen-code": "qwen",
}

# The runner-owned trailer appended to every operator prompt: the
# deliverable contract and the tool surface, identical for every head.
PROMPT_TRAILER = (
    "\n\nDeliverable: write your claimed findings as valid JSON to "
    "found.json in your current working directory (this is the attempt "
    f"directory). The {MCP_SERVER_NAME} MCP server provides "
    + ", ".join(MCP_TOOL_NAMES)
    + ". The challenge grader checks found.json.\n"
)


class RealHeadError(Exception):
    """Real-head command or MCP setup error (usage error class)."""


def command_env_for(head: str) -> str:
    env = HEAD_COMMAND_ENVS.get(head)
    if env is None:
        raise RealHeadError(
            f"unknown real head: {head} (supported: {', '.join(sorted(HEAD_COMMAND_ENVS))})"
        )
    return env


def command_for(head: str) -> str | None:
    """The operator's command override or the head's usual CLI name."""
    value = os.environ.get(command_env_for(head), "")
    return value.strip() or DEFAULT_HEAD_COMMANDS[head]


def bounded_child_environment(head: str) -> dict[str, str]:
    """Use the operator's process environment for the selected head.

    Old trace values belong to another attempt; the current attempt's values
    are added after the runner mints them.
    """
    command_env_for(head)
    child = dict(os.environ)
    for name in TRACE_VARS:
        child.pop(name, None)
    return child


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


def _mcp_launcher_path() -> Path:
    """The shared stdio launcher named in the private --mcp-config
    (claude-code and qwen-code ride the same one). Single source of
    truth for both the preflight check and the config composition."""
    return _repo_root() / "extension" / "heads" / "claude-code" / "launch_mcp.py"


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


# The child's PATHEXT, when the bounded environment carries one, replaces
# this list entirely; the fallback is CPython's own documented default
# extension list for Windows command resolution.
DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC"


def _resolve_child_executable(
    cmd: str, child_env: dict[str, str], attempt_dir: Path
) -> str:
    """Resolve the head command against the child environment only.

    The runner's ambient PATH/PATHEXT is never consulted: a child PATH
    naming different directories must not change what the parent spawns
    (Windows CreateProcess may otherwise search the parent PATH even
    when a child env is supplied). Blank or NUL-bearing commands,
    directories, NTFS alternate-data-stream paths, drive-relative
    commands, and bare names
    without an explicit child PATH all fail closed, and an empty PATH
    entry never falls back to the spawn directory. Returns the resolved
    executable path (an absolute command is returned as given).
    """
    if not cmd.strip():
        raise RealHeadError("head command is blank; refusing to spawn")
    if "\0" in cmd:
        raise RealHeadError("head command contains a NUL byte")
    windows = os.name == "nt"
    path_module = ntpath if windows else posixpath

    def is_child_absolute(value: str) -> bool:
        if windows:
            return path_module.isabs(value) and bool(path_module.splitdrive(value)[0])
        return path_module.isabs(value)

    def checked_absolute(candidate: str) -> str:
        # A stream suffix ("head.exe:ads") is not an executable name.
        if windows and ":" in path_module.splitdrive(candidate)[1]:
            raise RealHeadError(
                f"head command must not use an alternate data stream: {cmd}"
            )
        if os.path.isdir(candidate):
            raise RealHeadError(f"head command is a directory: {cmd}")
        if not os.path.isfile(candidate):
            raise RealHeadError(f"head command is not an existing file: {cmd}")
        if not windows and not os.access(candidate, os.X_OK):
            raise RealHeadError(f"head command is not executable: {cmd}")
        return candidate

    if is_child_absolute(cmd):
        return checked_absolute(cmd)
    if windows and path_module.splitdrive(cmd)[0]:
        raise RealHeadError(
            f"head command is drive-relative and has no absolute form: {cmd}"
        )
    if "/" in cmd or "\\" in cmd:
        # A relative path resolves against the spawn cwd (the attempt
        # directory), never against the runner's own cwd.
        return checked_absolute(str(Path(attempt_dir) / cmd))
    if windows and ":" in cmd:
        raise RealHeadError(
            f"head command must not use an alternate data stream: {cmd}"
        )
    if "PATH" not in child_env:
        raise RealHeadError(
            f"head command {cmd!r} is a bare name but the child "
            "environment has no PATH; refusing to search the runner's own"
        )
    if windows:
        if path_module.splitext(cmd)[1]:
            names = [cmd]
        else:
            pathext = child_env.get("PATHEXT") or DEFAULT_PATHEXT
            names = [cmd + ext for ext in pathext.split(os.pathsep)]
    else:
        names = [cmd]
    for raw_directory in child_env["PATH"].split(os.pathsep):
        if not raw_directory:
            # An empty PATH entry means the current directory on some
            # platforms; the attempt directory is never implicitly searched.
            continue
        if path_module.isabs(raw_directory):
            directory = raw_directory
        else:
            # A relative PATH entry belongs to the CHILD's world (its
            # cwd is the attempt directory), never the runner's own.
            directory = str(Path(attempt_dir) / raw_directory)
        for name in names:
            candidate = os.path.join(directory, name)
            if windows and ":" in path_module.splitdrive(candidate)[1]:
                continue
            if not os.path.isfile(candidate):
                continue
            if not windows and not os.access(candidate, os.X_OK):
                continue
            return candidate
    raise RealHeadError(
        f"head command {cmd!r} not found in the child PATH"
    )


def _require_readable_file(path: Path, description: str) -> None:
    """The launcher runs as the interpreter's argument, never directly,
    so existence and readability are the whole transport contract."""
    if not path.is_file():
        raise RealHeadError(f"{description} is missing: {path}")
    if not os.access(path, os.R_OK):
        raise RealHeadError(f"{description} is not readable: {path}")


def launch_preflight(
    head: str, cmd: str, child_env: dict[str, str], attempt_dir: Path
) -> tuple[str, dict[str, Any] | None]:
    """Fail closed before key minting, config writing, or spawn: the
    head command must resolve against the child environment,
    and the selected head's transport must be wired on this host.

    Returns (resolved_executable, transport_fact). codex-cli keeps its
    host-config trace-forwarding verification as the transport fact; the
    claude/qwen private-config transport verifies the shared launcher
    and the interpreter that will run it (their fact is the config
    written later, so there is nothing to return yet).
    """
    exec_path = _resolve_child_executable(cmd, child_env, attempt_dir)
    if head == "codex-cli":
        return exec_path, codex_preflight()
    if head in ("claude-code", "qwen-code"):
        _require_readable_file(_mcp_launcher_path(), "shared MCP launcher")
        _require_readable_file(Path(sys.executable), "runner interpreter")
    return exec_path, None


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
                "args": [str(_mcp_launcher_path())],
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
        "--mcp-config",
        str(config_path),
    ]


def _codex_argv(cmd: str, prompt_text: str, attempt_dir: Path) -> list[str]:
    return [
        cmd,
        "exec",
        "--skip-git-repo-check",
        "-C",
        str(attempt_dir),
        prompt_text,
    ]


# qwen-code (gemini-cli lineage) speaks MCP through the same mcpServers
# config shape claude uses, so it rides the private temp-config path and
# the shared stdio launcher. The positional prompt is the CLI's one-shot form.


def _qwen_argv(cmd: str, prompt_text: str, config_path: Path) -> list[str]:
    return [
        cmd,
        "--mcp-config",
        str(config_path),
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
    head: str,
    cmd: str,
    prompt_text: str,
    attempt_dir: Path,
    key: str,
    attempt_id: str,
    transport_fact: dict[str, Any] | None,
) -> tuple[list[str], dict[str, str] | None, dict[str, Any], Path | None]:
    """Per-CLI wiring. Returns (composed_argv, child_env_extra, mcp_fact, temp_path).

    ``composed_argv`` carries the marker at the prompt position; the
    caller materializes the real prompt for the spawn and elides it
    with the prompt hash for the record. ``child_env_extra`` is merged
    onto the caller's child environment. ``transport_fact`` is the fact
    ``launch_preflight`` verified before the key was minted.
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
        # carries the trace vars, so none are added to the bounded child
        # environment).
        config_path, config_sha256 = _write_claude_mcp_config(
            attempt_dir, key, attempt_id
        )
        argv = _qwen_argv(cmd, prompt_text, config_path)
        argv[-1] = PROMPT_TRAILER_MARKER
        return argv, None, {"kind": "temp-mcp-config", "sha256": config_sha256}, config_path
    if head == "codex-cli":
        # Verified by launch_preflight before the key was minted; calling
        # codex_preflight again here would re-read host state after the
        # key exists, buying a TOCTOU window instead of safety.
        if transport_fact is None:  # pragma: no cover - preflight guarantees
            raise RealHeadError("codex transport fact missing at composition")
        mcp_fact = transport_fact
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
    claims_path: Path | None = None,
) -> dict[str, Any]:
    """Spawn the selected head, then grade whatever the server recorded.

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
    # Build the child environment before minting; preflight resolves the
    # executable against that environment.
    child_env = bounded_child_environment(head)
    # The launch preflight is fail-closed BEFORE key minting, private
    # config writing, or spawn: a refused launch leaves nothing to clean up.
    exec_path, transport_fact = launch_preflight(head, cmd, child_env, directory)
    key = mint_key()
    attempt_id = os.urandom(32).hex()
    composed_argv, child_env_extra, mcp_fact, temp_path = _compose(
        head, cmd, prompt_text, directory, key, attempt_id, transport_fact
    )
    # The child gets the real prompt; the record gets the hash marker.
    spawn_argv = argv_and_prompt(composed_argv, prompt_text)
    # Spawn the RESOLVED executable: what preflight checked is what runs
    # (Windows CreateProcess may otherwise search the parent PATH even
    # with a child env supplied). The record keeps the armed cmd.
    spawn_argv[0] = exec_path
    recorded_argv = _elide_argv(composed_argv, prompt_sha256)

    # Whatever the transport (config file for claude/qwen, exported vars
    # for codex), only the minted trace facts are added to the bounded
    # environment; stale parent trace values never survive the allowlist.
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
            stderr=subprocess.DEVNULL,
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
    stderr_tail = ""
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
            **({"claims_path": claims_path} if claims_path is not None else {}),
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
        lane["spawn_note"] = f"head exited {exit_code}"
    return lane


def argv_and_prompt(argv: list[str], prompt_text: str) -> list[str]:
    """Materialize the spawn argv: the marker position gets the real
    prompt text (operator prompt + the runner-owned trailer)."""
    return [
        prompt_text + PROMPT_TRAILER if element == PROMPT_TRAILER_MARKER else element
        for element in argv
    ]


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
