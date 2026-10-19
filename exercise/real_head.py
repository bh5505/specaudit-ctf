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

The head process gets a BOUNDED child environment, not a copy of the
runner's ``os.environ``: an explicit base allowlist (PATH, home/config
and temp/locale names), the head's explicit auth/config names, and —
for claude-code only — AWS or Google provider credentials when
``CLAUDE_CODE_USE_BEDROCK`` / ``CLAUDE_CODE_USE_VERTEX`` explicitly
selects that provider. Codex gets the minted trace vars added to that
bounded set; claude/qwen carry them in the private config instead.
Unrelated ambient credentials, proxies, loader/injection values, stale
parent trace facts, and all ``EXERCISE_HEAD_*`` arming/control values
never reach the child. An operator may opt in additional credential
env NAMES with ``EXERCISE_HEAD_EXTRA_ENV`` (comma/whitespace separated
names, at most 64 names and 32 KiB of copied names/values); reserved
names and excess copies are refused before any spawn. Values are not
serialized into the lane record, and the retained child-stderr tail is
scrubbed of copied credential values. This contract bounds only the
child's initial environment; it is not an OS sandbox or a containment
claim.

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
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

HEAD_TIMEOUT_ENV = "EXERCISE_HEAD_TIMEOUT_SECONDS"
EXTRA_ENV_ENV = "EXERCISE_HEAD_EXTRA_ENV"
# Same fail-closed shape as the MCP stdio environment contract: a
# bounded number of names and a bounded total of names/values.
EXTRA_ENV_MAX_VARS = 64
EXTRA_ENV_MAX_BYTES = 32 * 1024
CHILD_ENV_MAX_BYTES = 128 * 1024
# Proxy-only hosts may explicitly opt in these conventional names. They are
# never copied by default, and arbitrary *_PROXY names remain reserved.
EXPLICIT_PROXY_ENV_NAMES = frozenset(
    {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"}
)
# A short copied credential cannot be replaced without mangling ordinary
# stderr. Suppress the whole tail instead of retaining the credential.
SECRET_REDACT_MIN_CHARS = 8
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

# The real head is spawned with an explicit allowlist, never a copy of
# the runner's ambient environment. These base names locate the armed
# binary and its per-user CLI state (auth files under HOME/APPDATA) and
# keep locale/temp behavior predictable. They are not credentials.
BASE_ENV_NAMES = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
)

# Explicit per-head auth/config names. File-backed logins still use the
# base home/config names above; these are the documented environment
# credentials each CLI can read directly. Nothing outside the head's
# own list (or the operator opt-in below) is copied.
CLAUDE_AUTH_ENV = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
)
CLAUDE_BEDROCK_ENV = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_BEARER_TOKEN_BEDROCK",
)
CLAUDE_VERTEX_ENV = (
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "CLOUD_ML_REGION",
    "ANTHROPIC_VERTEX_PROJECT_ID",
    "ANTHROPIC_VERTEX_BASE_URL",
)
CODEX_AUTH_ENV = (
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_ORG_ID",
    "OPENAI_ORGANIZATION",
    "OPENAI_PROJECT_ID",
    "OPENAI_PROJECT",
    "CODEX_HOME",
)
QWEN_AUTH_ENV = (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_MODEL",
    "OPENAI_API_VERSION",
    "DASHSCOPE_API_KEY",
)
HEAD_AUTH_ENV = {
    "claude-code": CLAUDE_AUTH_ENV,
    "codex-cli": CODEX_AUTH_ENV,
    "qwen-code": QWEN_AUTH_ENV,
}

# Auth-list names whose values are credentials or locations of credential
# files/config. These are scrubbed from the child stderr tail if a chatty
# head echoes them. Endpoints, selectors, and provider metadata are excluded.
_SECRET_ENV_NAMES = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CONFIG_DIR",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_BEARER_TOKEN_BEDROCK",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "OPENAI_API_KEY",
        "CODEX_HOME",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "DASHSCOPE_API_KEY",
    }
)

_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_IDENTITY_ENV = frozenset(
    (*BASE_ENV_NAMES, *CLAUDE_AUTH_ENV, *CODEX_AUTH_ENV, *QWEN_AUTH_ENV)
)
# The operator opt-in may add credential names, never trace transport,
# arming/control, loader/injection, proxy, or base-environment names.
_RESERVED_PREFIXES = (
    "PYTHON",
    "LD_",
    "DYLD_",
    "GIT_CONFIG",
    "GIT_TRACE",
    "EXERCISE_HEAD_",
    "SPECAUDIT_CTF_",
)
_RESERVED_ENV = frozenset(
    {
        *TRACE_VARS,
        EXTRA_ENV_ENV,
        HEAD_TIMEOUT_ENV,
        *ARMING_ENVS.values(),
        "PWD",
        "OLDPWD",
        "CDPATH",
        "ENV",
        "BASH_ENV",
        "BASHOPTS",
        "SHELLOPTS",
        "NODE_OPTIONS",
        "NODE_PATH",
        "RUBYOPT",
        "RUBYLIB",
        "PERL5OPT",
        "PERL5LIB",
        "SYSTEMROOT",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "GCONV_PATH",
        "LOCPATH",
        "ZDOTDIR",
    }
) | _IDENTITY_ENV

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


def extra_env_names() -> tuple[str, ...]:
    """Operator opt-in names copied from the parent, verbatim.

    The opt-in exists for a credential/configuration variable the
    per-head lists do not know about. It grants nothing by itself:
    trace/arming/control names, loader and injection names, arbitrary proxy
    names, and base/head-auth names are refused before any spawn. The four
    conventional proxy names are permitted only by explicit opt-in. At most
    64 names may be declared. Values are not serialized into the lane
    record; copied credential values are scrubbed from the retained
    child-stderr tail.
    """
    raw = os.environ.get(EXTRA_ENV_ENV, "")
    names: list[str] = []
    folded: set[str] = set()
    for token in re.split(r"[\s,]+", raw.strip()):
        if not token:
            continue
        if not _ENV_NAME_RE.fullmatch(token):
            raise RealHeadError(
                f"{EXTRA_ENV_ENV} contains an invalid environment name: {token!r}"
            )
        key = token.upper()
        if key in folded:
            if token in names:
                continue
            raise RealHeadError(
                f"{EXTRA_ENV_ENV} names a case-ambiguous environment variable: {token}"
            )
        if _is_reserved_extra(token):
            raise RealHeadError(
                f"{EXTRA_ENV_ENV} names a reserved environment variable: {token} "
                "(trace, arming/control, loader/injection, arbitrary proxy, "
                "and base/head-auth names are refused)"
            )
        if len(names) >= EXTRA_ENV_MAX_VARS:
            raise RealHeadError(
                f"{EXTRA_ENV_ENV} names more than {EXTRA_ENV_MAX_VARS} variables"
            )
        folded.add(key)
        names.append(token)
    return tuple(names)


def _is_reserved_extra(name: str) -> bool:
    key = name.upper()
    return (
        key in _RESERVED_ENV
        or key.startswith(_RESERVED_PREFIXES)
        or (key.endswith("_PROXY") and key not in EXPLICIT_PROXY_ENV_NAMES)
        or "TRACE" in key
    )


def _ambient_entry(name: str) -> tuple[str, str] | None:
    """Return (actual name, value) without assuming POSIX case rules.

    Windows enumerates the environment case-insensitively; an ambiguous
    case match fails closed instead of guessing which value to copy.
    """
    if name in os.environ:
        return name, os.environ[name]
    if os.name == "nt":
        matches = [
            (key, value)
            for key, value in os.environ.items()
            if key.upper() == name.upper()
        ]
        if len(matches) > 1:
            raise RealHeadError(
                f"ambient environment is case-ambiguous for {name}; refusing to guess"
            )
        if matches:
            return matches[0]
    return None


def _copy_ambient(child: dict[str, str], names: tuple[str, ...]) -> None:
    for name in names:
        if name in child:
            continue
        entry = _ambient_entry(name)
        if entry is not None:
            # Store under the canonical allowlist spelling, even when the
            # host enumerated a differently-cased name.
            child[name] = entry[1]


def _enabled(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def bounded_child_environment(head: str) -> dict[str, str]:
    """Build the head child env from explicit allowlists only.

    No ambient copy: unnamed parent variables (unrelated credentials,
    proxies, loader/injection settings, stale trace facts, arming and
    control variables) never reach the child. ``_compose`` adds the
    minted trace facts for codex-cli; claude-code and qwen-code carry
    them in the private per-server config instead.
    """
    arming_env_for(head)
    child: dict[str, str] = {}
    _copy_ambient(child, BASE_ENV_NAMES)
    _copy_ambient(child, HEAD_AUTH_ENV[head])
    if head == "claude-code":
        # Provider credentials ride along only when that provider is the
        # explicitly selected one; an unrelated ambient AWS/Google key
        # is never copied just because the head could theoretically use it.
        if _enabled(child.get("CLAUDE_CODE_USE_BEDROCK")):
            _copy_ambient(child, CLAUDE_BEDROCK_ENV)
        if _enabled(child.get("CLAUDE_CODE_USE_VERTEX")):
            _copy_ambient(child, CLAUDE_VERTEX_ENV)
    extra_bytes = 0
    for name in extra_env_names():
        entry = _ambient_entry(name)
        if entry is None:
            continue
        value = entry[1]
        if "\0" in value:
            raise RealHeadError(
                f"{EXTRA_ENV_ENV} value for {name} contains a NUL byte"
            )
        try:
            extra_bytes += (
                len(name.encode("utf-8")) + len(value.encode("utf-8")) + 2
            )
        except UnicodeEncodeError:
            raise RealHeadError(
                f"{EXTRA_ENV_ENV} value for {name} is not valid UTF-8 text"
            ) from None
        if extra_bytes > EXTRA_ENV_MAX_BYTES:
            raise RealHeadError(
                f"{EXTRA_ENV_ENV} copies more than {EXTRA_ENV_MAX_BYTES} "
                "bytes of names/values"
            )
        child[name] = value
    # Defense in depth: even a future allowlist edit cannot smuggle a
    # stale trace fact or arming/control value into the head process.
    for name in TRACE_VARS:
        child.pop(name, None)
    for name in ARMING_ENVS.values():
        child.pop(name, None)
    child.pop(HEAD_TIMEOUT_ENV, None)
    _check_child_environment_size(child)
    return child


def _check_child_environment_size(child: dict[str, str]) -> None:
    """Bound the complete environment, including minted trace variables."""
    try:
        total_bytes = sum(
            len(name.encode("utf-8")) + len(value.encode("utf-8")) + 2
            for name, value in child.items()
        )
    except UnicodeEncodeError:
        raise RealHeadError("head child environment requires UTF-8 text") from None
    if total_bytes > CHILD_ENV_MAX_BYTES:
        raise RealHeadError(
            f"head child environment exceeds {CHILD_ENV_MAX_BYTES} bytes"
        )


def _child_secret_values(child: dict[str, str]) -> tuple[str, ...]:
    """Copied credential values the child might echo, longest first.

    Short values cause the entire stderr tail to be suppressed rather than
    risk either credential leakage or destructive substring replacement.
    """
    values: list[str] = []
    seen: set[str] = set()
    for name in {*_SECRET_ENV_NAMES, *extra_env_names()}:
        value = child.get(name)
        if value and value not in seen:
            seen.add(value)
            values.append(value)
    values.sort(key=len, reverse=True)
    return tuple(values)


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
    with the prompt hash for the record. ``child_env_extra`` is merged
    ONTO the caller's bounded allowlist environment (it is never a
    parent-environment copy).
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
    claims_path: Path | None = None,
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
    # Validate the operator opt-in and build the allowlisted child env
    # BEFORE writing the private mcp-config: a bad extra name must not
    # leave key material behind.
    child_env = bounded_child_environment(head)
    child_secret_values = _child_secret_values(child_env)
    composed_argv, child_env_extra, mcp_fact, temp_path = _compose(
        head, cmd, prompt_text, directory, key, attempt_id
    )
    # The child gets the real prompt; the record gets the hash marker.
    spawn_argv = argv_and_prompt(composed_argv, prompt_text)
    recorded_argv = _elide_argv(composed_argv, prompt_sha256)

    # Whatever the transport (config file for claude/qwen, exported vars
    # for codex), only the minted trace facts are added to the bounded
    # environment; stale parent trace values never survive the allowlist.
    if child_env_extra:
        child_env.update(child_env_extra)
    _check_child_environment_size(child_env)

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
    # Scrub BEFORE the tail slice: a credential that straddles the
    # 400-character boundary is still a full occurrence in the raw text
    # and must not survive as a partial prefix/suffix.
    stderr_tail = _scrub_secrets(
        (proc.stderr or "").strip(),
        directory,
        key,
        attempt_id,
        child_secret_values,
    )[-400:]
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
        lane["spawn_note"] = f"head exited {exit_code}: {stderr_tail}"
    return lane


def argv_and_prompt(argv: list[str], prompt_text: str) -> list[str]:
    """Materialize the spawn argv: the marker position gets the real
    prompt text (operator prompt + the runner-owned trailer)."""
    return [
        prompt_text + PROMPT_TRAILER if element == PROMPT_TRAILER_MARKER else element
        for element in argv
    ]


def _scrub_secrets(
    text: str,
    directory: Path,
    key: str,
    attempt_id: str,
    secret_values: tuple[str, ...] = (),
) -> str:
    """The head's own output must never become the report's leak path:
    the minted trace facts AND copied credential values are scrubbed
    from anything the child printed before it can reach a persisted
    lane field."""
    if text and any(len(value) < SECRET_REDACT_MIN_CHARS for value in secret_values):
        return "<redacted child stderr>"
    for secret in (key, attempt_id, str(directory / "trace.ndjson"), *secret_values):
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
