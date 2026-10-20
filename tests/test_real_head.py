"""The operator-armed real-head execution mode (B0).

Unarmed hosts refuse exactly as before (pinned here and in
test_head_execute.py); an armed head is composed per CLI, spawned with
the prompt materialized, audited on stderr, and graded from
SERVER-SIDE evidence. No test here ever spawns a real agent CLI: the
spawn is a stub, and grading is the real fail-closed path unless
stubbed explicitly.
"""

from __future__ import annotations

import json
import ntpath
import os
import posixpath
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from exercise import real_head
from exercise.real_head import (
    ARMING_ENVS,
    DEFAULT_TIMEOUT_SECONDS,
    HEAD_TIMEOUT_ENV,
    PROMPT_TRAILER,
    RealHeadError,
    execute_real_head,
    load_prompt,
    resolve_timeout,
)
from exercise.runner import ExerciseError, run_exercise

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_02 = (
    ROOT
    / "challenges"
    / "telecom-aws-02-iam-s3-misconfig"
    / "artifacts"
    / "expected-findings.json"
)


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """No real head is armed, and no transport/control env leaks in."""
    for env in ARMING_ENVS.values():
        monkeypatch.delenv(env, raising=False)
    for env in (HEAD_TIMEOUT_ENV, real_head.EXTRA_ENV_ENV, *real_head.TRACE_VARS):
        monkeypatch.delenv(env, raising=False)


@pytest.fixture()
def prompt_file(tmp_path: Path) -> Path:
    path = tmp_path / "prompt.txt"
    path.write_text("Attempt the challenge and report findings.\n", encoding="utf-8")
    return path


def _stub_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    returncode: int = 0,
    seen: dict | None = None,
    side_effect=None,
):
    """Replace subprocess.run in exercise.real_head with a recording stub."""

    rc = returncode

    def fake_run(argv, **kwargs):
        if side_effect is not None:
            raise side_effect
        if seen is not None:
            seen["argv"] = list(argv)
            seen["kwargs"] = kwargs
            seen["cwd"] = kwargs.get("cwd")

        class Proc:
            stdout = ""
            stderr = ""
            returncode = rc

        return Proc()

    monkeypatch.setattr(real_head.subprocess, "run", fake_run)
    return fake_run


def _stub_grade(monkeypatch: pytest.MonkeyPatch, passed: bool) -> None:
    def fake_grade(directory, *, expected_path, key_env):
        return {
            "schema": "specaudit.ctf.attempt.v1",
            "attempt_dir": str(directory),
            "passed": passed,
            "trace": {"chain_ok": True, "close_ok": True, "records": 3, "tool_calls": 3},
        }

    monkeypatch.setattr("exercise.attempt.grade_attempt", fake_grade)


def _fake_executable(directory: Path, name: str) -> str:
    """An inert stub file the launch preflight accepts as the armed
    executable: a .cmd suffix on Windows, the exec bit on POSIX."""
    if os.name == "nt":
        path = directory / f"{name}.cmd"
    else:
        path = directory / name
    path.write_text("synthetic armed head stub\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o755)
    return str(path)


def _forbid_mint(monkeypatch: pytest.MonkeyPatch) -> None:
    """execute_real_head imports mint_key from extension.trace at call
    time, so the ordering pin must patch the source module."""
    monkeypatch.setattr(
        "extension.trace.mint_key",
        lambda: pytest.fail("mint_key ran before the launch preflight passed"),
    )


def test_unarmed_real_head_is_refused() -> None:
    with pytest.raises(ExerciseError, match="not armed on this host"):
        run_exercise(
            head="claude-code",
            head_execute=True,
            attempt_dir="x",
            expected_path="y",
            attempt_prompt="p",
        )


def test_armed_head_without_prompt_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ARMING_ENVS["claude-code"], "/usr/bin/claude")
    with pytest.raises(ExerciseError, match="requires --attempt-prompt"):
        run_exercise(
            head="claude-code", head_execute=True, attempt_dir="x", expected_path="y"
        )


def test_attempt_prompt_with_fake_head_is_refused() -> None:
    with pytest.raises(ExerciseError, match="belongs to real-head execution"):
        run_exercise(
            head="fake",
            head_execute=True,
            attempt_dir="x",
            expected_path="y",
            attempt_prompt="p",
        )


def test_unknown_head_under_head_execute_is_refused() -> None:
    with pytest.raises(ExerciseError, match="unknown head"):
        run_exercise(
            head="no-such-head",
            head_execute=True,
            attempt_dir="x",
            expected_path="y",
            attempt_prompt="p",
        )


def test_head_execute_without_head_names_the_choices() -> None:
    with pytest.raises(ExerciseError, match="requires --head"):
        run_exercise(head_execute=True, attempt_dir="x", expected_path="y")


def test_arming_env_blank_is_unarmed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ARMING_ENVS["codex-cli"], "   ")
    with pytest.raises(ExerciseError, match="not armed on this host"):
        run_exercise(
            head="codex-cli",
            head_execute=True,
            attempt_dir="x",
            expected_path="y",
            attempt_prompt="p",
        )


def test_load_prompt_contract(tmp_path: Path) -> None:
    path = tmp_path / "p.txt"
    with pytest.raises(RealHeadError, match="unreadable"):
        load_prompt(str(tmp_path / "missing.txt"))
    path.write_bytes(b"   \n")
    with pytest.raises(RealHeadError, match="empty"):
        load_prompt(str(path))
    path.write_bytes(b"x" * (real_head.PROMPT_MAX_BYTES + 1))
    with pytest.raises(RealHeadError, match="exceeds"):
        load_prompt(str(path))
    path.write_bytes("caféPrompt".encode("utf-8"))
    text, sha, chars = load_prompt(str(path))
    assert text == "caféPrompt"
    assert len(sha) == 64 and chars == len("caféPrompt")


def test_resolve_timeout_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    assert resolve_timeout() == DEFAULT_TIMEOUT_SECONDS
    monkeypatch.setenv(HEAD_TIMEOUT_ENV, "1200")
    assert resolve_timeout() == 1200
    monkeypatch.setenv(HEAD_TIMEOUT_ENV, "nope")
    with pytest.raises(RealHeadError, match="integer"):
        resolve_timeout()
    monkeypatch.setenv(HEAD_TIMEOUT_ENV, "0")
    with pytest.raises(RealHeadError, match="positive"):
        resolve_timeout()


def test_codex_preflight_requires_the_env_vars_allowlist(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "config.toml"
    monkeypatch.setattr(real_head, "_codex_config_path", lambda: config)

    with pytest.raises(RealHeadError, match="config missing"):
        real_head.codex_preflight()

    config.write_text('model = "x"\n', encoding="utf-8")
    with pytest.raises(RealHeadError, match="no \\[mcp_servers"):
        real_head.codex_preflight()

    config.write_text(
        '[mcp_servers.specaudit-ctf]\ncommand = "python"\n',
        encoding="utf-8",
    )
    with pytest.raises(RealHeadError, match="env_vars"):
        real_head.codex_preflight()

    config.write_text(
        '[mcp_servers.specaudit-ctf]\ncommand = "python"\nenv_vars = ["SPECAUDIT_CTF_MCP_TRACE"]\n',
        encoding="utf-8",
    )
    with pytest.raises(RealHeadError, match="missing: SPECAUDIT_CTF_MCP_TRACE_KEY"):
        real_head.codex_preflight()

    config.write_text(
        "[mcp_servers.specaudit-ctf]\ncommand = \"python\"\nenv_vars = ["
        + ", ".join(f'"{name}"' for name in real_head.TRACE_VARS)
        + "]\n",
        encoding="utf-8",
    )
    fact = real_head.codex_preflight()
    assert fact["kind"] == "host-config"
    assert fact["env_vars_forwarded"] == list(real_head.TRACE_VARS)


def test_armed_claude_head_is_composed_spawned_and_graded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path, capsys
) -> None:
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)

    prompt_text, sha, chars = load_prompt(str(prompt_file))
    lane = execute_real_head(
        head="claude-code",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text=prompt_text,
        prompt_sha256=sha,
        prompt_chars=chars,
        timeout_seconds=60,
    )

    assert lane["status"] == "passed" and lane["passed"] is True
    argv = seen["argv"]
    # An absolute cmd spawns verbatim as argv[0]; the prompt is argv[2].
    assert argv[0] == cmd
    # The real prompt reached the child; the trailer is runner-owned.
    assert argv[2] == prompt_text + PROMPT_TRAILER
    assert "--strict-mcp-config" in argv and "--output-format" in argv
    assert seen["cwd"] == str(attempt_dir)
    # The private mcp-config existed during the spawn and is gone after.
    config_path = Path(argv[argv.index("--mcp-config") + 1])
    assert not config_path.exists(), "temp mcp-config must be deleted after the run"
    assert config_path.parent == attempt_dir
    # The recorded argv never carries the prompt text or the key.
    recorded = json.dumps(lane)
    assert prompt_text not in recorded and "PROMPT" not in recorded
    assert lane["spawn"]["prompt_sha256"] == sha
    assert f"sha256:{sha}" in lane["spawn"]["argv"][2]
    assert lane["spawn"]["exit_code"] == 0
    assert lane["spawn"]["mcp"]["kind"] == "temp-mcp-config"
    err = capsys.readouterr().err
    assert "[head-spawn] head=claude-code" in err
    assert "[head-reap] head=claude-code exit=0" in err


def test_claude_mcp_config_carries_the_trace_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """The documented per-server env map is the trace vars' transport:
    verify the temp config's content and its 0600 mode as the head sees
    it (the runner deletes the file after the run)."""
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    seen: dict = {}

    class Proc:
        stdout = ""
        stderr = ""
        returncode = 0

    def fake_run(argv, **kwargs):
        config_path = Path(argv[argv.index("--mcp-config") + 1])
        seen["config_existed"] = config_path.exists()
        seen["config_path"] = config_path
        seen["config"] = config_path.read_text(encoding="utf-8")
        if os.name == "posix":
            seen["mode"] = config_path.stat().st_mode & 0o777
        return Proc()

    monkeypatch.setattr(real_head.subprocess, "run", fake_run)
    _stub_grade(monkeypatch, passed=True)

    execute_real_head(
        head="claude-code",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=60,
    )
    assert seen["config_existed"] is True
    assert not seen["config_path"].exists(), "deleted after the run"
    document = json.loads(seen["config"])
    server = document["mcpServers"]["specaudit-ctf"]
    assert server["args"][0].endswith("launch_mcp.py")
    env = server["env"]
    assert env["SPECAUDIT_CTF_MCP_TRACE"] == str(attempt_dir / "trace.ndjson")
    assert len(env["SPECAUDIT_CTF_MCP_TRACE_KEY"]) == 64
    assert env["SPECAUDIT_CTF_MCP_TRACE_ATTEMPT"]
    if os.name == "posix":
        assert seen["mode"] == 0o600


def test_armed_codex_head_exports_trace_vars_and_preflights(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    cmd = _fake_executable(tmp_path, "codex")
    monkeypatch.setenv(ARMING_ENVS["codex-cli"], cmd)
    config = tmp_path / "config.toml"
    config.write_text(
        "[mcp_servers.specaudit-ctf]\ncommand = \"python\"\nenv_vars = ["
        + ", ".join(f'"{name}"' for name in real_head.TRACE_VARS)
        + "]\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(real_head, "_codex_config_path", lambda: config)
    # Stale vars in the operator's shell must be overridden by the
    # minted ones (the allowlist forwards the child's env).
    monkeypatch.setenv("SPECAUDIT_CTF_MCP_TRACE_KEY", "stale-key-value")
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)

    prompt_text, sha, chars = load_prompt(str(prompt_file))
    lane = execute_real_head(
        head="codex-cli",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text=prompt_text,
        prompt_sha256=sha,
        prompt_chars=chars,
        timeout_seconds=60,
    )

    assert lane["status"] == "passed"
    argv = seen["argv"]
    assert argv[:5] == [cmd, "exec", "--sandbox", "workspace-write", "--skip-git-repo-check"]
    assert argv[6] == str(attempt_dir)
    assert argv[-1] == prompt_text + PROMPT_TRAILER
    child_env = seen["kwargs"]["env"]
    assert child_env["SPECAUDIT_CTF_MCP_TRACE_KEY"]
    assert child_env["SPECAUDIT_CTF_MCP_TRACE_KEY"] != "stale-key-value", (
        "the minted key must override any stale shell value"
    )
    assert child_env["SPECAUDIT_CTF_MCP_TRACE"] == str(attempt_dir / "trace.ndjson")
    assert lane["spawn"]["mcp"]["kind"] == "host-config"
    assert not (attempt_dir / "mcp-config.json").exists(), "codex path writes no temp config"


def test_codex_preflight_failure_fails_closed_before_spawn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    # A resolvable command whose host config lacks the allowlist: the
    # transport preflight is what refuses, before any spawn.
    cmd = _fake_executable(tmp_path, "codex")
    monkeypatch.setenv(ARMING_ENVS["codex-cli"], cmd)
    config = tmp_path / "config.toml"
    config.write_text('model = "x"\n', encoding="utf-8")
    monkeypatch.setattr(real_head, "_codex_config_path", lambda: config)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()

    def explode(argv, **kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("codex must not spawn without the allowlist")

    monkeypatch.setattr(real_head.subprocess, "run", explode)
    with pytest.raises(RealHeadError, match="no \\[mcp_servers"):
        execute_real_head(
            head="codex-cli",
            cmd=cmd,
            attempt_dir=str(attempt_dir),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=60,
        )


def test_timeout_fails_the_lane_without_grading(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()

    def explode(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv[0], timeout=1)

    monkeypatch.setattr(real_head.subprocess, "run", explode)

    def no_grade(*a, **k):  # pragma: no cover - must not be reached
        raise AssertionError("a timed-out attempt must not be graded")

    monkeypatch.setattr("exercise.attempt.grade_attempt", no_grade)
    lane = execute_real_head(
        head="claude-code",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    assert lane["status"] == "failed" and lane["passed"] is False
    assert "timeout" in lane["reason"]
    assert lane["spawn"]["exit_code"] is None
    assert lane["trace"]["chain_ok"] is False


@pytest.mark.parametrize(
    "spawn_error",
    [
        FileNotFoundError("[Errno 2] no such file: <resolved>"),
        PermissionError(13, "Permission denied"),
    ],
)
def test_spawn_failure_fails_closed_and_deletes_the_temp_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    prompt_file: Path,
    spawn_error: OSError,
) -> None:
    """A head that preflights clean but cannot exec at spawn time (the
    binary vanished, the cwd is unusable, the OS denies the exec) leaves
    no key material on disk and no traceback: a fail-closed lane with
    the spawn error as the reason, and the temp mcp-config gone."""
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()

    def deny(argv, **kwargs):
        raise spawn_error

    monkeypatch.setattr(real_head.subprocess, "run", deny)
    monkeypatch.setattr("exercise.attempt.grade_attempt", deny)
    lane = execute_real_head(
        head="claude-code",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    assert lane["status"] == "failed" and lane["passed"] is False
    assert "spawn failed" in lane["reason"]
    assert not (attempt_dir / "mcp-config.json").exists()
    assert lane["spawn"]["exit_code"] is None


def test_child_stderr_is_scrubbed_of_the_minted_trace_facts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """A chatty head that echoes its env/config must not carry the
    minted key (or the trace path/attempt id) into the lane record."""
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    seen: dict = {}

    def fake_run(argv, **kwargs):
        # The stub cannot know the minted key up front; grab the facts
        # from the temp config the composition just wrote.
        import json as _json

        config_path = Path(argv[argv.index("--mcp-config") + 1])
        env = _json.loads(config_path.read_text(encoding="utf-8"))["mcpServers"][
            "specaudit-ctf"
        ]["env"]
        proc = type(
            "Proc",
            (),
            {
                "stdout": "",
                "stderr": "trace-key-is "
                + env["SPECAUDIT_CTF_MCP_TRACE_KEY"]
                + " attempt "
                + env["SPECAUDIT_CTF_MCP_TRACE_ATTEMPT"],
                "returncode": 0,
            },
        )()
        seen["secrets"] = env
        return proc

    monkeypatch.setattr(real_head.subprocess, "run", fake_run)

    from exercise.attempt import AttemptError

    def failing_grade(*a, **k):
        raise AttemptError("attempt documents unusable: no trace")

    monkeypatch.setattr("exercise.attempt.grade_attempt", failing_grade)
    lane = execute_real_head(
        head="claude-code",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    assert seen["secrets"]["SPECAUDIT_CTF_MCP_TRACE_KEY"] not in json.dumps(lane)
    assert seen["secrets"]["SPECAUDIT_CTF_MCP_TRACE_ATTEMPT"] not in json.dumps(lane)
    assert "<redacted>" in lane.get("spawn_note", "") or "<redacted>" in lane.get("reason", "")


def test_claude_child_env_carries_no_stale_trace_vars(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """The config file is the claude-path transport: a stale trace key
    in the operator's own shell must not ride into the head process."""
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    monkeypatch.setenv("SPECAUDIT_CTF_MCP_TRACE_KEY", "stale-key-value")
    monkeypatch.setenv("SPECAUDIT_CTF_MCP_TRACE", "/stale/trace")
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)
    execute_real_head(
        head="claude-code",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    child_env = seen["kwargs"]["env"]
    assert "SPECAUDIT_CTF_MCP_TRACE_KEY" not in child_env
    assert "SPECAUDIT_CTF_MCP_TRACE" not in child_env


def test_spawn_refuses_to_overwrite_an_existing_temp_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """The temp mcp-config carries the minted key: an existing regular
    file at its path must fail closed with a refusal and survive
    untouched (a planted SYMLINK also fails closed on POSIX via
    O_NOFOLLOW, though through the generic OSError branch with the
    cannot-write message)."""
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    (attempt_dir / "mcp-config.json").write_text("sentinel", encoding="utf-8")
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)
    with pytest.raises(RealHeadError, match="refusing to overwrite"):
        execute_real_head(
            head="claude-code",
            cmd=cmd,
            attempt_dir=str(attempt_dir),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )
    assert not seen, "spawn must not be reached on refusal"
    assert (attempt_dir / "mcp-config.json").read_text(encoding="utf-8") == "sentinel"


def test_head_spawn_is_non_interactive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """A headless spawn must not inherit the runner's stdin (a CLI that
    probes it could block); it is wired to DEVNULL."""
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)
    execute_real_head(
        head="claude-code",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    assert seen["kwargs"]["stdin"] == subprocess.DEVNULL


def test_load_prompt_rejects_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bad.txt"
    path.write_bytes(b"\xff\xfe nope")
    with pytest.raises(RealHeadError, match="UTF-8"):
        load_prompt(str(path))


def test_codex_preflight_rejects_a_non_table_server_block(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        'mcp_servers = "not-a-table"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(real_head, "_codex_config_path", lambda: config)
    with pytest.raises(RealHeadError, match="no \\[mcp_servers"):
        real_head.codex_preflight()
    config.write_text(
        '[mcp_servers.specaudit-ctf]\ncommand = 3\n',
        encoding="utf-8",
    )
    with pytest.raises(RealHeadError, match="does not allowlist env_vars"):
        real_head.codex_preflight()
    config.write_text(
        'mcp_servers.specaudit-ctf = "scalar-not-a-table"\n',
        encoding="utf-8",
    )
    with pytest.raises(RealHeadError, match="not a table"):
        real_head.codex_preflight()


def test_runner_converts_preflight_failure_to_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """The full CLI path: an armed codex with a bad host config exits
    as `exercise: ...` (ExerciseError), never a traceback."""
    cmd = _fake_executable(tmp_path, "codex")
    monkeypatch.setenv(ARMING_ENVS["codex-cli"], cmd)
    config = tmp_path / "config.toml"
    config.write_text('model = "x"\n', encoding="utf-8")
    monkeypatch.setattr(real_head, "_codex_config_path", lambda: config)
    with pytest.raises(ExerciseError, match="has no \\[mcp_servers"):
        run_exercise(
            head="codex-cli",
            head_execute=True,
            attempt_dir=str(tmp_path / "attempt"),
            expected_path="expected.json",
            attempt_prompt=str(prompt_file),
        )


def test_run_exercise_end_to_end_with_a_stubbed_head(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """The full runner path: armed head + prompt file -> report carries
    the graded lane and never leaks the trace key or prompt text."""
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    _stub_run(monkeypatch, returncode=0)

    def fake_grade(directory, *, expected_path, key_env):
        assert key_env and len(key_env) == 64
        return {
            "schema": "specaudit.ctf.attempt.v1",
            "attempt_dir": str(directory),
            "passed": True,
            "trace": {"chain_ok": True, "close_ok": True, "records": 2, "tool_calls": 2},
        }

    monkeypatch.setattr("exercise.attempt.grade_attempt", fake_grade)
    document = run_exercise(
        challenge="demo",
        head="claude-code",
        head_execute=True,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        attempt_prompt=str(prompt_file),
    )
    assert document["head"]["status"] == "passed"
    assert document["head"]["mode"] == "executed"
    payload = json.dumps(document)
    prompt_text = prompt_file.read_text(encoding="utf-8")
    assert prompt_text not in payload
    assert PROMPT_TRAILER not in payload
    # The hermetic range completes and the stubbed attempt passes.
    assert document["status"] == "complete"
    assert document["ok"] is True


def test_qwen_head_is_composed_spawned_and_graded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path, capsys
) -> None:
    """The third armed head rides the shared temp-config + shared
    launcher path, allowlists the four MCP tools by per-server name,
    and goes one-shot on the positional prompt."""
    cmd = _fake_executable(tmp_path, "qwen")
    monkeypatch.setenv(ARMING_ENVS["qwen-code"], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)

    prompt_text, sha, chars = load_prompt(str(prompt_file))
    lane = execute_real_head(
        head="qwen-code",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text=prompt_text,
        prompt_sha256=sha,
        prompt_chars=chars,
        timeout_seconds=60,
    )

    assert lane["status"] == "passed" and lane["passed"] is True
    argv = seen["argv"]
    assert argv[0] == cmd
    # One-shot form: the positional prompt is last and carries the
    # runner-owned trailer.
    assert argv[-1] == prompt_text + PROMPT_TRAILER
    assert "--yolo" in argv
    allowed = argv[argv.index("--allowed-tools") + 1]
    for tool in ("list", "describe", "invoke", "run_range"):
        assert f"mcp__specaudit-ctf__{tool}" in allowed
    assert "write_file" in allowed
    assert seen["cwd"] == str(attempt_dir)
    # Same private-config custody as claude: existed during the spawn,
    # deleted after.
    config_path = Path(argv[argv.index("--mcp-config") + 1])
    assert not config_path.exists(), "temp mcp-config must be deleted after the run"
    assert config_path.parent == attempt_dir
    recorded = json.dumps(lane)
    assert prompt_text not in recorded
    assert lane["spawn"]["prompt_sha256"] == sha
    assert lane["spawn"]["mcp"]["kind"] == "temp-mcp-config"
    err = capsys.readouterr().err
    assert "[head-spawn] head=qwen-code" in err
    assert "[head-reap] head=qwen-code exit=0" in err


def test_qwen_child_env_carries_no_stale_trace_vars(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """The config file is the transport on this path too: a stale trace
    key in the operator's own shell must not ride into the head."""
    cmd = _fake_executable(tmp_path, "qwen")
    monkeypatch.setenv(ARMING_ENVS["qwen-code"], cmd)
    monkeypatch.setenv("SPECAUDIT_CTF_MCP_TRACE_KEY", "stale-key-value")
    monkeypatch.setenv("SPECAUDIT_CTF_MCP_TRACE", "/stale/trace")
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)
    execute_real_head(
        head="qwen-code",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    child_env = seen["kwargs"]["env"]
    assert "SPECAUDIT_CTF_MCP_TRACE_KEY" not in child_env
    assert "SPECAUDIT_CTF_MCP_TRACE" not in child_env


def test_unarmed_qwen_head_is_refused() -> None:
    with pytest.raises(ExerciseError, match="EXERCISE_HEAD_QWEN_CODE_CMD"):
        run_exercise(
            head="qwen-code",
            head_execute=True,
            attempt_dir="x",
            expected_path="y",
            attempt_prompt="p",
        )


def test_qwen_readiness_reports_no_bundled_launcher() -> None:
    document = run_exercise(head="qwen-code")
    lane = document["head"]
    assert lane["mode"] == "readiness"
    assert lane["ready"] is False
    assert lane["status"] == "skipped"


def _codex_allowlist_config(tmp_path: Path) -> Path:
    config = tmp_path / "config.toml"
    config.write_text(
        "[mcp_servers.specaudit-ctf]\ncommand = \"python\"\nenv_vars = ["
        + ", ".join(f'"{name}"' for name in real_head.TRACE_VARS)
        + "]\n",
        encoding="utf-8",
    )
    return config


_AMBIENT_SENTINELS = {
    "CTF_AMBIENT_SENTINEL": "ambient-synthetic-value",
    "GITHUB_TOKEN": "synthetic-github-token",
    "AWS_SECRET_ACCESS_KEY": "synthetic-aws-secret",
    "PYTHONPATH": "/synthetic/pythonpath",
    "LD_PRELOAD": "/synthetic/ld-preload.so",
    "DYLD_INSERT_LIBRARIES": "/synthetic/dyld-insert.dylib",
    "NODE_OPTIONS": "--require=/synthetic/node.js",
    "BASH_ENV": "/synthetic/bash-env",
    "HTTP_PROXY": "http://synthetic.invalid:8080",
    "HTTPS_PROXY": "http://synthetic.invalid:8080",
    "NO_PROXY": "synthetic.invalid",
}


@pytest.mark.parametrize(
    ("head", "expected_auth", "expected_value", "unexpected_auth"),
    [
        ("claude-code", "ANTHROPIC_API_KEY", "synthetic-anthropic", "OPENAI_API_KEY"),
        ("codex-cli", "OPENAI_API_KEY", "synthetic-openai", "ANTHROPIC_API_KEY"),
        ("qwen-code", "GEMINI_API_KEY", "synthetic-gemini", "ANTHROPIC_API_KEY"),
    ],
)
def test_child_environment_is_an_explicit_allowlist(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    head: str,
    expected_auth: str,
    expected_value: str,
    unexpected_auth: str,
) -> None:
    """The head child gets base/auth names only: no ambient copy, no
    stale trace facts, no arming/control vars, no unrelated secrets."""
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    cmd = _fake_executable(tmp_path, "synthetic-head")
    monkeypatch.setenv("PATH", "/synthetic/bin")
    monkeypatch.setenv("HOME", "/synthetic/home")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv(expected_auth, f"synthetic-{expected_auth.lower()}")
    monkeypatch.setenv(unexpected_auth, f"synthetic-{unexpected_auth.lower()}")
    monkeypatch.setenv("GEMINI_API_KEY", "synthetic-gemini")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-anthropic")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-openai")
    for name, value in _AMBIENT_SENTINELS.items():
        monkeypatch.setenv(name, value)
    for env in ARMING_ENVS.values():
        monkeypatch.setenv(env, cmd)
    monkeypatch.setenv(HEAD_TIMEOUT_ENV, "7")
    monkeypatch.setenv("SPECAUDIT_CTF_MCP_TRACE", "/stale/trace")
    monkeypatch.setenv("SPECAUDIT_CTF_MCP_TRACE_KEY", "stale-key")
    monkeypatch.setenv("SPECAUDIT_CTF_MCP_TRACE_ATTEMPT", "stale-attempt")
    if head == "codex-cli":
        monkeypatch.setattr(
            real_head,
            "_codex_config_path",
            lambda: _codex_allowlist_config(tmp_path),
        )
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)

    execute_real_head(
        head=head,
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )

    child_env = seen["kwargs"]["env"]
    assert child_env["PATH"] == "/synthetic/bin"
    assert child_env["HOME"] == "/synthetic/home"
    assert child_env["LANG"] == "C.UTF-8"
    assert child_env[expected_auth] == expected_value
    assert unexpected_auth not in child_env
    for name, value in _AMBIENT_SENTINELS.items():
        assert name not in child_env, f"{name} leaked into the head environment"
        assert value not in child_env.values()
    for env in ARMING_ENVS.values():
        assert env not in child_env
    assert HEAD_TIMEOUT_ENV not in child_env
    assert real_head.EXTRA_ENV_ENV not in child_env
    if head == "codex-cli":
        # Codex rides the minted child-env transport.
        assert child_env["SPECAUDIT_CTF_MCP_TRACE"] == str(attempt_dir / "trace.ndjson")
        assert child_env["SPECAUDIT_CTF_MCP_TRACE_KEY"] != "stale-key"
        assert len(child_env["SPECAUDIT_CTF_MCP_TRACE_KEY"]) == 64
        assert child_env["SPECAUDIT_CTF_MCP_TRACE_ATTEMPT"] != "stale-attempt"
    else:
        # Claude/Qwen carry the trace in the private per-server config.
        assert "SPECAUDIT_CTF_MCP_TRACE" not in child_env
        assert "SPECAUDIT_CTF_MCP_TRACE_KEY" not in child_env
        assert "SPECAUDIT_CTF_MCP_TRACE_ATTEMPT" not in child_env


def test_claude_provider_credentials_require_explicit_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic-aws-key")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/synthetic/google.json")
    child = real_head.bounded_child_environment("claude-code")
    assert "AWS_ACCESS_KEY_ID" not in child
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in child

    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    child = real_head.bounded_child_environment("claude-code")
    assert child["AWS_ACCESS_KEY_ID"] == "synthetic-aws-key"
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in child

    monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK")
    monkeypatch.setenv("CLAUDE_CODE_USE_VERTEX", "1")
    child = real_head.bounded_child_environment("claude-code")
    assert child["GOOGLE_APPLICATION_CREDENTIALS"] == "/synthetic/google.json"
    assert "AWS_ACCESS_KEY_ID" not in child


def test_extra_env_opt_in_copies_only_named_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        real_head.EXTRA_ENV_ENV, "MY_PROVIDER_KEY, OTHER_PROVIDER_CONFIG"
    )
    monkeypatch.setenv("MY_PROVIDER_KEY", "synthetic-provider-key")
    monkeypatch.setenv("OTHER_PROVIDER_CONFIG", "synthetic-provider-config")
    monkeypatch.setenv("UNRELATED_SECRET", "synthetic-unrelated-secret")
    child = real_head.bounded_child_environment("codex-cli")
    assert child["MY_PROVIDER_KEY"] == "synthetic-provider-key"
    assert child["OTHER_PROVIDER_CONFIG"] == "synthetic-provider-config"
    assert "UNRELATED_SECRET" not in child
    # An opted-in name absent from the parent is simply not copied.
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, "MY_PROVIDER_KEY ABSENT_KEY")
    child = real_head.bounded_child_environment("codex-cli")
    assert child["MY_PROVIDER_KEY"] == "synthetic-provider-key"
    assert "ABSENT_KEY" not in child


@pytest.mark.parametrize(
    "name",
    [
        "SPECAUDIT_CTF_MCP_TRACE",
        "SPECAUDIT_CTF_MCP_TRACE_KEY",
        "SPECAUDIT_CTF_ROOT",
        "EXERCISE_HEAD_CLAUDE_CODE_CMD",
        "EXERCISE_HEAD_TIMEOUT_SECONDS",
        "EXERCISE_HEAD_EXTRA_ENV",
        "PYTHONPATH",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "NODE_OPTIONS",
        "BASH_ENV",
        "GIT_CONFIG_GLOBAL",
        "SYSTEMROOT",
        "PWD",
        "LANG",
        "PATH",
        "HOME",
        "CLAUDE_CODE_USE_BEDROCK",
        "MCP_TRACE_PATH",
        "BAD-NAME",
        "1BAD",
        "A=B",
    ],
)
def test_extra_env_reserved_or_invalid_names_refuse_before_spawn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    prompt_file: Path,
    name: str,
) -> None:
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, name)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    monkeypatch.setattr(
        real_head.subprocess,
        "run",
        lambda *a, **k: pytest.fail(f"spawned with refused extra env name {name}"),
    )
    with pytest.raises(RealHeadError, match="reserved|invalid"):
        execute_real_head(
            head="claude-code",
            cmd="/usr/bin/claude",
            attempt_dir=str(attempt_dir),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )
    # Validation happens before the private config is written.
    assert not (attempt_dir / "mcp-config.json").exists()


def test_extra_env_case_ambiguous_name_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, "MY_KEY my_key")
    with pytest.raises(RealHeadError, match="case-ambiguous"):
        real_head.bounded_child_environment("codex-cli")


def _mcp_payload() -> str:
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "synthetic-real-head-stub", "version": "1.0.0"},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "list", "arguments": {}},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "run_range", "arguments": {"arm_ids": []}},
        },
    ]
    return "".join(json.dumps(request) + "\n" for request in requests)


def _drive_mcp(
    command: list[str],
    environment: dict[str, str],
    attempt_dir: Path,
    runner,
) -> subprocess.CompletedProcess[str]:
    """Run the REAL stdio MCP server, shaped like a stub head's attach."""
    proc = runner(
        command,
        input=_mcp_payload(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
        cwd=str(attempt_dir),
        env=environment,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    (attempt_dir / "found.json").write_text(
        CONTRACT_02.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return proc


@pytest.mark.parametrize("head", ["claude-code", "qwen-code"])
def test_private_config_env_drives_the_real_mcp_trace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    prompt_file: Path,
    head: str,
) -> None:
    """Stub the model CLI, but attach the REAL MCP server with exactly
    the private config's env map: the run grades from the server trace."""
    cmd = _fake_executable(tmp_path, "claude" if head == "claude-code" else "qwen")
    monkeypatch.setenv(ARMING_ENVS[head], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    original_run = subprocess.run
    seen: dict = {}

    def fake_run(argv, **kwargs):
        config_path = Path(argv[argv.index("--mcp-config") + 1])
        server = json.loads(config_path.read_text(encoding="utf-8"))["mcpServers"][
            real_head.MCP_SERVER_NAME
        ]
        seen["env"] = dict(server["env"])
        seen["config_path"] = config_path
        return _drive_mcp(
            [server["command"], *server["args"]],
            dict(server["env"]),
            attempt_dir,
            original_run,
        )

    monkeypatch.setattr(real_head.subprocess, "run", fake_run)

    prompt_text, sha, chars = load_prompt(str(prompt_file))
    lane = execute_real_head(
        head=head,
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path=str(CONTRACT_02),
        prompt_text=prompt_text,
        prompt_sha256=sha,
        prompt_chars=chars,
        timeout_seconds=120,
    )
    assert lane["status"] == "passed", lane.get("reason")
    assert lane["passed"] is True
    assert lane["trace"]["chain_ok"] is True
    assert lane["trace"]["close_ok"] is True
    assert lane["trace"]["tool_calls"] == 2
    assert seen["env"]["SPECAUDIT_CTF_MCP_TRACE"] == str(attempt_dir / "trace.ndjson")
    assert len(seen["env"]["SPECAUDIT_CTF_MCP_TRACE_KEY"]) == 64
    assert (attempt_dir / "trace.ndjson").is_file()
    assert not seen["config_path"].exists(), "temp config is deleted after the run"


def test_codex_bounded_env_drives_the_real_mcp_trace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    prompt_file: Path,
) -> None:
    """The minted codex child env must reach the REAL MCP server: no
    ambient copy, just the bounded allowlist plus the trace facts."""
    cmd = _fake_executable(tmp_path, "codex")
    monkeypatch.setenv(ARMING_ENVS["codex-cli"], cmd)
    monkeypatch.setattr(
        real_head,
        "_codex_config_path",
        lambda: _codex_allowlist_config(tmp_path),
    )
    monkeypatch.setenv("CTF_AMBIENT_SENTINEL", "must-not-arrive")
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    original_run = subprocess.run
    seen: dict = {}

    def fake_run(argv, **kwargs):
        child_env = dict(kwargs["env"])
        seen["env"] = child_env
        return _drive_mcp(
            [
                sys.executable,
                str(ROOT / "extension" / "heads" / "codex-cli" / "launch_mcp.py"),
            ],
            child_env,
            attempt_dir,
            original_run,
        )

    monkeypatch.setattr(real_head.subprocess, "run", fake_run)

    prompt_text, sha, chars = load_prompt(str(prompt_file))
    lane = execute_real_head(
        head="codex-cli",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path=str(CONTRACT_02),
        prompt_text=prompt_text,
        prompt_sha256=sha,
        prompt_chars=chars,
        timeout_seconds=120,
    )
    assert lane["status"] == "passed", lane.get("reason")
    assert lane["trace"]["chain_ok"] is True
    assert lane["trace"]["close_ok"] is True
    assert lane["trace"]["tool_calls"] == 2
    assert "CTF_AMBIENT_SENTINEL" not in seen["env"]
    assert seen["env"]["SPECAUDIT_CTF_MCP_TRACE"] == str(attempt_dir / "trace.ndjson")
    assert len(seen["env"]["SPECAUDIT_CTF_MCP_TRACE_KEY"]) == 64
    assert (attempt_dir / "trace.ndjson").is_file()


def test_extra_env_name_count_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    names = [
        f"SYNTH_EXTRA_{index}"
        for index in range(real_head.EXTRA_ENV_MAX_VARS + 1)
    ]
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, " ".join(names))
    with pytest.raises(RealHeadError, match="more than 64 variables"):
        real_head.bounded_child_environment("codex-cli")


def test_extra_env_total_bytes_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, "SYNTH_BIG_VALUE")
    monkeypatch.setenv(
        "SYNTH_BIG_VALUE", "x" * real_head.EXTRA_ENV_MAX_BYTES
    )
    with pytest.raises(RealHeadError, match="bytes of names/values"):
        real_head.bounded_child_environment("codex-cli")


def test_extra_env_excess_refuses_before_spawn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    names = [
        f"SYNTH_EXTRA_{index}"
        for index in range(real_head.EXTRA_ENV_MAX_VARS + 1)
    ]
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, " ".join(names))
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    monkeypatch.setattr(
        real_head.subprocess,
        "run",
        lambda *a, **k: pytest.fail("spawned with an over-limit extra env"),
    )
    with pytest.raises(RealHeadError, match="more than 64 variables"):
        execute_real_head(
            head="claude-code",
            cmd="/usr/bin/claude",
            attempt_dir=str(attempt_dir),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )
    assert not (attempt_dir / "mcp-config.json").exists()


def test_child_stderr_suppresses_short_copied_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """A short opted-in value makes the retained child stderr ambiguous,
    so suppress the tail rather than leaking a short credential."""
    extra_secret = "synthetic-provider-key-9f2c"
    api_secret = "synthetic-anthropic-credential-7a1b"
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, "MY_PROVIDER_KEY TINY_FLAG")
    monkeypatch.setenv("MY_PROVIDER_KEY", extra_secret)
    monkeypatch.setenv("TINY_FLAG", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", api_secret)
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()

    def fake_run(argv, **kwargs):
        class Proc:
            stdout = ""
            stderr = f"provider={extra_secret} api={api_secret} flag=1"
            returncode = 1

        return Proc()

    monkeypatch.setattr(real_head.subprocess, "run", fake_run)

    from exercise.attempt import AttemptError

    def failing_grade(*a, **k):
        raise AttemptError("attempt documents unusable: no trace")

    monkeypatch.setattr("exercise.attempt.grade_attempt", failing_grade)
    lane = execute_real_head(
        head="claude-code",
        cmd=cmd,
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    recorded = json.dumps(lane)
    assert extra_secret not in recorded
    assert api_secret not in recorded
    assert "flag=1" not in lane["reason"]
    assert "<redacted child stderr>" in lane["reason"]


def test_total_child_environment_bytes_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "x" * (real_head.CHILD_ENV_MAX_BYTES + 1))
    with pytest.raises(RealHeadError, match="head child environment exceeds"):
        real_head.bounded_child_environment("codex-cli")


def test_minted_trace_cannot_exceed_total_child_environment_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    base = real_head.bounded_child_environment("codex-cli")
    base_bytes = sum(len(k.encode()) + len(v.encode()) + 2 for k, v in base.items())
    key_bytes = len("OPENAI_API_KEY") + 2
    monkeypatch.setenv(
        "OPENAI_API_KEY",
        "x" * (real_head.CHILD_ENV_MAX_BYTES - base_bytes - key_bytes - 32),
    )
    real_head.bounded_child_environment("codex-cli")
    monkeypatch.setattr(real_head, "codex_preflight", lambda: {"kind": "test"})
    monkeypatch.setattr(
        real_head.subprocess,
        "run",
        lambda *a, **k: pytest.fail("oversized final child environment spawned"),
    )
    with pytest.raises(RealHeadError, match="head child environment exceeds"):
        execute_real_head(
            head="codex-cli",
            cmd=_fake_executable(tmp_path, "codex"),
            attempt_dir=str(tmp_path / "attempt"),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )


def test_long_copied_credentials_are_redacted_with_stderr_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    extra_secret = "synthetic-provider-key-9f2c"
    api_secret = "synthetic-anthropic-credential-7a1b"
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, "MY_PROVIDER_KEY")
    monkeypatch.setenv("MY_PROVIDER_KEY", extra_secret)
    monkeypatch.setenv("ANTHROPIC_API_KEY", api_secret)
    credential_path = "/synthetic/private/google-credential-file.json"
    monkeypatch.setenv("CLAUDE_CODE_USE_VERTEX", "1")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", credential_path)
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)

    class Proc:
        stdout = ""
        stderr = (
            f"prefix provider={extra_secret} api={api_secret} "
            f"credential_path={credential_path} suffix"
        )
        returncode = 1

    monkeypatch.setattr(real_head.subprocess, "run", lambda *a, **k: Proc())
    from exercise.attempt import AttemptError

    def failing_grade(*a, **k):
        raise AttemptError("attempt documents unusable: no trace")

    monkeypatch.setattr("exercise.attempt.grade_attempt", failing_grade)
    lane = execute_real_head(
        head="claude-code",
        cmd=cmd,
        attempt_dir=str(tmp_path / "attempt"),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    recorded = json.dumps(lane)
    assert extra_secret not in recorded
    assert api_secret not in recorded
    assert credential_path not in recorded
    assert (
        "prefix provider=<redacted> api=<redacted> "
        "credential_path=<redacted> suffix"
    ) in lane["reason"]


def test_conventional_proxy_requires_explicit_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.invalid:8080")
    assert "HTTPS_PROXY" not in real_head.bounded_child_environment("qwen-code")
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, "HTTPS_PROXY")
    assert real_head.bounded_child_environment("qwen-code")["HTTPS_PROXY"] == (
        "http://proxy.example.invalid:8080"
    )
    monkeypatch.setenv("https_proxy", "http://lowercase.invalid:8080")
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, "https_proxy")
    assert real_head.bounded_child_environment("qwen-code")["https_proxy"] == (
        "http://lowercase.invalid:8080"
    )
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, "CUSTOM_PROXY")
    with pytest.raises(RealHeadError, match="reserved"):
        real_head.bounded_child_environment("qwen-code")


def test_credential_config_paths_are_sensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(real_head.EXTRA_ENV_ENV, raising=False)
    locations = {
        "CLAUDE_CONFIG_DIR": "/synthetic/private/claude",
        "AWS_CONFIG_FILE": "/synthetic/private/aws-config",
        "AWS_SHARED_CREDENTIALS_FILE": "/synthetic/private/aws-credentials",
        "CODEX_HOME": "/synthetic/private/codex",
        "GOOGLE_APPLICATION_CREDENTIALS": "/synthetic/private/google.json",
    }
    assert set(locations.values()).issubset(
        real_head._child_secret_values(locations)
    )


def test_child_stderr_secret_crossing_tail_boundary_is_scrubbed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = "synthetic-cross-boundary-secret"
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret)
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)

    class Proc:
        stdout = ""
        stderr = "x" * 400 + secret + "z" * 392
        returncode = 1

    monkeypatch.setattr(real_head.subprocess, "run", lambda *a, **k: Proc())
    from exercise.attempt import AttemptError

    def failing_grade(*a, **k):
        raise AttemptError("attempt documents unusable: no trace")

    monkeypatch.setattr("exercise.attempt.grade_attempt", failing_grade)
    lane = execute_real_head(
        head="claude-code",
        cmd=cmd,
        attempt_dir=str(tmp_path / "attempt"),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    assert secret not in json.dumps(lane)
    assert secret[-8:] not in lane["reason"]
# --- Launch preflight: child-PATH resolution and fail-closed ordering ---


def _nt_os(shim_isfile) -> SimpleNamespace:
    """An os shim with nt semantics so the resolver's Windows behavior
    runs on every host (the test_mcp_stdio_env.py SimpleNamespace
    pattern): the child env decides, never the host filesystem layout."""
    return SimpleNamespace(
        name="nt",
        pathsep=";",
        X_OK=1,
        access=lambda candidate, mode: True,
        path=SimpleNamespace(
            join=ntpath.join, isfile=shim_isfile, isdir=lambda candidate: False
        ),
    )


def _posix_os(shim_isfile, shim_access) -> SimpleNamespace:
    return SimpleNamespace(
        name="posix",
        pathsep=":",
        X_OK=1,
        access=shim_access,
        path=SimpleNamespace(
            join=posixpath.join, isfile=shim_isfile, isdir=lambda candidate: False
        ),
    )


def test_resolver_refuses_a_blank_command() -> None:
    with pytest.raises(RealHeadError, match="blank"):
        real_head._resolve_child_executable("   ", {"PATH": "/synthetic/bin"}, Path("."))


def test_resolver_refuses_a_bare_command_without_a_child_path(tmp_path: Path) -> None:
    with pytest.raises(RealHeadError, match="no PATH"):
        real_head._resolve_child_executable("synthetic-head", {}, tmp_path)


def test_resolver_accepts_an_absolute_file_and_returns_it_verbatim(
    tmp_path: Path,
) -> None:
    exe = _fake_executable(tmp_path, "claude")
    assert real_head._resolve_child_executable(exe, {}, tmp_path) == exe


def test_resolver_refuses_an_absent_absolute_command(tmp_path: Path) -> None:
    missing = str(tmp_path / "absent" / "claude")
    with pytest.raises(RealHeadError, match="not an existing file"):
        real_head._resolve_child_executable(missing, {}, tmp_path)


def test_resolver_refuses_a_directory_command(tmp_path: Path) -> None:
    with pytest.raises(RealHeadError, match="directory"):
        real_head._resolve_child_executable(str(tmp_path), {}, tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX exec-bit discipline")
def test_resolver_refuses_a_non_executable_absolute_file(tmp_path: Path) -> None:
    path = tmp_path / "claude"
    path.write_text("synthetic stub\n", encoding="utf-8")
    with pytest.raises(RealHeadError, match="not executable"):
        real_head._resolve_child_executable(str(path), {}, tmp_path)


def test_resolver_resolves_a_relative_command_against_the_attempt_dir(
    tmp_path: Path,
) -> None:
    """A separator-carrying relative command resolves against the spawn
    cwd (the attempt directory), never against the runner's own cwd."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = _fake_executable(bin_dir, "claude")
    relative = os.path.join("bin", os.path.basename(exe))
    assert real_head._resolve_child_executable(relative, {}, tmp_path) == exe
    with pytest.raises(RealHeadError, match="not an existing file"):
        real_head._resolve_child_executable(
            os.path.join("bin", "absent-head"), {}, tmp_path
        )


def test_resolver_windows_resolves_only_through_the_child_pathext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the child's PATHEXT extensions are candidates: the .exe
    file sitting in the EARLIER PATH directory is never tried, and the
    search continues to a later directory holding the extension."""
    files = {r"C:\other\claude.cmd", r"C:\search\claude.exe"}
    monkeypatch.setattr(real_head, "os", _nt_os(lambda candidate: candidate in files))
    resolved = real_head._resolve_child_executable(
        "claude",
        {"PATH": r"C:\search;" + r"C:\other", "PATHEXT": ".cmd"},
        Path("."),
    )
    assert resolved == r"C:\other\claude.cmd"


def test_resolver_windows_falls_back_to_the_default_pathext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No child PATHEXT falls back to CPython's default extension list,
    still resolved inside the child's PATH directories only."""
    files = {r"C:\search\claude.EXE"}
    monkeypatch.setattr(real_head, "os", _nt_os(lambda candidate: candidate in files))
    resolved = real_head._resolve_child_executable(
        "claude", {"PATH": r"C:\search"}, Path(".")
    )
    assert resolved == r"C:\search\claude.EXE"


def test_resolver_windows_keeps_an_armed_extension_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A command already carrying an extension is tried as-is; PATHEXT
    is never appended to it."""
    files = {r"C:\search\claude.exe"}
    monkeypatch.setattr(real_head, "os", _nt_os(lambda candidate: candidate in files))
    resolved = real_head._resolve_child_executable(
        "claude.exe", {"PATH": r"C:\search", "PATHEXT": ".cmd"}, Path(".")
    )
    assert resolved == r"C:\search\claude.exe"


@pytest.mark.parametrize("cmd", [r"C:\bin\claude.exe:ads", "claude.exe:ads"])
def test_resolver_windows_refuses_alternate_data_streams(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, cmd: str
) -> None:
    monkeypatch.setattr(real_head, "os", _nt_os(lambda candidate: True))
    with pytest.raises(RealHeadError, match="alternate data stream"):
        real_head._resolve_child_executable(cmd, {"PATH": r"C:\bin"}, tmp_path)


def test_resolver_refuses_a_nul_byte_command() -> None:
    with pytest.raises(RealHeadError, match="NUL"):
        real_head._resolve_child_executable(
            "cla\0ude", {"PATH": "/usr/bin"}, Path("/tmp")
        )


def test_resolver_resolves_a_relative_path_entry_against_the_attempt_dir(
    tmp_path: Path,
) -> None:
    """A relative child-PATH entry belongs to the child's cwd — the
    attempt directory — never the runner's own working directory."""
    attempt = tmp_path / "attempt"
    bin_dir = attempt / "bin"
    bin_dir.mkdir(parents=True)
    if os.name == "nt":
        tool = bin_dir / "head.cmd"
        tool.write_text("", encoding="utf-8")
    else:
        tool = bin_dir / "head"
        tool.write_text("", encoding="utf-8")
        tool.chmod(0o755)
    resolved = real_head._resolve_child_executable("head", {"PATH": "bin"}, attempt)
    assert Path(resolved).resolve() == tool.resolve()


def test_resolver_skips_non_executable_and_directory_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A directory or a non-executable file earlier on the child PATH is
    skipped, and the search continues to the executable entry."""
    kinds = {
        "/search-a/claude": "dir",
        "/search-b/claude": "plain-file",
        "/search-c/claude": "executable",
    }
    monkeypatch.setattr(
        real_head,
        "os",
        _posix_os(
            lambda candidate: kinds.get(candidate) in ("plain-file", "executable"),
            lambda candidate, mode: kinds.get(candidate) == "executable",
        ),
    )
    resolved = real_head._resolve_child_executable(
        "claude", {"PATH": "/search-a:/search-b:/search-c"}, Path(".")
    )
    assert resolved == "/search-c/claude"


def test_absent_command_fails_closed_before_mint_config_or_spawn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A command that cannot resolve refuses BEFORE anything sensitive
    happens: no minted key, no private config, no spawn."""
    missing = str(tmp_path / "absent" / "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], missing)
    attempt_dir = tmp_path / "attempt"
    _forbid_mint(monkeypatch)
    monkeypatch.setattr(
        real_head.subprocess,
        "run",
        lambda *a, **k: pytest.fail("spawned after a refused launch"),
    )
    with pytest.raises(RealHeadError, match="not an existing file"):
        execute_real_head(
            head="claude-code",
            cmd=missing,
            attempt_dir=str(attempt_dir),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )
    assert not (attempt_dir / "mcp-config.json").exists()


def test_codex_config_failure_fails_closed_before_mint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A resolvable command with an unwired codex transport still refuses
    before the key exists (the preflight moved ahead of minting)."""
    cmd = _fake_executable(tmp_path, "codex")
    monkeypatch.setenv(ARMING_ENVS["codex-cli"], cmd)
    monkeypatch.setattr(
        real_head, "_codex_config_path", lambda: tmp_path / "absent-config.toml"
    )
    _forbid_mint(monkeypatch)
    with pytest.raises(RealHeadError, match="config missing"):
        execute_real_head(
            head="codex-cli",
            cmd=cmd,
            attempt_dir=str(tmp_path / "attempt"),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )


def test_extra_env_validation_precedes_executable_preflight(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The operator opt-in is validated before the resolver runs: a
    reserved name refuses even with a command that cannot resolve."""
    monkeypatch.setenv(real_head.EXTRA_ENV_ENV, "PYTHONPATH")
    with pytest.raises(RealHeadError, match="reserved"):
        execute_real_head(
            head="claude-code",
            cmd=str(tmp_path / "absent" / "claude"),
            attempt_dir=str(tmp_path / "attempt"),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )


def test_missing_launcher_fails_closed_before_mint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Both private-config heads verify the shared launcher before the
    key is minted (qwen rides the same launcher as claude)."""
    for head in ("claude-code", "qwen-code"):
        cmd = _fake_executable(tmp_path, "head")
        monkeypatch.setenv(ARMING_ENVS[head], cmd)
        monkeypatch.setattr(
            real_head,
            "_mcp_launcher_path",
            lambda: tmp_path / "absent" / "launch_mcp.py",
        )
        _forbid_mint(monkeypatch)
        with pytest.raises(RealHeadError, match="launcher"):
            execute_real_head(
                head=head,
                cmd=cmd,
                attempt_dir=str(tmp_path / "attempt"),
                expected_path="expected.json",
                prompt_text="p",
                prompt_sha256="a" * 64,
                prompt_chars=1,
                timeout_seconds=7,
            )


def test_missing_interpreter_fails_closed_before_mint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The interpreter the private config will name is verified while
    the preflight runs, not after the key is on disk."""
    cmd = _fake_executable(tmp_path, "claude")
    monkeypatch.setenv(ARMING_ENVS["claude-code"], cmd)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "absent-python"))
    _forbid_mint(monkeypatch)
    with pytest.raises(RealHeadError, match="interpreter"):
        execute_real_head(
            head="claude-code",
            cmd=cmd,
            attempt_dir=str(tmp_path / "attempt"),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX exec-bit semantics")
def test_launcher_needs_readability_not_the_exec_bit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The shared launcher runs as the interpreter's argument, never
    directly: a readable non-executable launcher is a valid transport."""
    launcher = tmp_path / "launch_mcp.py"
    launcher.write_text("# readable, never executed directly\n", encoding="utf-8")
    launcher.chmod(0o644)
    monkeypatch.setattr(real_head, "_mcp_launcher_path", lambda: launcher)
    cmd = _fake_executable(tmp_path, "claude")
    exec_path, transport_fact = real_head.launch_preflight(
        "claude-code", cmd, {"PATH": str(tmp_path)}, tmp_path
    )
    assert exec_path == cmd and transport_fact is None


def test_bare_command_without_a_child_path_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """No ambient fallback: a bare command with no PATH in the bounded
    child environment refuses instead of searching the runner's PATH."""
    monkeypatch.delenv("PATH", raising=False)
    _forbid_mint(monkeypatch)
    with pytest.raises(RealHeadError, match="no PATH"):
        execute_real_head(
            head="claude-code",
            cmd="synthetic-claude",
            attempt_dir=str(tmp_path / "attempt"),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX exec-bit semantics")
def test_non_executable_shadow_on_the_child_path_is_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    search_a = tmp_path / "a"
    search_b = tmp_path / "b"
    search_a.mkdir()
    search_b.mkdir()
    (search_a / "claude").write_text("not executable\n", encoding="utf-8")
    exe = _fake_executable(search_b, "claude")
    monkeypatch.setenv("PATH", os.pathsep.join([str(search_a), str(search_b)]))
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)
    lane = execute_real_head(
        head="claude-code",
        cmd="claude",
        attempt_dir=str(tmp_path / "attempt"),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    assert lane["status"] == "passed"
    assert seen["argv"][0] == exe
    # The record keeps the operator's armed command, not the rewrite.
    assert lane["spawn"]["argv"][0] == "claude"


@pytest.mark.skipif(os.name == "nt", reason="POSIX exec-bit semantics")
def test_only_non_executable_candidates_on_the_child_path_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    search_a = tmp_path / "a"
    search_a.mkdir()
    (search_a / "claude").write_text("not executable\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(search_a))
    _forbid_mint(monkeypatch)
    with pytest.raises(RealHeadError, match="not found"):
        execute_real_head(
            head="claude-code",
            cmd="claude",
            attempt_dir=str(tmp_path / "attempt"),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )


def test_directory_entry_on_the_child_path_is_skipped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    search_a = tmp_path / "a"
    search_b = tmp_path / "b"
    search_a.mkdir()
    search_b.mkdir()
    (search_a / ("claude.cmd" if os.name == "nt" else "claude")).mkdir()
    exe = _fake_executable(search_b, "claude")
    monkeypatch.setenv("PATH", os.pathsep.join([str(search_a), str(search_b)]))
    if os.name == "nt":
        monkeypatch.setenv("PATHEXT", ".cmd;.exe")
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)
    lane = execute_real_head(
        head="claude-code",
        cmd="claude",
        attempt_dir=str(tmp_path / "attempt"),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    assert lane["status"] == "passed"
    assert seen["argv"][0] == exe


def test_empty_path_entry_never_searches_the_attempt_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An empty PATH entry means the current directory on some platforms;
    the spawn cwd (the attempt directory) is never implicitly searched."""
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    _fake_executable(attempt_dir, "claude")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("PATH", os.pathsep.join(["", str(elsewhere)]))
    if os.name == "nt":
        monkeypatch.setenv("PATHEXT", ".cmd;.exe")
    _forbid_mint(monkeypatch)
    with pytest.raises(RealHeadError, match="not found"):
        execute_real_head(
            head="claude-code",
            cmd="claude",
            attempt_dir=str(attempt_dir),
            expected_path="expected.json",
            prompt_text="p",
            prompt_sha256="a" * 64,
            prompt_chars=1,
            timeout_seconds=7,
        )
    assert not (attempt_dir / "mcp-config.json").exists()


def test_child_path_names_the_spawned_binary_not_the_ambient_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The argv[0] rewrite: the CHILD env's PATH decides what spawns. An
    ambient PATH offering a same-named binary must never win — and the
    bare command must never reach CreateProcess for a parent-PATH search."""
    child_dir = tmp_path / "child"
    ambient_dir = tmp_path / "ambient"
    child_dir.mkdir()
    ambient_dir.mkdir()
    child_exe = _fake_executable(child_dir, "claude")
    ambient_exe = _fake_executable(ambient_dir, "claude")
    monkeypatch.setenv("PATH", str(ambient_dir))
    if os.name == "nt":
        monkeypatch.setenv("PATHEXT", ".cmd;.exe")
    # The bounded env is pinned by U-SAFE.d elsewhere; here it is the
    # seam that lets the child PATH name a different directory than the
    # runner's own ambient PATH above.
    child_env = real_head.bounded_child_environment("claude-code")
    child_env["PATH"] = str(child_dir)
    monkeypatch.setattr(
        real_head, "bounded_child_environment", lambda head: child_env
    )
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)
    lane = execute_real_head(
        head="claude-code",
        cmd="claude",
        attempt_dir=str(tmp_path / "attempt"),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    assert lane["status"] == "passed"
    assert seen["argv"][0] == child_exe
    assert seen["argv"][0] != ambient_exe


def test_bare_child_path_command_spawns_the_resolved_absolute_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    child_dir = tmp_path / "bin"
    child_dir.mkdir()
    exe = _fake_executable(child_dir, "claude")
    monkeypatch.setenv("PATH", str(child_dir))
    if os.name == "nt":
        monkeypatch.setenv("PATHEXT", ".cmd;.exe")
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)
    lane = execute_real_head(
        head="claude-code",
        cmd="claude",
        attempt_dir=str(tmp_path / "attempt"),
        expected_path="expected.json",
        prompt_text="p",
        prompt_sha256="a" * 64,
        prompt_chars=1,
        timeout_seconds=7,
    )
    assert lane["status"] == "passed"
    # The bare armed name spawns as its resolved absolute child-PATH hit.
    assert seen["argv"][0] == exe
    assert lane["spawn"]["argv"][0] == "claude"
