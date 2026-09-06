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
import os
import subprocess
from pathlib import Path

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


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """No real head is armed, and no timeout env leaks in."""
    for env in ARMING_ENVS.values():
        monkeypatch.delenv(env, raising=False)
    monkeypatch.delenv(HEAD_TIMEOUT_ENV, raising=False)


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
    monkeypatch.setenv(ARMING_ENVS["claude-code"], "/usr/bin/claude")
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)

    prompt_text, sha, chars = load_prompt(str(prompt_file))
    lane = execute_real_head(
        head="claude-code",
        cmd="/usr/bin/claude",
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text=prompt_text,
        prompt_sha256=sha,
        prompt_chars=chars,
        timeout_seconds=60,
    )

    assert lane["status"] == "passed" and lane["passed"] is True
    argv = seen["argv"]
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
    it (the runner deletes the file after the spawn)."""
    monkeypatch.setenv(ARMING_ENVS["claude-code"], "/usr/bin/claude")
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
        cmd="/usr/bin/claude",
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
    monkeypatch.setenv(ARMING_ENVS["codex-cli"], "/usr/bin/codex")
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
        cmd="/usr/bin/codex",
        attempt_dir=str(attempt_dir),
        expected_path="expected.json",
        prompt_text=prompt_text,
        prompt_sha256=sha,
        prompt_chars=chars,
        timeout_seconds=60,
    )

    assert lane["status"] == "passed"
    argv = seen["argv"]
    assert argv[:5] == ["/usr/bin/codex", "exec", "--sandbox", "workspace-write", "--skip-git-repo-check"]
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
    monkeypatch.setenv(ARMING_ENVS["codex-cli"], "/usr/bin/codex")
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
            cmd="/usr/bin/codex",
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
    monkeypatch.setenv(ARMING_ENVS["claude-code"], "/usr/bin/claude")
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
        cmd="/usr/bin/claude",
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


def test_spawn_failure_fails_closed_and_deletes_the_temp_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """A head binary that cannot exec (missing, bad cwd) leaves no key
    material on disk and no traceback: a fail-closed lane with the
    spawn error as the reason, and the temp mcp-config gone."""
    monkeypatch.setenv(ARMING_ENVS["claude-code"], "/nonexistent/claude")
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()

    def deny(argv, **kwargs):
        raise FileNotFoundError(f"[Errno 2] no such file: {argv[0]}")

    monkeypatch.setattr(real_head.subprocess, "run", deny)
    monkeypatch.setattr("exercise.attempt.grade_attempt", deny)
    lane = execute_real_head(
        head="claude-code",
        cmd="/nonexistent/claude",
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
    monkeypatch.setenv(ARMING_ENVS["claude-code"], "/usr/bin/claude")
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
        cmd="/usr/bin/claude",
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
    monkeypatch.setenv(ARMING_ENVS["claude-code"], "/usr/bin/claude")
    monkeypatch.setenv("SPECAUDIT_CTF_MCP_TRACE_KEY", "stale-key-value")
    monkeypatch.setenv("SPECAUDIT_CTF_MCP_TRACE", "/stale/trace")
    attempt_dir = tmp_path / "attempt"
    attempt_dir.mkdir()
    seen: dict = {}
    _stub_run(monkeypatch, seen=seen)
    _stub_grade(monkeypatch, passed=True)
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
    child_env = seen["kwargs"]["env"]
    assert "SPECAUDIT_CTF_MCP_TRACE_KEY" not in child_env
    assert "SPECAUDIT_CTF_MCP_TRACE" not in child_env


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


def test_run_exercise_end_to_end_with_a_stubbed_head(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prompt_file: Path
) -> None:
    """The full runner path: armed head + prompt file -> report carries
    the graded lane and never leaks the trace key or prompt text."""
    monkeypatch.setenv(ARMING_ENVS["claude-code"], "/usr/bin/claude")
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
