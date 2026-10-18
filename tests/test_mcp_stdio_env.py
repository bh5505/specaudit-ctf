"""Causal environment isolation for explicitly configured outbound MCP children."""

from __future__ import annotations

import ast
import errno
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from extension.contract import ArmSpec, Catalog, CatalogEntry, Extension, ExtensionError, NotCuratedError
from extension.transports import mcp
from extension.transports.mcp import McpTransport


ARM = "fixture-stdio"
SPEC = ArmSpec(id=ARM, protocols=("mcp",), curated=True, notes="Synthetic fixture.", tier="research")
TOKEN = "synthetic-authorized-token-92d48c"


def _transport(script: str, *, environment=None, timeout: float = 3.0) -> McpTransport:
    return McpTransport(
        stdio_cmds={ARM: [sys.executable, "-c", script]},
        stdio_envs=None if environment is None else {ARM: environment},
        timeout=timeout,
    )


def test_default_child_environment_has_no_ambient_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    marker = tmp_path / "startup-ran"
    (tmp_path / "sitecustomize.py").write_text(
        f"from pathlib import Path; Path({str(marker)!r}).touch()\n", encoding="utf-8"
    )
    ambient = {
        "CTF_AMBIENT_SENTINEL": "ambient-synthetic-value",
        "AWS_ACCESS_KEY_ID": "synthetic-ambient-credential",
        "AWS_PROFILE": "synthetic-profile", "GOOGLE_APPLICATION_CREDENTIALS": "/synthetic/key",
        "HTTP_PROXY": "http://synthetic.invalid", "https_proxy": "http://synthetic.invalid",
        "NO_PROXY": "synthetic.invalid", "PYTHONPATH": str(tmp_path),
        "PYTHONHOME": "/synthetic/not-a-python-home", "PYTHONSTARTUP": str(tmp_path / "startup.py"),
        "LD_PRELOAD": "/synthetic/not-a-library", "DYLD_INSERT_LIBRARIES": "/synthetic/library",
        "SPECAUDIT_TRACE_PATH": "/synthetic/trace", "PWD": str(tmp_path),
        "HOME": str(tmp_path), "PATH": str(tmp_path), "NODE_OPTIONS": "synthetic-marker",
    }
    for name, value in ambient.items():
        monkeypatch.setenv(name, value)
    result = _transport(
        "import json,os; print(json.dumps({'result': {'keys': sorted(os.environ)}}))"
    ).invoke(SPEC, "inspect", {})
    assert result.ok, result.error
    assert result.output == {"keys": ["LANG", "LC_ALL"]}
    assert not marker.exists()


def test_explicit_per_arm_environment_is_copied_and_payload_argv_preserved() -> None:
    configured = {"APP_TOKEN": TOKEN, "APP_CONFIG": "synthetic-config-v1"}
    script = (
        "import json,os,sys; request=json.loads(sys.stdin.readline()); "
        "print(json.dumps({'result': {'authorized': os.environ.get('APP_TOKEN') == "
        f"{TOKEN!r}, 'configured': os.environ.get('APP_CONFIG') == 'synthetic-config-v1', "
        "'argv': sys.argv[1:], 'request': request, 'tail': sys.stdin.read()}}))"
    )
    argv = [sys.executable, "-c", script, "spaces stay together", "--literal=$HOME"]
    transport = McpTransport(stdio_cmds={ARM: argv}, stdio_envs={ARM: configured})
    configured["APP_TOKEN"] = "mutated-after-validation"
    argv[-1] = "mutated-argv"
    result = transport.invoke(SPEC, "fixture.call", {"unicode": "é", "n": 4})
    assert result.ok, result.error
    assert result.output == {
        "authorized": True, "configured": True,
        "argv": ["spaces stay together", "--literal=$HOME"],
        "request": {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "fixture.call", "arguments": {"unicode": "é", "n": 4},
        }}, "tail": "",
    }


def test_explicit_path_supports_bare_executable_without_ambient_path() -> None:
    executable = Path(sys.executable)
    transport = McpTransport(
        stdio_cmds={ARM: [executable.name, "-c", "import json; print(json.dumps({'result': {'ok': True}}))"]},
        stdio_envs={ARM: {"PATH": str(executable.parent)}},
    )
    result = transport.invoke(SPEC, "ping", {})
    assert result.ok, result.error
    assert result.output == {"ok": True}


def test_explicit_path_does_not_fall_back_to_parent_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", str(Path(sys.executable).parent))
    transport = McpTransport(
        stdio_cmds={ARM: [Path(sys.executable).name]},
        stdio_envs={ARM: {"PATH": str(tmp_path)}},
    )
    result = transport.invoke(SPEC, "ping", {})
    assert not result.ok
    assert result.error == "stdio executable not found in explicit PATH"


def test_environment_is_bound_to_one_exact_arm() -> None:
    other = "other-stdio"
    script = "import json,os; print(json.dumps({'result': {'has_token': 'APP_TOKEN' in os.environ}}))"
    transport = McpTransport(
        stdio_cmds={ARM: [sys.executable, "-c", script], other: [sys.executable, "-c", script]},
        stdio_envs={ARM: {"APP_TOKEN": TOKEN}},
    )
    other_spec = ArmSpec(id=other, protocols=("mcp",), curated=True, notes="Synthetic.", tier="research")
    assert transport.invoke(SPEC, "ping", {}).output == {"has_token": True}
    assert transport.invoke(other_spec, "ping", {}).output == {"has_token": False}


@pytest.mark.parametrize("environment", [
    None, [], "APP_TOKEN=value", {"APP_TOKEN": None}, {"APP_TOKEN": 1},
    {"APP_TOKEN": b"bytes"}, {"APP_TOKEN": "nul\0value"}, {1: "value"},
    {"": "value"}, {"NAME=BAD": "value"}, {"WITH SPACE": "value"},
    {"APP_TOKEN": "value", "app_token": "other"}, {"Path": "/usr/bin"},
    {"APP_TOKEN": "\ud800"}, {"APP_TOKEN": "x" * mcp._MAX_ENV_BYTES},
    {f"APP_{index}": "value" for index in range(mcp._MAX_ENV_VARS + 1)},
])
def test_malformed_environment_refused_before_spawn(environment, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp.subprocess, "run", lambda *a, **kw: pytest.fail("spawned invalid config"))
    with pytest.raises(ValueError):
        McpTransport(stdio_cmds={ARM: [sys.executable]}, stdio_envs={ARM: environment})


@pytest.mark.parametrize("name", [
    "PYTHONPATH", "pythonstartup", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV",
    "ENV", "NODE_OPTIONS", "RUBYOPT", "PERL5OPT", "GIT_CONFIG_COUNT", "GIT_TRACE",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "GCONV_PATH",
    "CTF_TRACE_PATH", "HTTP_PROXY", "https_proxy", "NO_PROXY", "PWD", "LC_ALL", "SystemRoot",
])
def test_unsafe_explicit_environment_refused(name: str) -> None:
    with pytest.raises(ValueError, match="reserved"):
        _transport("", environment={name: "synthetic-rejected-value"})


@pytest.mark.parametrize("path", ["", ".", "relative", "/usr/bin:", ":/usr/bin", "/usr/bin:/usr/bin", "/usr/bin:/usr/bin/.", "/usr/../bin", ":".join(f"/d{i}" for i in range(17))])
def test_path_contract_refuses_unbounded_or_relative_search(path: str) -> None:
    with pytest.raises(ValueError, match="PATH"):
        _transport("", environment={"PATH": path})


@pytest.mark.parametrize("command", [["python"], ["./python"], ["subdir/python"], [""], "python", [1], ["/python\0"]])
def test_unsafe_command_refused_before_spawn(command) -> None:
    with pytest.raises(ValueError):
        McpTransport(stdio_cmds={ARM: command})


@pytest.mark.parametrize("kwargs", [
    {"stdio_envs": {"unknown": {"APP_TOKEN": TOKEN}}},
    {"stdio_cmds": {ARM: []}, "stdio_envs": {ARM: {}}},
    {"stdio_cmds": {ARM: None}, "stdio_envs": {ARM: {}}},
    {"stdio_cmds": {ARM: [sys.executable]}, "endpoints": {ARM: "http://synthetic.invalid"}, "stdio_envs": {ARM: {}}},
    {"stdio_envs": []}, {"stdio_cmds": []},
])
def test_unmatched_or_ambiguous_environment_refused(kwargs) -> None:
    with pytest.raises(ValueError):
        McpTransport(**kwargs)


class _DuplicateMapping(dict):
    def items(self):
        return [("APP_TOKEN", "synthetic-one"), ("APP_TOKEN", "synthetic-two")]


def test_duplicate_mapping_entries_refused() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        _transport("", environment=_DuplicateMapping())


@pytest.mark.parametrize("body,ok,error", [
    ("print('not JSON')", False, "no JSON-RPC response"),
    ("print('{broken')", False, "Expecting property name"),
    ("print('[]')", False, "no JSON-RPC response"),
    ("print('{\"result\": 5}')", False, "malformed tool result"),
    ("print('{\"error\": {\"message\": \"refused\"}}')", False, "refused"),
    ("print('{\"result\": {\"isError\": true, \"content\": [{\"text\": \"denied\"}]}}')", False, "denied"),
    ("print('startup banner'); print('{\"result\": {\"ok\": true}}')", True, None),
])
def test_stdio_response_translation_preserved(body: str, ok: bool, error: str | None) -> None:
    result = _transport(body).invoke(SPEC, "ping", {})
    assert result.ok is ok
    if error:
        assert error in result.error
    else:
        assert result.error is None


def test_stdio_timeout_remains_failure() -> None:
    result = _transport("import time; time.sleep(1)", timeout=0.05).invoke(SPEC, "ping", {})
    assert not result.ok
    assert "timed out" in result.error


@pytest.mark.parametrize("credential", [
    "synthetic-unicode-凭据", "synthetic-'single\"double-quote",
    "synthetic-backslash-\\value", "synthetic-newline-\nvalue",
])
def test_timeout_argv_redacted_before_exception_escaping(credential: str) -> None:
    timeout = 0.05
    transport = McpTransport(
        stdio_cmds={ARM: [sys.executable, "-c", "import time; time.sleep(1)", credential]},
        stdio_envs={ARM: {"APP_TOKEN": credential}}, timeout=timeout,
    )
    result = transport.invoke(SPEC, "ping", {})
    assert not result.ok
    assert result.output is None
    command = result.error.removeprefix("Command '").removesuffix(
        f"' timed out after {timeout} seconds"
    )
    assert ast.literal_eval(command)[-1] == "[redacted]"


@pytest.mark.parametrize("credential", [
    "synthetic-unicode-凭据", "synthetic-'single\"double-quote",
    "synthetic-backslash-\\value", "synthetic-newline-\nvalue",
])
def test_missing_filename_redacted_before_exception_escaping(
    credential: str, tmp_path: Path,
) -> None:
    missing = str(tmp_path / ("absent-" + credential))
    transport = McpTransport(
        stdio_cmds={ARM: [missing]}, stdio_envs={ARM: {"APP_TOKEN": credential}},
    )
    result = transport.invoke(SPEC, "ping", {})
    assert not result.ok
    assert result.output is None
    assert "No such file or directory" in result.error
    rendered_filename = result.error.rsplit(": ", 1)[-1]
    assert ast.literal_eval(rendered_filename) == str(tmp_path / "absent-[redacted]")


@pytest.mark.parametrize("credential", [
    "synthetic-unicode-凭据", "synthetic-'single\"double-quote",
    "synthetic-backslash-\\value", "synthetic-newline-\nvalue",
])
@pytest.mark.parametrize("kind", ["timeout-tuple", "two-filenames", "bytes-filename", "message-only", "ordinary"])
def test_structured_process_exception_fields_redacted(
    credential: str, kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    if kind == "timeout-tuple":
        exception = subprocess.TimeoutExpired((sys.executable, credential), 1)
        expected = str(subprocess.TimeoutExpired([sys.executable, "[redacted]"], 1))
    elif kind == "two-filenames":
        exception = OSError(errno.ENOENT, "missing " + credential, credential, None, credential)
        expected = str(OSError(errno.ENOENT, "missing [redacted]", "[redacted]", None, "[redacted]"))
    elif kind == "bytes-filename":
        exception = FileNotFoundError(errno.ENOENT, "missing", credential.encode("utf-8"))
        expected = str(FileNotFoundError(errno.ENOENT, "missing", b"[redacted]"))
    elif kind == "message-only":
        exception = OSError("missing " + credential)
        expected = "missing [redacted]"
    else:
        exception = ValueError("ordinary " + credential)
        expected = "ordinary [redacted]"

    def refuse(*args, **kwargs):
        raise exception

    monkeypatch.setattr(mcp.subprocess, "run", refuse)
    result = _transport("", environment={"APP_TOKEN": credential}).invoke(SPEC, "ping", {})
    assert not result.ok
    assert result.output is None
    assert result.error == expected


def test_absent_exception_filenames_remain_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args, **kwargs):
        raise OSError(errno.EACCES, "permission denied")

    monkeypatch.setattr(mcp.subprocess, "run", refuse)
    result = _transport("", environment={"APP_CONFIG": "null"}).invoke(SPEC, "ping", {})
    assert not result.ok
    assert result.error == str(OSError(errno.EACCES, "permission denied"))


def test_rendered_os_error_gets_final_numeric_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args, **kwargs):
        raise OSError(errno.EACCES, "permission denied")

    monkeypatch.setattr(mcp.subprocess, "run", refuse)
    result = _transport("", environment={"APP_CONFIG": str(errno.EACCES)}).invoke(SPEC, "ping", {})
    assert not result.ok
    assert result.error == "[Errno [redacted]] permission denied"


def test_stdout_total_cap_includes_trailing_output() -> None:
    result = _transport(
        f"print('{{\"result\": {{\"ok\": true}}}}'); print('x' * {mcp._MAX_BYTES})"
    ).invoke(SPEC, "ping", {})
    assert not result.ok
    assert "response exceeds" in result.error


@pytest.mark.parametrize("script", [
    "import os,sys; print(os.environ['APP_TOKEN'], file=sys.stderr); sys.exit(3)",
    "import json,os; print(json.dumps({'result': {'content': [os.environ['APP_TOKEN']], os.environ['APP_TOKEN']: 'key'}}))",
    "import json,os; print(json.dumps({'error': {'message': os.environ['APP_TOKEN']}}))",
])
def test_configured_values_scrubbed_from_result_and_error(script: str) -> None:
    result = _transport(script, environment={"APP_TOKEN": TOKEN}).invoke(SPEC, "ping", {})
    serialized = json.dumps({"output": result.output, "error": result.error})
    assert TOKEN not in serialized
    assert "[redacted]" in serialized


@pytest.mark.parametrize("credential", [
    "synthetic-unicode-密钥-凭据", "synthetic-quoted-\"credential\"",
    "synthetic-backslash-\\credential", "synthetic-newline-\ncredential",
])
@pytest.mark.parametrize("kind", ["rpc-error", "tool-error"])
def test_structured_errors_redacted_before_rendering(credential: str, kind: str) -> None:
    script = (
        "import json,os; secret=os.environ['APP_TOKEN']; "
        + ("body={'error': {'data': {'nested': secret}}}; " if kind == "rpc-error" else
           "body={'result': {'isError': True, 'content': [{'text': {'nested': secret}}]}}; ")
        + "print(json.dumps(body))"
    )
    result = _transport(script, environment={"APP_TOKEN": credential}).invoke(SPEC, "ping", {})
    assert not result.ok
    if kind == "rpc-error":
        assert result.output == {"data": {"nested": "[redacted]"}}
        assert json.loads(result.error) == result.output
    else:
        assert result.output == {
            "isError": True, "content": [{"text": {"nested": "[redacted]"}}],
        }
        assert result.error == "{'nested': '[redacted]'}"
    assert credential not in json.dumps(result.output, ensure_ascii=False)
    assert credential not in result.error


def test_response_classification_precedes_redaction() -> None:
    result = _transport(
        "print('{\"result\": {\"ok\": true}}')", environment={"APP_CONFIG": "result"},
    ).invoke(SPEC, "ping", {})
    assert result.ok
    assert result.output == {"ok": True}


def test_numeric_response_echo_is_redacted() -> None:
    result = _transport(
        "import json,os; print(json.dumps({'result': {'echo': int(os.environ['APP_CONFIG'])}}))",
        environment={"APP_CONFIG": "928471"},
    ).invoke(SPEC, "ping", {})
    assert result.ok
    assert result.output == {"echo": "[redacted]"}


@pytest.mark.parametrize("configured", ["null", "true", "false", "9138", "19.25"])
def test_json_primitive_response_echo_is_redacted(configured: str) -> None:
    result = _transport(
        "import json,os; print(json.dumps({'result': {'echo': json.loads(os.environ['APP_CONFIG'])}}))",
        environment={"APP_CONFIG": configured},
    ).invoke(SPEC, "ping", {})
    assert result.ok
    assert result.output == {"echo": "[redacted]"}


def test_redaction_accepts_deeply_nested_valid_json() -> None:
    script = (
        "import os; print('{\"result\": {\"nested\": ' + '[' * 700 + "
        "'\"' + os.environ['APP_TOKEN'] + '\"' + ']' * 700 + '}}')"
    )
    result = _transport(script, environment={"APP_TOKEN": TOKEN}).invoke(SPEC, "ping", {})
    assert result.ok, result.error
    item = result.output["nested"]
    for _ in range(700):
        assert isinstance(item, list) and len(item) == 1
        item = item[0]
    assert item == "[redacted]"


def test_transport_injected_at_existing_extension_handler_seam() -> None:
    entry = CatalogEntry(id=ARM, kind="arm", protocols=("mcp",), curated=True, notes="Synthetic fixture.", tier="research")
    transport = _transport(
        f"import json,os; print(json.dumps({{'result': {{'authorized': os.environ.get('APP_TOKEN') == {TOKEN!r}}}}}))",
        environment={"APP_TOKEN": TOKEN},
    )
    extension = Extension(catalog=Catalog([entry]), arms={ARM: transport}, transports={})
    result = extension.invoke(ARM, "ping", {})
    assert result.ok, result.error
    assert result.output == {"authorized": True}


@pytest.mark.parametrize("curated", [False, True])
def test_generic_extension_transport_preserves_admission_refusals(
    curated: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = CatalogEntry(id=ARM, kind="arm", protocols=("mcp",), curated=curated, notes="Synthetic fixture.", tier="research")
    transport = _transport("raise AssertionError('must not spawn')")
    monkeypatch.setattr(mcp.subprocess, "run", lambda *a, **kw: pytest.fail("spawned refused generic transport"))
    extension = Extension(catalog=Catalog([entry]), arms={}, transports={"mcp": transport})
    error_type = ExtensionError if curated else NotCuratedError
    with pytest.raises(error_type):
        extension.invoke(ARM, "ping", {})


def test_legacy_positional_constructor_and_empty_argv_preserved() -> None:
    transport = McpTransport({}, {ARM: []}, None, 0.5)
    assert transport.timeout == 0.5
    assert transport._stdio_cmds[ARM] == []
    assert not transport.installed(SPEC)


def test_windows_bootstrap_reads_only_case_insensitive_systemroot(monkeypatch: pytest.MonkeyPatch) -> None:
    windows = SimpleNamespace(name="nt", pathsep=";", environ={
        "systemroot": "C:\\Windows", "APP_TOKEN": TOKEN, "PATH": "C:\\untrusted",
    })
    monkeypatch.setattr(mcp, "os", windows)
    assert mcp._minimal_stdio_environment() == {
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "SystemRoot": "C:\\Windows",
    }
    transport = McpTransport(stdio_cmds={ARM: ["C:\\Python\\python.exe"]})
    assert transport.installed(SPEC)


def test_windows_path_resolution_uses_fixed_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    visited = []

    def isfile(candidate):
        visited.append(candidate)
        return candidate == "C:\\allowed\\fixture.exe"

    windows = SimpleNamespace(
        name="nt", pathsep=";", X_OK=1, access=lambda candidate, mode: True,
        path=SimpleNamespace(join=mcp.ntpath.join, isfile=isfile),
    )
    monkeypatch.setattr(mcp, "os", windows)
    assert mcp._resolved_stdio_argv(["fixture", "literal-arg"], {"PATH": "C:\\allowed"}) == [
        "C:\\allowed\\fixture.exe", "literal-arg",
    ]
    assert visited == ["C:\\allowed\\fixture", "C:\\allowed\\fixture.exe"]


@pytest.mark.parametrize("executable", [
    "C:fixture.exe", "C:fixture", "fixture.exe:stream", ":fixture.exe", ".", "..",
    "C:\\allowed\\fixture.exe:stream", "\\\\server\\share\\fixture.exe:stream",
])
def test_windows_drive_relative_and_stream_executables_refused(
    executable: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp, "os", SimpleNamespace(name="nt", pathsep=";"))
    with pytest.raises(ValueError):
        McpTransport(
            stdio_cmds={ARM: [executable]}, stdio_envs={ARM: {"PATH": "D:\\allowed"}},
        )
    with pytest.raises(ValueError):
        mcp._resolved_stdio_argv([executable], {"PATH": "D:\\allowed"})


@pytest.mark.parametrize("candidate", ["C:fixture.exe", "D:\\outside\\fixture.exe", "D:\\allowed\\.."])
def test_windows_resolved_candidate_must_stay_in_search_directory(
    candidate: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows = SimpleNamespace(
        name="nt", pathsep=";", X_OK=1, access=lambda *a: pytest.fail("outside access"),
        path=SimpleNamespace(
            join=lambda *a: candidate, isfile=lambda *a: pytest.fail("outside stat"),
        ),
    )
    monkeypatch.setattr(mcp, "os", windows)
    with pytest.raises(RuntimeError, match="escaped"):
        mcp._resolved_stdio_argv(["fixture.exe"], {"PATH": "D:\\allowed"})


def test_windows_path_refuses_case_aliased_directories(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp, "os", SimpleNamespace(name="nt", pathsep=";"))
    with pytest.raises(ValueError, match="distinct absolute"):
        McpTransport(
            stdio_cmds={ARM: ["fixture"]},
            stdio_envs={ARM: {"PATH": "C:\\allowed;c:\\ALLOWED"}},
        )


@pytest.mark.parametrize("environ", [{}, {"SystemRoot": "relative"}, {"SystemRoot": "C:\\Windows", "SYSTEMROOT": "D:\\Windows"}])
def test_windows_invalid_or_ambiguous_bootstrap_refused(environ, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp, "os", SimpleNamespace(name="nt", environ=environ))
    with pytest.raises(ValueError, match="SystemRoot"):
        mcp._minimal_stdio_environment()
