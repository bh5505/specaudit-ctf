"""Thin MCP JSON-RPC client (tools/call)."""

from __future__ import annotations

import json
import ntpath
import os
import posixpath
import re
import subprocess
from collections.abc import Mapping, Sequence
from typing import Any
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from ..contract import (
    TRANSPORT_MCP,
    ArmSpec,
    NotInstalledError,
    Result,
)

_MAX_BYTES = 1024 * 1024
_MAX_ENV_BYTES = 32 * 1024
_MAX_ENV_VARS = 64
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_GENERATED_ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


class McpTransport:
    protocol = TRANSPORT_MCP

    def __init__(
        self,
        endpoints: Mapping[str, str] | None = None,
        stdio_cmds: Mapping[str, Sequence[str]] | None = None,
        token: str | None = None,
        timeout: float = 10.0,
        *,
        stdio_envs: Mapping[str, Mapping[str, str]] | None = None,
    ) -> None:
        self._endpoints = {
            key: value.strip()
            for key, value in (endpoints or {}).items()
            if value and value.strip()
        }
        # Preserve explicit empty list vs absent: empty argv means
        # "configured but not installed" (parity with CliTransport which
        # uses `is not None`). Discard only when value is None/missing.
        self._stdio_cmds = _stdio_commands(stdio_cmds)
        self._stdio_envs = _stdio_environments(
            stdio_envs, self._stdio_cmds, self._endpoints
        )
        for arm_id, argv in self._stdio_cmds.items():
            _validate_executable(argv, self._stdio_envs[arm_id])
        self.token = token
        self.timeout = timeout

    def installed(self, spec: ArmSpec) -> bool:
        if spec.id in self._endpoints:
            return True
        cmd = self._stdio_cmds.get(spec.id)
        return bool(cmd)

    def invoke(
        self, spec: ArmSpec, action: str, args: Mapping[str, Any]
    ) -> Result:
        endpoint = self._endpoints.get(spec.id)
        stdio_cmd = self._stdio_cmds.get(spec.id)
        environment = self._stdio_envs.get(spec.id, {}) if not endpoint else {}
        if not endpoint and not stdio_cmd:
            raise NotInstalledError(spec.id)
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": action, "arguments": dict(args)},
        }
        try:
            if endpoint:
                body = self._call_http(endpoint, payload)
            else:
                assert stdio_cmd is not None
                body = self._call_stdio(stdio_cmd, payload, environment)
        except Exception as exc:  # noqa: BLE001 - surface as Result, stay closed
            error = str(exc) if endpoint else _stdio_exception_text(exc, environment)
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error=error,
            )
        if not isinstance(body, dict):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=None,
                error="malformed JSON-RPC response",
            )
        if "error" in body and body["error"] is not None:
            safe_error = _redact(body.get("error"), environment)
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=safe_error,
                error=_error_text(safe_error),
            )
        result = body.get("result")
        if not isinstance(result, dict):
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=_redact(result, environment),
                error="malformed tool result",
            )
        if result.get("isError"):
            safe_result = _redact(result, environment)
            return Result(
                ok=False,
                arm_id=spec.id,
                action=action,
                output=safe_result,
                error=_result_error_text(safe_result),
            )
        return Result(
            ok=True,
            arm_id=spec.id,
            action=action,
            output=_redact(result, environment),
            error=None,
        )

    def _call_http(self, endpoint: str, payload: dict[str, Any]) -> Any:
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib_request.Request(
            endpoint, data=data, headers=headers, method="POST"
        )
        try:
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read(_MAX_BYTES + 1)
        except HTTPError as exc:
            # HTTPError subclasses URLError, so this must be caught first.
            detail = exc.read(4096).decode("utf-8", errors="replace") if hasattr(exc, "read") else str(exc)
            raise RuntimeError(f"HTTP {exc.code}: {detail[:1000]}") from exc
        except URLError as exc:
            raise RuntimeError(f"MCP endpoint unreachable: {exc}") from exc
        if len(raw) > _MAX_BYTES:
            raise RuntimeError(f"response exceeds {_MAX_BYTES} bytes")
        return json.loads(raw.decode("utf-8"))

    def _call_stdio(
        self, argv: Sequence[str], payload: dict[str, Any], configured_env: Mapping[str, str]
    ) -> Any:
        line = json.dumps(payload) + "\n"
        proc = subprocess.run(
            _resolved_stdio_argv(argv, configured_env),
            input=line,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=self.timeout,
            check=False,
            env={**_minimal_stdio_environment(), **configured_env},
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
            raise RuntimeError(detail)
        # Guard total stdout size before parsing individual lines (first JSON line
        # check alone would miss large trailing output). Reuse _MAX_BYTES.
        if len(proc.stdout.encode("utf-8")) > _MAX_BYTES:
            raise RuntimeError(f"response exceeds {_MAX_BYTES} bytes")
        for candidate in proc.stdout.splitlines():
            stripped = candidate.strip()
            if stripped.startswith("{"):
                parsed = json.loads(stripped)
                if len(stripped.encode("utf-8")) > _MAX_BYTES:
                    raise RuntimeError(f"response exceeds {_MAX_BYTES} bytes")
                return parsed
        raise RuntimeError("no JSON-RPC response")


def _mapping_items(value: Any, label: str) -> list[tuple[Any, Any]]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a mapping")
    items = list(value.items())
    seen: set[str] = set()
    for key, _ in items:
        if not isinstance(key, str) or not key or key.strip() != key or "\0" in key:
            raise ValueError(f"{label} requires nonempty string keys")
        if key in seen:
            raise ValueError(f"{label} contains duplicate keys")
        seen.add(key)
    return items


def _stdio_commands(value: Any) -> dict[str, list[str]]:
    commands: dict[str, list[str]] = {}
    for arm_id, argv in _mapping_items({} if value is None else value, "stdio_cmds"):
        # Keep the existing absent/None and explicitly empty argv contracts.
        if argv is None:
            continue
        if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)):
            raise ValueError("stdio argv must be a sequence of strings")
        if any(not isinstance(item, str) or "\0" in item for item in argv):
            raise ValueError("stdio argv must contain only NUL-free strings")
        commands[arm_id] = list(argv)
    return commands


def _stdio_environments(
    value: Any, commands: Mapping[str, Sequence[str]], endpoints: Mapping[str, str]
) -> dict[str, dict[str, str]]:
    environments = {arm_id: {} for arm_id in commands}
    for arm_id, configured in _mapping_items({} if value is None else value, "stdio_envs"):
        if arm_id not in commands or not commands[arm_id]:
            raise ValueError("stdio environment requires a matching nonempty command")
        if arm_id in endpoints:
            raise ValueError("stdio environment is ambiguous with an HTTP endpoint")
        items = _mapping_items(configured, "stdio environment")
        if len(items) > _MAX_ENV_VARS:
            raise ValueError("stdio environment exceeds variable limit")
        copied: dict[str, str] = {}
        names: set[str] = set()
        total = 0
        for name, entry in items:
            folded = name.upper()
            if not _ENV_NAME.fullmatch(name) or folded in names:
                raise ValueError("stdio environment has invalid or ambiguous names")
            if name != "PATH" and folded == "PATH":
                raise ValueError("stdio environment PATH must use its canonical name")
            if not isinstance(entry, str) or "\0" in entry:
                raise ValueError("stdio environment values must be NUL-free strings")
            try:
                total += len(name.encode("utf-8")) + len(entry.encode("utf-8")) + 2
            except UnicodeEncodeError:
                raise ValueError("stdio environment requires UTF-8 strings") from None
            if total > _MAX_ENV_BYTES:
                raise ValueError("stdio environment exceeds byte limit")
            names.add(folded)
            copied[name] = entry
        environments[arm_id] = copied
    return environments


def _validate_executable(argv: Sequence[str], environment: Mapping[str, str]) -> None:
    if not argv:
        return
    executable = argv[0]
    drive, tail = ntpath.splitdrive(executable)
    if os.name == "nt" and ":" in tail:
        raise ValueError("stdio executable must not use an alternate data stream")
    if _absolute_path(executable):
        return
    if (
        not executable or executable in {".", ".."}
        or drive or ":" in executable or "/" in executable
        or "\\" in executable or "PATH" not in environment
    ):
        raise ValueError("stdio executable must be absolute or a bare name with explicit PATH")


def _absolute_path(value: str) -> bool:
    if os.name == "nt":
        return ntpath.isabs(value) and bool(ntpath.splitdrive(value)[0])
    return posixpath.isabs(value)


def _path_key(value: str) -> str:
    if os.name == "nt":
        return ntpath.normcase(ntpath.normpath(value))
    return posixpath.normpath(value)


def _resolved_stdio_argv(
    argv: Sequence[str], environment: Mapping[str, str]
) -> list[str]:
    _validate_executable(argv, environment)
    if _absolute_path(argv[0]):
        return list(argv)
    # Resolve ourselves: on Windows CreateProcess may search using the parent
    # PATH even when a child env is supplied. Never consult ambient PATHEXT.
    names = [argv[0]]
    if os.name == "nt" and not ntpath.splitext(argv[0])[1]:
        names.extend([argv[0] + ".exe", argv[0] + ".com"])
    for directory in environment["PATH"].split(os.pathsep):
        for name in names:
            candidate = os.path.join(directory, name)
            path_module = ntpath if os.name == "nt" else posixpath
            if (
                not _absolute_path(candidate)
                or _path_key(path_module.dirname(path_module.normpath(candidate))) != _path_key(directory)
            ):
                raise RuntimeError("stdio executable escaped its explicit PATH directory")
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return [candidate, *argv[1:]]
    raise RuntimeError("stdio executable not found in explicit PATH")


def _minimal_stdio_environment() -> dict[str, str]:
    environment = dict(_GENERATED_ENV)
    if os.name == "nt":
        # Windows needs its OS directory for side-by-side assembly loading.
        # Read only this bootstrap field; never copy the parent environment.
        roots = [value for key, value in os.environ.items() if key.upper() == "SYSTEMROOT"]
        if len(roots) != 1 or "\0" in roots[0] or not _absolute_path(roots[0]):
            raise ValueError("Windows stdio requires one absolute SystemRoot bootstrap")
        environment["SystemRoot"] = roots[0]
    return environment


def _redact(value: Any, environment: Mapping[str, str]) -> Any:
    """Do not surface explicitly supplied environment values in child responses."""
    secrets = sorted(set(environment.values()) - {""}, key=len, reverse=True)
    if not secrets:
        return value

    def text(item: str) -> str:
        for secret in secrets:
            item = item.replace(secret, "[redacted]")
        return item

    # The JSON parser already limits nesting. Avoid imposing a second, lower
    # recursion limit while sanitizing an otherwise accepted response.
    root: list[Any] = [None]
    pending: list[tuple[Any, Any, Any]] = [(root, 0, value)]
    while pending:
        parent, key, item = pending.pop()
        if isinstance(item, dict):
            copied: dict[str, Any] = {}
            parent[key] = copied
            pending.extend((copied, text(name), child) for name, child in item.items())
        elif isinstance(item, (list, tuple)):
            children: list[Any] = [None] * len(item)
            parent[key] = children
            pending.extend((children, index, child) for index, child in enumerate(item))
        elif isinstance(item, str):
            parent[key] = text(item)
        elif isinstance(item, bytes):
            for secret in secrets:
                item = item.replace(secret.encode("utf-8"), b"[redacted]")
            parent[key] = item
        elif item is None or isinstance(item, (int, float, bool)):
            encoded = json.dumps(item)
            parent[key] = "[redacted]" if any(secret in encoded for secret in secrets) else item
        else:
            parent[key] = item
    return root[0]


def _stdio_exception_text(exc: Exception, environment: Mapping[str, str]) -> str:
    """Sanitize raw process-error fields before their repr/escaping is applied."""
    if isinstance(exc, subprocess.TimeoutExpired):
        safe_command = _redact(exc.cmd, environment)
        safe_timeout = _redact(exc.timeout, environment)
        return _redact(str(subprocess.TimeoutExpired(safe_command, safe_timeout)), environment)
    if isinstance(exc, OSError):
        if exc.errno is None and exc.strerror is None:
            return _redact(str(OSError(*_redact(list(exc.args), environment))), environment)
        safe_error = OSError(
            exc.errno,
            _redact(exc.strerror, environment) if exc.strerror is not None else None,
            _redact(exc.filename, environment) if exc.filename is not None else None,
            getattr(exc, "winerror", None),
            _redact(exc.filename2, environment) if exc.filename2 is not None else None,
        )
        return _redact(str(safe_error), environment)
    return _redact(str(exc), environment)


def _error_text(error: Any) -> str:
    if isinstance(error, dict):
        message = error.get("message")
        if message:
            return str(message)
        return json.dumps(error, sort_keys=True)
    return str(error)


def _result_error_text(result: Any) -> str:
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict) and first.get("text"):
                return str(first["text"])
    return "tool error"
