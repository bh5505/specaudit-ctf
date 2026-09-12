"""Closed input/config policy for the Ivanti (RiskSense) VM API arm.

Config is read from an Ivanti config INI (same shape as the operator's
``Ivanti_config.ini``) located at ``$IVANTI_CONFIG`` or
``./Ivanti_config.ini``/``Ivanti_config.ini`` beside the arm, with explicit
environment overrides for the live secrets so an agent can arm it without a
checked-in credential file:

  IVANTI_URL          e.g. https://platform4.risksense.com
  IVANTI_API_VER      e.g. /api/v1
  IVANTI_CLIENT_ID    e.g. 1550
  IVANTI_API_KEY      live credential (overrides [secrets] api_key)
"""

from __future__ import annotations

import configparser
import json
import os
from pathlib import Path
from typing import Any

ARM_ID = "ivanti"
# subject endpoints this arm pulls (host = assets, hostFinding = findings).
ENDPOINTS = frozenset({"host", "hostFinding", "vulnerability", "tag"})
ALLOWED_ACTIONS = frozenset({"search", "export", "filters", "fields"})
LIST_ACTIONS = frozenset({"list_tools", "tools/list"})
ARG_KEYS = frozenset({
    "endp", "filters", "projection", "size", "pages",
    "save", "extract_host", "filename", "poll", "timeout",
    "config", "verify_ssl",
})
DEFAULT_SIZE = 750
DEFAULT_CONFIG_NAMES = ("Ivanti_config.ini",)
ENV_CONFIG = "IVANTI_CONFIG"
ENV_URL = "IVANTI_URL"
ENV_API_VER = "IVANTI_API_VER"
ENV_CLIENT_ID = "IVANTI_CLIENT_ID"
ENV_API_KEY = "IVANTI_API_KEY"
ENV_SCOPE = "IVANTI_SCOPE"

_HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = str(_HERE / "Ivanti_config.ini")


class IvantiConfigError(Exception):
    """Missing/ill-formed Ivanti API configuration."""


def _read_ini(config_path: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read(config_path)
    return parser


def resolve_config_path(explicit: str | None = None) -> str | None:
    """Return a usable config path (explicit, env, or beside the arm)."""
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get(ENV_CONFIG)
    if env:
        candidates.append(env)
    candidates.append(DEFAULT_CONFIG_PATH)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def connection_config(config_path: str | None) -> dict[str, str]:
    """Resolve (url, api_ver, client_id, api_key) from config + env overrides."""
    url = os.environ.get(ENV_URL)
    api_ver = os.environ.get(ENV_API_VER)
    client_id = os.environ.get(ENV_CLIENT_ID)
    api_key = os.environ.get(ENV_API_KEY)
    if config_path:
        cfg = _read_ini(config_path)
        if cfg.has_section("platform"):
            url = url or cfg.get("platform", "url", fallback="") or None
            api_ver = api_ver or cfg.get("platform", "api_ver", fallback="") or None
            client_id = client_id or cfg.get("platform", "client_id", fallback="") or None
        if cfg.has_section("secrets"):
            api_key = api_key or cfg.get("secrets", "api_key", fallback="") or None
    missing = [name for name, val in
               (("url", url), ("api_ver", api_ver), ("client_id", client_id), ("api_key", api_key))
               if not val]
    if missing:
        raise IvantiConfigError(
            f"ivanti arm is unarmed: missing {', '.join(missing)} "
            f"(set IVANTI_CONFIG / IVANTI_URL / IVANTI_API_VER / IVANTI_CLIENT_ID / IVANTI_API_KEY)"
        )
    return {"url": str(url), "api_ver": str(api_ver),
            "client_id": str(client_id), "api_key": str(api_key)}


def parse_filters(raw: Any) -> list[dict[str, Any]] | None:
    """Accept a list of RiskSense filter dicts, or a JSON string of one."""
    if raw is None:
        return None
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        parsed = json.loads(text)
        if not isinstance(parsed, list):
            raise ValueError("filters must be a JSON array")
        return parsed
    raise ValueError("filters must be a list of filter dicts or a JSON array string")


def args_refusal(payload: dict[str, Any]) -> str | None:
    extra = sorted(set(payload) - ARG_KEYS)
    if extra:
        return f"ivanti rejects unexpected arguments: {', '.join(extra)}"
    endp = payload.get("endp")
    if not isinstance(endp, str) or endp not in ENDPOINTS:
        return f"endp must be one of {sorted(ENDPOINTS)} (got {endp!r})"
    if "filters" in payload and payload["filters"] is not None:
        try:
            parse_filters(payload["filters"])
        except (ValueError, json.JSONDecodeError) as exc:
            return f"filters invalid: {exc}"
    projection = payload.get("projection")
    if projection not in (None, "basic", "detail"):
        return f"projection must be 'basic' or 'detail' (got {projection!r})"
    for key in ("size", "pages"):
        value = payload.get(key)
        if value is not None and (not isinstance(value, int) or value < 1):
            return f"{key} must be a positive integer (got {value!r})"
    return None
