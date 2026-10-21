"""MCP tool-name syntax shared by the connected-server adapters."""

from __future__ import annotations

import re
from typing import Final, Pattern

DEFAULT_TOOL_PATTERN: Final[Pattern[str]] = re.compile(r"^[A-Za-z0-9_]+$")
