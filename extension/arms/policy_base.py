"""Shared allow/block policy shape for curated arms.

Every curated arm ships a policy module. The refusal ordering and the
message strings below are part of the arm contract (tests pin them);
arms layer their own gating (edition, credential, path containment) on
top of these three checks.
"""

from __future__ import annotations

import re
from typing import Final, Iterable, Pattern

DEFAULT_TOOL_PATTERN: Final[Pattern[str]] = re.compile(r"^[A-Za-z0-9_]+$")


class ToolPolicy:
    """Name-shape, blocklist, then allowlist refusal checks."""

    def __init__(
        self,
        allowed: Iterable[str],
        blocked: Iterable[str],
        pattern: Pattern[str] = DEFAULT_TOOL_PATTERN,
    ) -> None:
        self.allowed = frozenset(allowed)
        self.blocked = frozenset(blocked)
        self.pattern = pattern

    def refuse_reason(self, tool: str) -> str | None:
        """Return the refusal reason for *tool*, or None to proceed."""
        if not self.pattern.match(tool):
            return f"invalid tool name: {tool!r}"
        if tool in self.blocked:
            return f"tool {tool!r} is blocked"
        if tool not in self.allowed:
            return f"tool {tool!r} is not on the allowlist"
        return None
