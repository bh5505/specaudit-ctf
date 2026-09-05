"""The rehearsal battery: the runner's default multi-arm composition.

The battery is the offline/contained pair from the campaign consult:

- ``checkov.scan`` — offline IaC scan whose root is contained BY
  CONSTRUCTION to the packaged synthetic range (no arming decision
  exists to make);
- ``semgrep-mcp.semgrep_scan`` — inline rule pack against planted
  fixture code, contained by ``SEMGREP_SCAN_ROOT``.

Target-facing arms (zgrab2/wapiti against the spawned lab target) are
NOT preset members: they need a live, operator-armed target, so they
compose through explicit ``--arms`` in the lab. The preset stays
honest on every host: a member whose arming env is unset — or whose
binary is absent — is skipped (run degrades), never failed; an
installed member that runs and fails fails the run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

BATTERY_SCHEMA = "exercise.battery.v1"


@dataclass(frozen=True)
class BatteryMember:
    """One preset member: the invocation plus what arms it."""

    arm_id: str
    action: str
    args: dict[str, Any]
    # The environment variable that arms the member, or None for a
    # member contained by construction (nothing to arm).
    arming_env: str | None


# Inline rule pack (semgrep config must be inline rules: registry and
# URL configs are refused by the arm's egress gate). Rules read the
# planted fixture violations the range contracts describe.
SEMGREP_INLINE_RULE_PACK = """\
rules:
  - id: demo-terraform-s3-public-read
    message: S3 bucket ACL grants public read access
    severity: WARNING
    languages: [terraform]
    patterns:
      - pattern: acl = "public-read"
  - id: demo-terraform-iam-wildcard-action
    message: IAM policy statement allows every action
    severity: WARNING
    languages: [terraform]
    patterns:
      - pattern: Action = "*"
"""

BATTERY_PRESET: tuple[BatteryMember, ...] = (
    BatteryMember(
        arm_id="checkov",
        action="scan",
        args={},
        arming_env=None,
    ),
    BatteryMember(
        arm_id="semgrep-mcp",
        action="semgrep_scan",
        args={"config": SEMGREP_INLINE_RULE_PACK},
        arming_env="SEMGREP_SCAN_ROOT",
    ),
)
