"""Default multi-arm CTF exercise preset.

The preset scans packaged IaC with Checkov and Semgrep, looks up a
technique in the shipped ATT&CK sample, and probes ``LAB_TARGET_HOST``
with Wapiti and Nmap when the operator supplies that target. A missing
binary or target skips its member; a command that runs and fails is a
failed member. Operators choose the target and are accountable for use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from extension.arms.attackstix.policy import demo_bundle_path

# The shared target env for target-facing members: a bare host or IP
# (no scheme, no port — the member template owns those).
TARGET_ENV = "LAB_TARGET_HOST"


@dataclass(frozen=True)
class BatteryMember:
    """One preset member and its optional target placeholder.

    ``args`` may carry a ``{target}`` placeholder in string values;
    it is filled when ``target_env`` is set.
    """

    arm_id: str
    action: str
    args: dict[str, Any]
    # The environment variable naming the target for a ``{target}``
    # template, or None for a member that takes no live target.
    target_env: str | None = None


# Inline rules read planted fixture violations in the packaged range.
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
    ),
    BatteryMember(
        arm_id="semgrep-mcp",
        action="semgrep_scan",
        args={"config": SEMGREP_INLINE_RULE_PACK},
    ),
    BatteryMember(
        arm_id="attack-stix-data",
        action="technique",
        args={
            "bundle": str(demo_bundle_path()),
            # Verified present in the shipped demo bundle's
            # external_references (pinned by test against the file).
            "id": "T1552",
        },
    ),
    BatteryMember(
        arm_id="wapiti",
        action="scan",
        args={"url": "http://{target}:8080/"},
        target_env=TARGET_ENV,
    ),
    BatteryMember(
        arm_id="nmap",
        action="scan",
        args={"target": "{target}"},
        target_env=TARGET_ENV,
    ),
)
