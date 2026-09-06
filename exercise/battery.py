"""The rehearsal battery: the runner's default multi-arm composition.

The preset spans the catalog's exercise domains (2026-09-06 consult:
composition is dual-gated, never capability-limited):

- ``checkov.scan`` — offline IaC scan whose root is contained BY
  CONSTRUCTION to the packaged synthetic range (no arming decision
  exists to make);
- ``semgrep-mcp.semgrep_scan`` — inline rule pack against planted
  fixture code, contained by ``SEMGREP_SCAN_ROOT``;
- ``attack-stix-data.technique`` — the knowledge/reasoning member: an
  exact ATT&CK technique lookup over the shipped demo bundle, R0
  local-read, contained by construction (the bundle path is the
  arm's own shipped sample — the only member that completes on a
  bare host);
- ``wapiti.scan`` — the web/DAST member against the operator's
  spawned target's HTTP lane (dual gate: ``WAPITI_DISPATCH_SCOPE``
  plus ``LAB_TARGET_HOST``);
- ``nmap.scan`` — the network member against the same host, single
  target (dual gate: ``NMAP_DISPATCH_SCOPE`` plus ``LAB_TARGET_HOST``).

Target-facing members carry a ``{target}`` placeholder that the runner
fills from the shared ``LAB_TARGET_HOST`` env (a bare host/IP; the
port lives in the member's visible template, not in runner code). The
arming scope env stays an authorization value only — the target is
never derived from it, so a subnet-shaped scope cannot become the
argument, and the arm's containment check keeps judging an
operator-named target rather than a tautology.

Skip semantics are uniform across the preset (honest designed-safe
unavailability: a skipped member degrades the run, never fails it):

- arming env unset → skip (checked first, so an unarmed host never
  interpolates or discloses a target);
- target env unset → skip;
- binary absent → skip (the arm's own "not installed" envelope);
- a member that runs and fails — including a scope/URL refusal —
  fails the run: misconfiguration is not unavailability.

zgrab2 remains a lab ``--arms`` composition (it needs a per-run
module choice the preset does not presume).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from extension.arms.attackstix.policy import demo_bundle_path

# The shared target env for target-facing members: a bare host or IP
# (no scheme, no port — the member template owns those). Containment
# stays with each arm's scope check; this env only names the target.
TARGET_ENV = "LAB_TARGET_HOST"


@dataclass(frozen=True)
class BatteryMember:
    """One preset member: the invocation plus what arms it.

    ``args`` may carry a ``{target}`` placeholder in string values;
    it is filled only when ``target_env`` is set, and only after the
    arming env check passes.
    """

    arm_id: str
    action: str
    args: dict[str, Any]
    # The environment variable that arms the member, or None for a
    # member contained by construction (nothing to arm).
    arming_env: str | None
    # The environment variable naming the target for a ``{target}``
    # template, or None for a member that takes no live target.
    target_env: str | None = None


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
    BatteryMember(
        arm_id="attack-stix-data",
        action="technique",
        args={
            "bundle": str(demo_bundle_path()),
            # Verified present in the shipped demo bundle's
            # external_references (pinned by test against the file).
            "id": "T1552",
        },
        arming_env=None,
    ),
    BatteryMember(
        arm_id="wapiti",
        action="scan",
        args={"url": "http://{target}:8080/"},
        arming_env="WAPITI_DISPATCH_SCOPE",
        target_env=TARGET_ENV,
    ),
    BatteryMember(
        arm_id="nmap",
        action="scan",
        args={"target": "{target}"},
        arming_env="NMAP_DISPATCH_SCOPE",
        target_env=TARGET_ENV,
    ),
)
