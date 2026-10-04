"""Packaged fictional evidence for actual admitted in-process reader actions.

Each recipe is an exact request for the existing ``extension.dispatch`` path.
No reader is invoked here and no new admission or trust is conferred.  Paths
are resolved from this installed package, not from the caller's working tree.
"""

from __future__ import annotations

from pathlib import Path


_ROOT = Path(__file__).resolve().parent / "data" / "reader-fixtures"


def _file(name: str) -> str:
    return str((_ROOT / name).resolve(strict=True))


def recipes() -> dict[str, tuple[str, str, dict]]:
    """Return independent, fixed, fixture-backed reader dispatch requests.

    File actions keep ``synthetic_only: false`` in their normal v1 profiles:
    these particular supplied files are fictional, but arbitrary caller files
    to the same capabilities need separate custody and classification.
    """
    from extension.arms.vulnify.policy import demo_bundle_path

    return {
        "reader-security-detections": (
            "security-detections-mcp", "get_rule",
            {"index": _file("detection-rules.json"), "rule_id": "SYN-R-01"},
        ),
        "reader-agentseal": (
            "agentseal", "analyze", {"fixture": _file("agent-scenarios.json")},
        ),
        "reader-vulnify": (
            "vulnify", "lookup",
            {"bundle_path": str(demo_bundle_path()), "cve_ids": ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-9999"]},
        ),
        "reader-leonidas": (
            "leonidas", "technique",
            {"corpus": _file("cloud-techniques.json"), "technique_id": "SYN-T-01"},
        ),
        "reader-specterops-skills": (
            "specterops-skills", "skill",
            {"catalog": _file("method-skills.json"), "skill_id": "SYN-S-01"},
        ),
        "reader-detection-in-the-cloud": (
            "detection-in-the-cloud", "list_rules",
            {"playbook_dir": _file("playbooks")},
        ),
        "reader-pentestkit": (
            "pentestkit", "summary", {"ledger": _file("experiment-ledger.json")},
        ),
        "reader-collinear": (
            "collinear", "scenario",
            {"scenarios_file": _file("simulated-worlds.json"), "scenario_id": "SYN-W-01"},
        ),
        "reader-ad-pathfinder": (
            "ad-pathfinder", "list_datasources", {"export": _file("ad-paths.json")},
        ),
        "reader-gpohound": (
            "gpohound", "policy",
            {"evidence": _file("gpo-policies.json"), "policy_id": "SYN-GPO-02"},
        ),
        "reader-claude-ad": (
            "claude-ad", "list_prerequisites",
            {"method_file": _file("ad-methods.json")},
        ),
        "reader-numasec": (
            "numasec", "list_transitions",
            {"ledger": _file("finding-transitions.json"), "finding_id": "SYN-F-02"},
        ),
        "reader-rubeus": (
            "rubeus", "telemetry",
            {"telemetry_file": _file("ad-telemetry.json"), "event_id": "SYN-E-01"},
        ),
        "reader-m365pwned": (
            "m365pwned", "list_permissions",
            {"cases_file": _file("m365-consent-cases.json"), "case_id": "SYN-C-01"},
        ),
    }
