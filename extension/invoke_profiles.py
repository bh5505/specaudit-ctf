"""Authoritative X2-PUB profiles for the bounded CLI invoke surface.

Only actions listed here may run through ``python -m extension invoke``:
in-process, read-only policy discovery (``list_tools``) plus the
scope-gated dispatch-class actions admitted since 2026-09-01 under the
honest R1 manifest recipe. Every action that spawns a subprocess,
reaches a network, spends model tokens, or mutates state still requires
its own admitted dispatch profile; anything unlisted is refused.

Capability manifests for these profiles are encoded from this registry.
A child-returned or caller-constructed document is not authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from .arms.mcp_client import MCP_CALL_TIMEOUT

PACKAGE_NAME = "specaudit-ctf"
PACKAGE_VERSION = "0.1.0"


@dataclass(frozen=True)
class InvokeProfile:
    """Result-envelope metadata for one admitted read-only action."""

    arm_id: str
    action: str
    capability_id: str
    tool_name: str
    tool_version: str
    authorized_scope: tuple[str, ...]
    touched_scope: tuple[str, ...]
    safety_class: str
    side_effects: tuple[str, ...]
    timeout_ms: int
    max_output_bytes: int
    max_tool_steps: int
    max_spend: float | int | None
    cleanup_required: bool
    approval_ref: str | None
    roe_ref: str | None
    # Support tier carried into the capability manifest. X5-PROMOTE: the
    # agent-wiz read tier is the catalog's only maintained capability.
    tier: str = "research"
    # Manifest truth carried per profile. Read profiles are static metadata
    # (default-off in the validator sense, synthetic-only by construction).
    # Dispatch profiles stay default-off (the <ARM>_DISPATCH_SCOPE gate)
    # but are NOT synthetic-only: the operator arms a real lab target.
    default_off: bool = True
    synthetic_only: bool = True


_STATIC_POLICY_ARMS = (
    "agent-wiz",
    "ai-deep-sast",
    "attack-stix-data",
    "rpz-decoder",
    "dark-moon",
    "deepsec",
    "nmap",
    "pyrit",
    "routersploit",
    "semgrep-mcp",
    "sniper",
    "vvah",
    "zgrab2",
    "security-detections-mcp",
    "agentseal",
    "vulnify",
    "leonidas",
    "specterops-skills",
    "detection-in-the-cloud",
    "pentestkit",
    "collinear",
    "ad-pathfinder",
    "gpohound",
    "claude-ad",
    "numasec",
    "rubeus",
    "m365pwned",
)


def _policy_profile(arm_id: str, tier: str = "research") -> InvokeProfile:
    capability_id = f"{arm_id}.list_tools"
    scope = (f"policy://extension/arms/{arm_id}",)
    return InvokeProfile(
        arm_id=arm_id,
        action="list_tools",
        capability_id=capability_id,
        tool_name=PACKAGE_NAME,
        tool_version=PACKAGE_VERSION,
        authorized_scope=scope,
        touched_scope=scope,
        safety_class="R0",
        side_effects=("local-read",),
        timeout_ms=30_000,
        max_output_bytes=1_048_576,
        max_tool_steps=1,
        max_spend=None,
        cleanup_required=False,
        approval_ref=None,
        roe_ref=None,
        tier=tier,
    )


def _local_read_profile(arm_id: str, action: str, tier: str = "research") -> InvokeProfile:
    """Read admission for a first-party in-process local-file lookup.

    Same grammar as the static policy arms (R0, local-read, default-off
    in the validator sense, synthetic-only by construction), scoped per
    action: the only touched surface is the caller-named local bundle
    file, validated by the arm's egress gate (existing local file,
    STIX suffix, size cap; URLs refused). There is no endpoint and no
    subprocess.
    """
    capability_id = f"{arm_id}.{action}"
    scope = (f"policy://extension/arms/{arm_id}",)
    return InvokeProfile(
        arm_id=arm_id,
        action=action,
        capability_id=capability_id,
        tool_name=PACKAGE_NAME,
        tool_version=PACKAGE_VERSION,
        authorized_scope=scope,
        touched_scope=scope,
        safety_class="R0",
        side_effects=("local-read",),
        timeout_ms=30_000,
        max_output_bytes=1_048_576,
        max_tool_steps=1,
        max_spend=None,
        cleanup_required=False,
        approval_ref=None,
        roe_ref=None,
        tier=tier,
    )


# X5-PROMOTE: agent-wiz's read tier is promoted to maintained (doc 13
# evidence gate; dossier on AuditPack issue #5). No adjacent row moves.
_POLICY_ARM_TIERS = {arm_id: "research" for arm_id in _STATIC_POLICY_ARMS}
_POLICY_ARM_TIERS["agent-wiz"] = "maintained"


def _mcp_read_profile(arm_id: str, action: str, tier: str = "research") -> InvokeProfile:
    """Read-tier admission for an MCP-backed arm action.

    Unlike the static policy arms, these dial the operator-configured
    MCP endpoint (default-off until the env names one; not synthetic
    once configured). Loopback-armed arms (burp, metasploit) stay
    local-read; remote-https arms use the dispatch-shaped builder below.
    """
    capability_id = f"{arm_id}.{action}"
    scope = (f"policy://extension/arms/{arm_id}",)
    return InvokeProfile(
        arm_id=arm_id,
        action=action,
        capability_id=capability_id,
        tool_name=PACKAGE_NAME,
        tool_version=PACKAGE_VERSION,
        authorized_scope=scope,
        touched_scope=scope,
        safety_class="R0",
        side_effects=("local-read",),
        timeout_ms=30_000,
        max_output_bytes=1_048_576,
        max_tool_steps=1,
        max_spend=None,
        cleanup_required=False,
        approval_ref=None,
        roe_ref=None,
        tier=tier,
        default_off=True,
        synthetic_only=False,
    )


# Caldera read admission (2026-09-06, emulation-listing packet): the
# eight allowlisted v2 GET views over the operator-configured
# CALDERA_ENDPOINT (general-http policy — an operator-scoped lab
# resource, typically the locally-run first-party server per
# lab/install-caldera.sh; CALDERA_API_KEY is the server-side gate).
# schedule_operation stays handler-level behind CALDERA_DISPATCH_SCOPE
# — its dispatch admission is a separate packet, unchanged here.
_CALDERA_READ_ACTIONS = (
    "abilities",
    "adversaries",
    "agents",
    "operations",
    "operations_summary",
    "operation",
    "operation_links",
    "operation_facts",
)

# Burp read admission (2026-09-04; expanded 2026-09-06 after
# re-verifying the full current tool surface from source): discovery,
# utilities, and every proxy/WebSocket/Organizer history read incl.
# the regex variants, both config exports (credential-filtered
# upstream since v1.3.0), and the Pro-gated scanner/Collaborator
# reads (a Community server simply does not list them - no edition
# gating; the arm's server-surface check refuses absent tools). The
# live-editor read stays blocked (operator UI state, not an audit
# artifact).
_BURP_READ_ACTIONS = (
    "list_tools",
    "url_encode",
    "url_decode",
    "base64_encode",
    "base64_decode",
    "generate_random_string",
    "get_proxy_http_history",
    "get_proxy_http_history_regex",
    "get_proxy_websocket_history",
    "get_proxy_websocket_history_regex",
    "get_organizer_items",
    "get_organizer_items_regex",
    "output_project_options",
    "output_user_options",
    "get_scanner_issues",
    "get_collaborator_interactions",
)


def _remote_read_profile(arm_id: str, action: str, endpoint_env: str, tier: str = "research") -> InvokeProfile:
    """Read admission for an endpoint-armed MCP arm action.

    The action is a lookup (no mutation), but it egresses to the
    operator-configured endpoint once armed (https for remote-armed
    arms; the union policy also admits the literal-loopback local
    shape, where the client never leaves loopback but the armed
    endpoint is still the operator decision), so the profile carries
    the dispatch-class grammar: R1, network-egress, default-off, and
    the endpoint env as the operator's arming/approval decision
    (operator://endpoint/<ENV>, the remote-read analog of the dispatch
    scope envs). Timeout mirrors the shared MCP_CALL_TIMEOUT the client
    applies to every call.
    """
    capability_id = f"{arm_id}.{action}"
    scope = (f"policy://extension/arms/{arm_id}",)
    return InvokeProfile(
        arm_id=arm_id,
        action=action,
        capability_id=capability_id,
        tool_name=PACKAGE_NAME,
        tool_version=PACKAGE_VERSION,
        authorized_scope=scope,
        touched_scope=scope,
        safety_class="R1",
        side_effects=("network-egress",),
        timeout_ms=int(MCP_CALL_TIMEOUT * 1000),
        max_output_bytes=1_048_576,
        max_tool_steps=1,
        max_spend=None,
        cleanup_required=False,
        approval_ref=f"operator://endpoint/{endpoint_env}",
        roe_ref="doc://README#remote-read-admission",
        tier=tier,
        default_off=True,
        synthetic_only=False,
    )


# GTI read admission (2026-09-03, expanded 2026-09-06): discovery
# plus the 32 verified read-only lookups against the official gti-mcp
# tool inventory (36 tools: 32 reads, 4 mutating exactly blocked -
# the collection create/update family and the upload-and-share
# analyse_file).
_GTI_READ_ACTIONS = (
    "list_tools",
    "search_iocs",
    "get_hunting_ruleset",
    "get_entities_related_to_a_hunting_ruleset",
    "get_domain_report",
    "get_entities_related_to_a_domain",
    "get_ip_address_report",
    "get_entities_related_to_an_ip_address",
    "get_url_report",
    "get_entities_related_to_an_url",
    "get_file_report",
    "get_entities_related_to_a_file",
    "get_file_behavior_report",
    "get_file_behavior_summary",
    "search_digital_threat_monitoring",
    "list_threat_profiles",
    "get_threat_profile",
    "get_threat_profile_recommendations",
    "get_threat_profile_associations_timeline",
    "get_collection_report",
    "get_entities_related_to_a_collection",
    "search_threats",
    "search_campaigns",
    "search_threat_actors",
    "search_malware_families",
    "search_software_toolkits",
    "search_threat_reports",
    "search_vulnerabilities",
    "get_collection_timeline_events",
    "get_collection_mitre_tree",
    "get_collection_feature_matches",
    "get_collections_commonalities",
    "get_collection_rules",
)

# Prowler read admission (2026-09-06): discovery plus the 43 exact-name
# read lookups pinned from the first-party OSS server source
# (prowler-cloud/prowler mcp_server/: prowler_hub catalog 10, prowler_docs
# 2, tenant prowler_ namespace 31 reads; the 18 mutating names and the
# hosted-only prowler_cloud_ namespace stay exactly blocked).
_PROWLER_READ_ACTIONS = (
    "list_tools",
    "prowler_list_attack_paths_scans",
    "prowler_list_attack_paths_queries",
    "prowler_run_attack_paths_query",
    "prowler_get_attack_paths_cartography_schema",
    "prowler_get_compliance_overview",
    "prowler_get_compliance_framework_state_details",
    "prowler_list_finding_groups",
    "prowler_get_finding_group_details",
    "prowler_list_finding_group_resources",
    "prowler_search_security_findings",
    "prowler_get_finding_details",
    "prowler_get_findings_overview",
    "prowler_list_integrations",
    "prowler_get_integration",
    "prowler_get_jira_issue_types",
    "prowler_get_mutelist",
    "prowler_list_mute_rules",
    "prowler_get_mute_rule",
    "prowler_search_providers",
    "prowler_list_resources",
    "prowler_get_resource",
    "prowler_get_resources_overview",
    "prowler_get_resource_events",
    "prowler_list_roles",
    "prowler_get_role",
    "prowler_get_user_roles",
    "prowler_list_users",
    "prowler_get_user",
    "prowler_get_current_user",
    "prowler_list_scans",
    "prowler_get_scan",
    "prowler_hub_list_checks",
    "prowler_hub_semantic_search_checks",
    "prowler_hub_get_check_details",
    "prowler_hub_get_check_code",
    "prowler_hub_get_check_fixer",
    "prowler_hub_list_compliances",
    "prowler_hub_semantic_search_compliances",
    "prowler_hub_get_compliance_details",
    "prowler_hub_list_providers",
    "prowler_hub_get_provider_services",
    "prowler_docs_search",
    "prowler_docs_get_document",
)

# Dispatch-class admission (2026-09-01 operator directive: expand the MVP
# functional CTF tools; 2026-09-02/03 continuation waves). These profiles carry
# the honest manifest truth for scope-gated live actions: safety class R1,
# declared side effects, default-off (the arm's <ARM>_DISPATCH_SCOPE gate
# refuses until the operator names the target), NOT synthetic-only. The
# arms' own refusals, audit lines, and stamps remain the enforcement point;
# the profile is the admission + metadata contract. Timeouts mirror each
# arm's policy TIMEOUT_SECONDS.
_DISPATCH_PROFILES = (
    # (arm_id, action, side_effects, timeout_ms, scope_env)
    ("nmap", "scan", ("subprocess", "network-egress"), 180_000, "NMAP_DISPATCH_SCOPE"),
    ("zaproxy", "ascan_scan", ("network-egress",), 120_000, "ZAP_DISPATCH_SCOPE"),
    ("zaproxy", "spider_scan", ("network-egress",), 120_000, "ZAP_DISPATCH_SCOPE"),
    ("zgrab2", "scan", ("subprocess", "network-egress"), 60_000, "ZGRAB2_DISPATCH_SCOPE"),
    ("wapiti", "scan", ("subprocess", "network-egress"), 600_000, "WAPITI_DISPATCH_SCOPE"),
    ("zdns", "lookup", ("subprocess", "network-egress"), 60_000, "ZDNS_DISPATCH_SCOPE"),
    # rpz-decoder (2026-09-08): ad-hoc ThreatStop RPZ zone reads. fetch
    # AXFR-transfers the operator's zone with the staged 0600 TSIG key
    # (secret rides the dig argv transiently) and writes the decoded raw
    # indicator lists to the caller-named outdir; status is a keyless
    # SOA freshness probe.
    ("rpz-decoder", "fetch", ("subprocess", "network-egress", "local-write"), 300_000, "RPZDECODER_DISPATCH_SCOPE"),
    ("rpz-decoder", "status", ("subprocess", "network-egress"), 300_000, "RPZDECODER_DISPATCH_SCOPE"),
    # Wave B (offensive/pyrit families; doc-20 dispositions): pyrit spends
    # model tokens on operator-configured endpoints (caveat + catalog note,
    # not a side-effect enum value); routersploit's run always executes the
    # module upstream (no check-only path); osmedeus scan is the documented
    # alias of run.
    ("pyrit", "scan", ("subprocess", "network-egress"), 600_000, "PYRIT_DISPATCH_SCOPE"),
    ("routersploit", "run", ("subprocess", "network-egress"), 120_000, "ROUTERSPLOIT_DISPATCH_SCOPE"),
    ("osmedeus", "scan", ("subprocess", "network-egress"), 600_000, "OSMEDEUS_DISPATCH_SCOPE"),
    # page-fetch (doc-20 disposition): the redirect caveat rides the
    # admission — only the initial URL is scope-checked; the fetcher may
    # follow redirects and render third-party subresources (egress beyond
    # the named scope, including metadata IPs reachable via redirect) and
    # may write browser state in its default location.
    ("page-fetch", "fetch", ("subprocess", "network-egress"), 60_000, "PAGE_FETCH_DISPATCH_SCOPE"),
    # commix (doc-20 standing disposition now exercised via the normal
    # recipe): active command-injection prober — no read-only mode
    # upstream, probe is the whole surface.
    ("commix", "scan", ("subprocess", "network-egress"), 600_000, "COMMIX_DISPATCH_SCOPE"),
    # dark-moon campaign/run (2026-09-05, rider on the normal recipe —
    # supersedes the doc-20 §3 "not admitted this campaign" row).
    # Launcher-shaped composite platform: the MCP gateway still launches
    # Nuclei/sqlmap/NetExec/etc. inside Docker, so the spend truth is
    # composite egress accepted by the operator-armed scope (catalog
    # caveat, not a side-effect enum value — the v1 enum is closed).
    ("dark-moon", "campaign", ("subprocess", "network-egress"), 600_000, "DARK_MOON_DISPATCH_SCOPE"),
    ("dark-moon", "run", ("subprocess", "network-egress"), 600_000, "DARK_MOON_DISPATCH_SCOPE"),
    # vuls.scan (2026-09-05, normal recipe — off-roster per doc-20 §2):
    # host vulnerability scan. Spend truth: the scope env authorizes the
    # scan ACTION, not a named host — targets come from vuls's own
    # config discovery (config.toml at the invoke cwd), so the audit
    # line records target=unknown and the operator's config decides
    # what is scanned. Upstream reads stdin only behind an explicit
    # --pipe flag the fixed argv never passes (verified 2026-09-05).
    ("vuls", "scan", ("subprocess", "network-egress"), 60_000, "VULS_DISPATCH_SCOPE"),
    # stratus-red-team warmup/detonate/revert (2026-09-05, normal
    # recipe — off-roster per doc-20 §2): cloud-side attack-technique
    # lifecycle. Spend truth: detonation acts on the OPERATOR'S OWN
    # cloud account through stratus (real resources are created,
    # modified, and cleaned up); STRATUS_DISPATCH_SCOPE binds the
    # technique ID — the armed scope must literally name the technique
    # being lifecycle-managed (equality under the same target_in_scope
    # containment as host arms; technique ids parse as hostnames).
    # Never run from the lab (no operator credentials are ever spent
    # there); the demo notes are operator-gated by construction.
    ("stratus-red-team", "warmup", ("subprocess", "network-egress"), 120_000, "STRATUS_DISPATCH_SCOPE"),
    ("stratus-red-team", "detonate", ("subprocess", "network-egress"), 120_000, "STRATUS_DISPATCH_SCOPE"),
    ("stratus-red-team", "revert", ("subprocess", "network-egress"), 120_000, "STRATUS_DISPATCH_SCOPE"),
    # semgrep-mcp (2026-09-03 CLI integration packet): the first-party
    # CLI is the primary surface; scan runs locally with an inline rule
    # pack (registry/URL configs refused, --metrics=off), so the spend
    # is subprocess only. Arming/containment is the scan root env.
    ("semgrep-mcp", "semgrep_scan", ("subprocess",), 120_000, "SEMGREP_SCAN_ROOT"),
)


def _rpz_decode_profile() -> InvokeProfile:
    """Admission for the rpz-decoder decode action (2026-09-08)."""
    scope = (f"policy://extension/arms/rpz-decoder",)
    return InvokeProfile(
        arm_id="rpz-decoder",
        action="decode",
        capability_id="rpz-decoder.decode",
        tool_name=PACKAGE_NAME,
        tool_version=PACKAGE_VERSION,
        authorized_scope=scope,
        touched_scope=scope + ("file://caller-named-dump", "file://caller-named-outdir"),
        safety_class="R1",
        side_effects=("local-read", "local-write"),
        timeout_ms=30_000,
        max_output_bytes=1_048_576,
        max_tool_steps=1,
        max_spend=None,
        cleanup_required=False,
        # Write-capable profiles are dispatch-class in the frozen
        # grammar and must name an approval: the policy anchor is the
        # containment (the caller-named outdir is validated by the
        # arm's egress gate), mirroring the checkov.scan shape.
        approval_ref="policy://extension/arms/rpz-decoder",
        roe_ref="doc://README#dispatch-doctrine",
        tier="research",
        default_off=True,
        synthetic_only=False,
    )


def _dispatch_profile(
    arm_id: str,
    action: str,
    side_effects: tuple[str, ...],
    timeout_ms: int,
    scope_env: str,
    tier: str = "research",
) -> InvokeProfile:
    capability_id = f"{arm_id}.{action}"
    scope = (f"policy://extension/arms/{arm_id}",)
    return InvokeProfile(
        arm_id=arm_id,
        action=action,
        capability_id=capability_id,
        tool_name=PACKAGE_NAME,
        tool_version=PACKAGE_VERSION,
        authorized_scope=scope,
        touched_scope=scope,
        safety_class="R1",
        side_effects=side_effects,
        timeout_ms=timeout_ms,
        max_output_bytes=1_048_576,
        max_tool_steps=1,
        max_spend=None,
        cleanup_required=False,
        # The manifest names its authorities honestly: the operator's
        # arming decision (the scope env gate) is the approval; the
        # repository's dispatch doctrine is the rules of engagement. The
        # arm's runtime scope check enforces both.
        approval_ref=f"operator://dispatch-scope/{scope_env}",
        roe_ref="doc://README#dispatch-doctrine",
        tier=tier,
        default_off=True,
        synthetic_only=False,
    )


def _checkov_scan_profile() -> InvokeProfile:
    """Admission for a subprocess scan contained BY CONSTRUCTION.

    Deliberate grammar carve-out (2026-09-05, rehearsal-battery packet;
    consult-reviewed): the arm cannot leave its containment — the scan
    root is pinned inside the packaged synthetic range and the scan is
    offline — so there is no operator arming decision to record and no
    scope env to name. Synthetic-only is the honest value (the reachable
    surface IS the synthetic range), unlike scope-gated dispatch where
    the operator arms real targets. Restricting this shape to reviewed
    capability ids is enforced by the registry grammar test; any second
    member needs its own reviewed disposition.
    """
    # Deliberately parameterless and checkov-named (review follow-up):
    # a generic builder would let a second member silently inherit this
    # carve-out shape; this one cannot.
    arm_id, action = "checkov", "scan"
    capability_id = f"{arm_id}.{action}"
    scope = (f"policy://extension/arms/{arm_id}",)
    return InvokeProfile(
        arm_id=arm_id,
        action=action,
        capability_id=capability_id,
        tool_name=PACKAGE_NAME,
        tool_version=PACKAGE_VERSION,
        authorized_scope=scope,
        touched_scope=scope,
        safety_class="R1",
        side_effects=("subprocess",),
        timeout_ms=60_000,
        max_output_bytes=1_048_576,
        max_tool_steps=1,
        max_spend=None,
        cleanup_required=False,
        # Grammar note: the frozen v1 envelope/manifest grammar requires
        # a non-empty approval_ref on every dispatch-class payload, so
        # "None" is not admissible here. The honest authority for a
        # contained-by-construction scan is the containment itself —
        # the arm's structural scan-root policy, shipped by this
        # repository — not an operator scope decision that does not
        # exist.
        approval_ref="policy://extension/arms/checkov",
        roe_ref="doc://README#dispatch-doctrine",
        default_off=True,
        synthetic_only=True,
    )


INVOKE_PROFILES = {
    profile.capability_id: profile
    for profile in (
        *(
            _policy_profile(arm_id, tier)
            for arm_id, tier in _POLICY_ARM_TIERS.items()
        ),
        *(
            _dispatch_profile(arm_id, action, side_effects, timeout_ms, scope_env)
            for arm_id, action, side_effects, timeout_ms, scope_env in _DISPATCH_PROFILES
        ),
        # checkov.scan (2026-09-05, rehearsal-battery packet): offline
        # IaC scan contained BY CONSTRUCTION to the packaged synthetic
        # range (scan root pinned inside it, --skip-download). The
        # contained-subprocess carve-out — no scope env, no operator
        # arming decision to record; see _checkov_scan_profile.
        _checkov_scan_profile(),
        # Caldera read admission (2026-09-06, emulation-listing packet):
        # the eight v2 GET views as R1 network-egress reads over the
        # operator-configured endpoint; the endpoint env is the arming
        # decision (CALDERA_API_KEY is server-side).
        *(
            _remote_read_profile("caldera", action, "CALDERA_ENDPOINT")
            for action in _CALDERA_READ_ACTIONS
        ),
        *(_mcp_read_profile("burp-mcp", action) for action in _BURP_READ_ACTIONS),
        *(
            _remote_read_profile("google-mcp-security", action, "GTI_MCP_ENDPOINT")
            for action in _GTI_READ_ACTIONS
        ),
        # Prowler read admission (2026-09-06, superseding the 2026-09-04
        # discovery-only shape): the 43 exact-name read lookups pinned
        # from the first-party OSS server source, over the explicit
        # union transport policy (operator-fronted https for self-hosted
        # remote, literal-loopback http for the first-party local
        # default) on the streamable-HTTP dialect. The 18 mutating
        # names and the hosted-only prowler_cloud_ namespace stay
        # exactly blocked; the client sends no credential.
        *(
            _remote_read_profile("prowler-mcp", action, "PROWLER_MCP_ENDPOINT")
            for action in _PROWLER_READ_ACTIONS
        ),
        # attack-stix-data read admission (2026-09-04, P4): the offline
        # ATT&CK knowledge reads over an operator-supplied local STIX
        # bundle - exact technique/software/group lookups and bounded
        # relationship reads. R0 local-read with no dispatch tier; the
        # bundle path is caller data validated by the arm's egress gate.
        *(
            _local_read_profile("attack-stix-data", action)
            for action in ("technique", "software", "group", "relationships")
        ),
        # rpz-decoder decode admission (2026-09-08): in-process AXFR
        # decode of the caller-named dump into raw IP/CIDR + domain
        # indicator lists. Honest truth: real local files are touched
        # (read dump, optionally write the lists to the caller-named
        # outdir — the arm creates that directory itself and performs
        # no other writes), so this is NOT synthetic-only and carries
        # a local-write side effect; no subprocess, no endpoint, no
        # schedule (ad-hoc by design).
        _rpz_decode_profile(),
        # security-detections-mcp read admission: local rule reads over
        # operator-supplied pinned detection indexes. R0 local-read with
        # no dispatch tier; the index path is caller data validated by
        # the arm's egress gate.
        *(
            _local_read_profile("security-detections-mcp", action)
            for action in ("list_rules", "search_rules", "get_rule")
        ),
        # agentseal read admission: offline static fixture analysis.
        # R0 local-read; fixture path is caller data.
        *(
            _local_read_profile("agentseal", action)
            for action in ("analyze", "list_scenarios")
        ),
        # vulnify read admission: bounded local vulnerability reads.
        # R0 local-read; feed path is caller data.
        *(
            _local_read_profile("vulnify", action)
            for action in ("lookup", "list_vulns")
        ),
        # leonidas read admission: declarative cloud attack corpus reads.
        # R0 local-read; corpus path is caller data.
        *(
            _local_read_profile("leonidas", action)
            for action in ("technique", "list_techniques")
        ),
        # specterops-skills read admission: curated methodology skill reads.
        # R0 local-read; catalog path is caller data.
        *(
            _local_read_profile("specterops-skills", action)
            for action in ("skill", "list_skills")
        ),
        # detection-in-the-cloud read admission: cloud detection playbook reads.
        # R0 local-read; playbook_dir is caller data.
        *(
            _local_read_profile("detection-in-the-cloud", action)
            for action in ("playbook", "list_playbooks", "list_rules")
        ),
        # pentestkit read admission: experiment accounting reads.
        # R0 local-read; ledger path is caller data.
        *(
            _local_read_profile("pentestkit", action)
            for action in ("result", "list_results", "summary")
        ),
        # collinear read admission: simulated world scenario reads.
        # R0 local-read; scenarios_file is caller data.
        *(
            _local_read_profile("collinear", action)
            for action in ("scenario", "list_scenarios", "verify")
        ),
        # ad-pathfinder read admission: imported AD path results.
        *(
            _local_read_profile("ad-pathfinder", action)
            for action in ("path", "list_paths", "list_datasources")
        ),
        # gpohound read admission: GPO policy evidence reads.
        *(
            _local_read_profile("gpohound", action)
            for action in ("policy", "list_policies", "list_links")
        ),
        # claude-ad read admission: AD methodology reads.
        *(
            _local_read_profile("claude-ad", action)
            for action in ("technique", "list_techniques", "list_prerequisites")
        ),
        # numasec read admission: finding lifecycle reads.
        *(
            _local_read_profile("numasec", action)
            for action in ("finding", "list_findings", "list_transitions")
        ),
        # rubeus read admission: deweaponized AD telemetry reads.
        *(
            _local_read_profile("rubeus", action)
            for action in ("telemetry", "list_telemetry", "list_indicators")
        ),
        # m365pwned read admission: synthetic M365 consent case reads.
        *(
            _local_read_profile("m365pwned", action)
            for action in ("case_study", "list_case_studies", "list_permissions")
        ),
        # Metasploit read admission (2026-09-04): the exploit/payload/
        # session/listener listings over the operator-run loopback SSE server
        # (GH05TCREW MetasploitMCP).
        *(
            _mcp_read_profile("metasploit-mcp", action)
            for action in (
                "list_tools",
                "list_exploits",
                "list_payloads",
                "list_active_sessions",
                "list_listeners",
            )
        ),
        # Metasploit EXECUTION admission (2026-09-05, rider on the
        # normal recipe): the handler-gated execution surfaces get their
        # registry profiles. Host-bearing tools (run_exploit,
        # run_auxiliary_module) are scope-matched by the arm's
        # RHOSTS/RHOST extraction; the scope-presence tools authorize on
        # the armed scope and audit the session/job id - the arm
        # policy's documented residual risk (send_session_command's
        # session host is not verifiable from scope presence) rides the
        # admission caveat, and operators who do not accept it leave
        # the arm unarmed. Execution happens at the operator-run msf
        # server, so the honest side effect is network-egress and the
        # timeout is the arm's MCP_CALL_TIMEOUT (single source, same
        # derivation as the read admission below).
        *(
            _dispatch_profile(
                "metasploit-mcp",
                action,
                ("network-egress",),
                int(MCP_CALL_TIMEOUT * 1000),
                "METASPLOIT_DISPATCH_SCOPE",
            )
            for action in (
                "run_exploit",
                "run_auxiliary_module",
                "run_post_module",
                "generate_payload",
                "send_session_command",
                "terminate_session",
                "start_listener",
                "stop_job",
            )
        ),
    )
}
INVOKE_CAPABILITY_IDS = frozenset(INVOKE_PROFILES)


def invoke_profile(arm_id: str, action: str) -> InvokeProfile | None:
    """Return an admitted profile without deriving trust from caller input."""

    profile = INVOKE_PROFILES.get(f"{arm_id}.{action}")
    if profile is None or profile.arm_id != arm_id or profile.action != action:
        return None
    return profile
