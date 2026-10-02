-- ext_telecom_offsec_asmvm_t5_sandboxed_reproduction.sql - T5 (sandboxed
-- reproduction + read-only verifier). Flags evidence bundles that ran live
-- fire outside isolated compute, violating the reachability-sandbox rule.
-- Bound params: ?1 = run_id, ?2 = row limit.
--
-- INHERITED CHECK: re-expressed from ext_telecom_cyber/checks/ext_telecom_t5_sandboxed_reproduction.sql unchanged
-- in logic, retargeted to this pack's own ledger tables (ext_telecom_offsec_asmvm_evidence_bundle). The
-- ASM/VM pack owns its evidence/candidate/rule/run ledger so it loads and runs
-- standalone; running it here keeps the process controls (adversarial
-- validation, evidence gates, dedupe, sandboxing, rule corpus, resumability)
-- enforced over the ASM/VM evidence instead of only over the AWS posture pack.
-- Booleans are CAST explicitly so the SQL stays valid under the CSV loopback
-- runner, which types an all-true/all-false column as INTEGER.
-- Reserved-column contract: the established eight columns are followed by the
-- optional ninth safety_json object. See specaudit-ctf/tools/ctf_run_checks.py
-- for runner parsing semantics. Booleans come from typed bundle flags; lane is
-- emitted only for the CAP-PARAM reproduction_lanes allowlist.

SELECT
    'asmvm:live-fire-unsandboxed:' || e.bundle_id AS finding_key,
    'Live-fire reproduction outside sandbox: ' || e.bundle_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    e.bundle_id || ' / ' || COALESCE(e.project_id, '') || ' / ' || COALESCE(e.source_lane, '') AS record_locator,
    'has_live_fire=' || CASE WHEN COALESCE(CAST(e.has_live_fire AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; is_sandboxed=' || CASE WHEN COALESCE(CAST(e.is_sandboxed AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; has_report=' || CASE WHEN COALESCE(CAST(e.has_report AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; has_receipt=' || CASE WHEN COALESCE(CAST(e.has_receipt AS BOOLEAN), false) THEN 'true' ELSE 'false' END AS details,
    e.run_id AS run_id,
    60 AS risk_score
    , '{"live_fire":' ||
    CASE WHEN COALESCE(CAST(e.has_live_fire AS BOOLEAN), false) = true
         THEN 'true' ELSE 'false' END ||
    ',"sandboxed":' ||
    CASE WHEN COALESCE(CAST(e.is_sandboxed AS BOOLEAN), false) = true
         THEN 'true' ELSE 'false' END ||
    ',"adversarial_verified":' ||
    CASE WHEN COALESCE(CAST(e.has_adversarial_reverify AS BOOLEAN), false) = true
         THEN 'true' ELSE 'false' END ||
    CASE WHEN e.source_lane IN ('credentialed_scan', 'banner_reverify_probe',
                                'live_fire_probe_udp_tcp', 'live_fire_probe_tls',
                                'live_fire_probe_generic')
         THEN ',"lane":"' || e.source_lane || '"'
         ELSE '' END || '}'                         AS safety_json
FROM ext_telecom_offsec_asmvm_evidence_bundle e
WHERE e.run_id = ?1
  AND CAST(e.has_live_fire AS BOOLEAN) = true
  AND CAST(e.is_sandboxed AS BOOLEAN) = false
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
