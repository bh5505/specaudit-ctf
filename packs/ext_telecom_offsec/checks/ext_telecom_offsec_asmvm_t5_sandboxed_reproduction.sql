-- ext_telecom_offsec_asmvm_t5_sandboxed_reproduction.sql - T5 (sandboxed
-- reproduction + read-only verifier). Flags live-fire bundles that ran outside
-- isolated compute or have no recorded isolation state. Unknown is a control
-- gap, not proof that the reproduction ran outside a sandbox.
-- Bound params: ?1 = run_id, ?2 = row limit.
-- Booleans are CAST explicitly so the SQL stays valid under the CSV loopback
-- runner, which types an all-true/all-false column as INTEGER.
-- Reserved-column contract: the established eight columns are followed by the
-- optional ninth safety_json object. See specaudit-ctf/tools/ctf_run_checks.py
-- for runner parsing semantics. Booleans come from typed bundle flags; lane is
-- emitted only for the CAP-PARAM reproduction_lanes allowlist.

SELECT
    'asmvm:' || CASE WHEN e.is_sandboxed IS NULL
                    THEN 'live-fire-sandbox-unknown:'
                    ELSE 'live-fire-unsandboxed:' END ||
        CAST(LENGTH(e.bundle_id) AS VARCHAR) || ':' || e.bundle_id || ':' ||
        CAST(LENGTH(e.accept_event_id) AS VARCHAR) || ':' || e.accept_event_id AS finding_key,
    CASE WHEN e.is_sandboxed IS NULL
         THEN 'Live-fire sandbox isolation unverified: '
         ELSE 'Live-fire reproduction outside sandbox: ' END || e.bundle_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    e.bundle_id || ' / ' || e.accept_event_id || ' / ' ||
        COALESCE(e.project_id, '') || ' / ' || COALESCE(e.source_lane, '') AS record_locator,
    'has_live_fire=' || CASE WHEN COALESCE(CAST(e.has_live_fire AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; is_sandboxed=' || CASE WHEN e.is_sandboxed IS NULL THEN 'unknown'
                             WHEN CAST(e.is_sandboxed AS BOOLEAN) THEN 'true'
                             ELSE 'false' END ||
    '; has_report=' || CASE WHEN COALESCE(CAST(e.has_report AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; has_receipt=' || CASE WHEN COALESCE(CAST(e.has_receipt AS BOOLEAN), false) THEN 'true' ELSE 'false' END AS details,
    e.run_id AS run_id,
    60 AS risk_score
    , '{"live_fire":' ||
    CASE WHEN COALESCE(CAST(e.has_live_fire AS BOOLEAN), false) = true
         THEN 'true' ELSE 'false' END ||
    ',"sandboxed":' ||
    CASE WHEN e.is_sandboxed IS NULL THEN 'null'
         WHEN CAST(e.is_sandboxed AS BOOLEAN) THEN 'true'
         ELSE 'false' END ||
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
  AND (e.is_sandboxed IS NULL OR CAST(e.is_sandboxed AS BOOLEAN) = false)
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
