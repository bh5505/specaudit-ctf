-- ext_telecom_offsec_aws_t5_sandboxed_reproduction.sql - T5 (sandboxed
-- reproduction + read-only verifier). Flags live-fire bundles that ran outside
-- isolated compute or have no recorded isolation state. Unknown is a control
-- gap, not proof that the reproduction ran outside a sandbox.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    CASE WHEN e.is_sandboxed IS NULL
         THEN 'live_fire_sandbox_unknown:'
         ELSE 'live_fire_unsandboxed:' END ||
        CAST(LENGTH(e.bundle_id) AS VARCHAR) || ':' || e.bundle_id || ':' ||
        CAST(LENGTH(e.accept_event_id) AS VARCHAR) || ':' || e.accept_event_id AS finding_key,
    CASE WHEN e.is_sandboxed IS NULL
         THEN 'Live-fire sandbox isolation unverified: '
         ELSE 'Live-fire reproduction outside sandbox: ' END || e.bundle_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    e.bundle_id || ' / ' || e.accept_event_id || ' / ' ||
        COALESCE(e.project_id, '') || ' / ' || COALESCE(e.source_lane, '') AS record_locator,
    'has_live_fire=' || CAST(COALESCE(e.has_live_fire, false) AS VARCHAR) ||
    '; is_sandboxed=' || CASE WHEN e.is_sandboxed IS NULL THEN 'unknown'
                             WHEN CAST(e.is_sandboxed AS BOOLEAN) THEN 'true'
                             ELSE 'false' END ||
    '; has_report=' || CAST(COALESCE(e.has_report, false) AS VARCHAR) ||
    '; has_receipt=' || CAST(COALESCE(e.has_receipt, false) AS VARCHAR) AS details,
    e.run_id AS run_id,
    60 AS risk_score
FROM ext_telecom_offsec_aws_evidence_bundle e
WHERE e.run_id = ?1
  AND CAST(e.has_live_fire AS BOOLEAN) = true
  AND (e.is_sandboxed IS NULL OR CAST(e.is_sandboxed AS BOOLEAN) = false)
ORDER BY finding_key
LIMIT ?2;
