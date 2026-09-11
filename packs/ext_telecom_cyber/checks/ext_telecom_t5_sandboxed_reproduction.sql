-- ext_telecom_t5_sandboxed_reproduction.sql - method T5 (sandboxed
-- reproduction + read-only verifier). Flags evidence bundles that ran live
-- fire outside isolated compute, violating the reachability-sandbox rule.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'live_fire_unsandboxed:' || e.bundle_id AS finding_key,
    'Live-fire reproduction outside sandbox: ' || e.bundle_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    e.bundle_id || ' / ' || COALESCE(e.project_id, '') || ' / ' || COALESCE(e.source_lane, '') AS record_locator,
    'has_live_fire=' || CAST(COALESCE(e.has_live_fire, false) AS VARCHAR) ||
    '; is_sandboxed=' || CAST(COALESCE(e.is_sandboxed, false) AS VARCHAR) ||
    '; has_report=' || CAST(COALESCE(e.has_report, false) AS VARCHAR) ||
    '; has_receipt=' || CAST(COALESCE(e.has_receipt, false) AS VARCHAR) AS details,
    e.run_id AS run_id,
    60 AS risk_score
FROM gw_silver_ext_telecom_evidence_bundle e
WHERE e.run_id = ?1
  AND e.has_live_fire = true
  AND e.is_sandboxed = false
ORDER BY finding_key
LIMIT ?2;
