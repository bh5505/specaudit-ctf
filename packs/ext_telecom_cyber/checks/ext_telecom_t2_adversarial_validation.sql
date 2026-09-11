-- ext_telecom_t2_adversarial_validation.sql - method T2 (adversarial
-- validation, finder != validator). Flags evidence bundles that never went
-- through an adversarial re-verification pass, so unverified findings cannot
-- ship. Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'bundle:' || e.bundle_id AS finding_key,
    'Evidence bundle missing adversarial re-verification: ' || e.bundle_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    e.bundle_id || ' / ' || COALESCE(e.project_id, '') || ' / ' || COALESCE(e.source_lane, '') AS record_locator,
    'has_report=' || CAST(COALESCE(e.has_report, false) AS VARCHAR) ||
    '; has_receipt=' || CAST(COALESCE(e.has_receipt, false) AS VARCHAR) ||
    '; has_live_fire=' || CAST(COALESCE(e.has_live_fire, false) AS VARCHAR) ||
    '; has_adversarial_reverify=' || CAST(COALESCE(e.has_adversarial_reverify, false) AS VARCHAR) ||
    '; is_sandboxed=' || CAST(COALESCE(e.is_sandboxed, false) AS VARCHAR) AS details,
    e.run_id AS run_id,
    35 AS risk_score
FROM gw_silver_ext_telecom_evidence_bundle e
WHERE e.run_id = ?1
  AND e.has_adversarial_reverify = false
ORDER BY finding_key
LIMIT ?2;
