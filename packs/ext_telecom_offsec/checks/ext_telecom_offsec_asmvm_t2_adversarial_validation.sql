-- ext_telecom_offsec_asmvm_t2_adversarial_validation.sql - T2 (adversarial
-- validation, finder != validator). Flags evidence bundles that never went
-- through an adversarial re-verification pass, so unverified findings cannot
-- ship. Bound params: ?1 = run_id, ?2 = row limit.
--
-- Reads this pack's ASM/VM evidence ledger. An unknown re-verification state
-- is an unresolved control gap and is labelled unknown in the details.
-- Booleans are CAST explicitly so the SQL stays valid under the CSV loopback
-- runner, which types an all-true/all-false column as INTEGER.

SELECT
    'asmvm:bundle:' || e.bundle_id AS finding_key,
    'Evidence bundle missing adversarial re-verification: ' || e.bundle_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    e.bundle_id || ' / ' || COALESCE(e.project_id, '') || ' / ' || COALESCE(e.source_lane, '') AS record_locator,
    'has_report=' || CASE WHEN COALESCE(CAST(e.has_report AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; has_receipt=' || CASE WHEN COALESCE(CAST(e.has_receipt AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; has_live_fire=' || CASE WHEN COALESCE(CAST(e.has_live_fire AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; has_adversarial_reverify=' || CASE WHEN e.has_adversarial_reverify IS NULL THEN 'unknown'
                                        WHEN CAST(e.has_adversarial_reverify AS BOOLEAN) THEN 'true'
                                        ELSE 'false' END ||
    '; is_sandboxed=' || CASE WHEN COALESCE(CAST(e.is_sandboxed AS BOOLEAN), false) THEN 'true' ELSE 'false' END AS details,
    e.run_id AS run_id,
    35 AS risk_score
FROM ext_telecom_offsec_asmvm_evidence_bundle e
WHERE e.run_id = ?1
  AND COALESCE(CAST(e.has_adversarial_reverify AS BOOLEAN), false) = false
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
