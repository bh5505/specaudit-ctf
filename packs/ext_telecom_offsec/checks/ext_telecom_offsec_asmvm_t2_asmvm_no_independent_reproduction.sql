-- ext_telecom_offsec_asmvm_t2_asmvm_no_independent_reproduction.sql - T2
-- (adversarial validation), evidence-provenance half.
--
-- Every evidence bundle in an ASM/VM engagement starts life as a vendor export.
-- A bundle that has never been reproduced by an independent active lane
-- (has_live_fire = false) carries claims that rest on ONE vendor artifact: the
-- vendor's own reachability view, its own version parsing, its own dedupe. This
-- check is the evidence-provenance statement of T2 - "which of the artifacts
-- behind this engagement's findings has anyone else confirmed?" - and it is the
-- companion to ext_telecom_offsec_asmvm_t2_adversarial_validation, which asks the
-- related but different question of whether a second reviewer/model tried to
-- DISPROVE the bundle's conclusions.
--
-- Tables: ext_telecom_offsec_asmvm_evidence_bundle.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'asmvm:no-reproduction:' || b.bundle_id         AS finding_key,
    'Evidence bundle with no independent reproduction lane: ' || b.bundle_id AS title,
    1                                               AS affected_count,
    1                                               AS exposure_estimate,
    b.bundle_id || ' / ' || COALESCE(b.source_file, '') AS record_locator,
    'source_system=' || COALESCE(b.source_system, '') ||
    '; source_lane=' || COALESCE(b.source_lane, '') ||
    '; has_report=' || CASE WHEN COALESCE(CAST(b.has_report AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; has_receipt=' || CASE WHEN COALESCE(CAST(b.has_receipt AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; has_live_fire=' || CASE WHEN COALESCE(CAST(b.has_live_fire AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; has_adversarial_reverify=' || CASE WHEN COALESCE(CAST(b.has_adversarial_reverify AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; is_sandboxed=' || CASE WHEN COALESCE(CAST(b.is_sandboxed AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; validation=probe_or_credentialed_replay_required' AS details,
    b.run_id                                        AS run_id,
    45                                              AS risk_score
FROM ext_telecom_offsec_asmvm_evidence_bundle b
WHERE b.run_id = ?1
  AND COALESCE(CAST(b.has_live_fire AS BOOLEAN), false) = false
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
