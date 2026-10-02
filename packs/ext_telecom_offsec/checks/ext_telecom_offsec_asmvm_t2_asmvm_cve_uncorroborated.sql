-- ext_telecom_offsec_asmvm_t2_asmvm_cve_uncorroborated.sql - T2 (adversarial
-- validation: the finder is not the validator).
--
-- An ASM feed publishes *externally inferred* CVEs: a banner was read, a
-- version string was matched, and a CVE list was attached. No probe reproduced
-- the vulnerability and no authenticated scan confirmed the patch level. This
-- check lists the inferred CVEs on an address the vulnerability-management feed
-- has never observed the same CVE for - i.e. claims with no second source at
-- all. These are exactly the claims that must not enter the workpaper as facts.
--
-- Grouped by CVE: the un-corroborated *claim* is the unit of validation work
-- (one probe or one credentialed scan settles the whole class).
--
-- Table: ext_telecom_offsec_asmvm_cve_observation_provenance. The landing-zone view
-- marks matching VM evidence scan_corroborated, live-probe evidence
-- probe_corroborated (observed version inside the CVE affected range), and
-- distinguishes service-banner inference from unattributed ASM inference. This
-- consumer admits only the two inference classes; banner context and a
-- probe_corroborated observation can therefore never pose as an uncorroborated
-- claim (a corroborated CVE does not fire here).
-- Bound params: ?1 = run_id, ?2 = row limit.
-- Invariant: record_locator, asm_sources and provenance_class come from the
-- same ranked observation. Banner-attributable inferences rank first so the
-- provenance-sensitive representative is visible; remaining ties are stable by
-- evidence_ref, ip and observation id.

WITH ranked AS (
    SELECT
        a.*,
        ROW_NUMBER() OVER (
            PARTITION BY a.cve
            ORDER BY CASE WHEN a.provenance_class = 'banner_asserted_inference'
                          THEN 0 ELSE 1 END,
                     a.evidence_ref, a.ip, a.cve_observation_id
        ) AS rn
    FROM ext_telecom_offsec_asmvm_cve_observation_provenance a
    WHERE a.run_id = ?1
      AND CAST(a.is_active AS BOOLEAN)
      AND a.provenance_class IN ('banner_asserted_inference',
                                 'asm_asserted_inference')
)
SELECT
    'asmvm:inferred-cve:' || a.cve                  AS finding_key,
    'Externally inferred CVE without scan corroboration: ' || a.cve AS title,
    COUNT(DISTINCT a.ip)                            AS affected_count,
    CAST(COUNT(DISTINCT a.ip) AS BIGINT)            AS exposure_estimate,
    'asm:' || MAX(CASE WHEN a.rn = 1 THEN a.evidence_ref END) ||
    ' / ip:' || MAX(CASE WHEN a.rn = 1 THEN a.ip END) AS record_locator,
    'ips=' || CAST(COUNT(DISTINCT a.ip) AS VARCHAR) ||
    '; asm_sources=' || MAX(CASE WHEN a.rn = 1 THEN a.sources END) ||
    '; max_inferred_score=' || CAST(ROUND(COALESCE(MAX(a.inferred_score), 0), 1) AS VARCHAR) ||
    '; vm_corroborated=false' ||
    '; provenance_class=' || MAX(CASE WHEN a.rn = 1 THEN a.provenance_class END) ||
    '; sample_ip=' || MAX(CASE WHEN a.rn = 1 THEN a.ip END) ||
    '; validation=live_probe_or_credentialed_scan_required' AS details,
    a.run_id                                        AS run_id,
    CASE WHEN MAX(COALESCE(a.inferred_score, 0)) >= 9.0 THEN 48
         WHEN MAX(COALESCE(a.inferred_score, 0)) >= 7.0 THEN 42
         ELSE 36 END                                AS risk_score
FROM ranked a
GROUP BY a.cve, a.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
