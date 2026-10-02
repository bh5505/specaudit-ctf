-- ext_telecom_offsec_asmvm_t5_asmvm_reproduction_queue.sql - T5 (sandboxed
-- reproduction with a read-only verifier), queue view.
--
-- Every queued candidate whose claim can only be settled by an ACTIVE lane:
-- banner re-verification for ASM-inferred CVEs, a live probe for
-- attack-surface-rule firings, a credentialed scan for scanner-reported
-- severity. This check reports the queue BY LANE, and reports inline how many
-- evidence bundles in this run carry estate live-fire evidence versus lab
-- fixture evidence. Estate live fire means has_live_fire=true and
-- is_sandboxed=false; lab fixture means is_sandboxed=true. The stable details
-- tokens make both counts available without changing the finding-row contract.
--
-- Lane assignment is CAP-PARAM: it mirrors engagement_configs/default.yaml
-- (reproduction_lanes). The lane is derived from the candidate's source system,
-- subject kind and rule name, not from free text.
--
-- Tables: ext_telecom_offsec_asmvm_candidate_subject, ext_telecom_offsec_asmvm_evidence_bundle.
-- Bound params: ?1 = run_id, ?2 = row limit.
-- Reserved-column contract: the established eight columns are followed by the
-- optional ninth safety_json object. See specaudit-ctf/tools/ctf_run_checks.py
-- for runner parsing semantics. Booleans come from typed bundle flags; lane is
-- emitted only for the CAP-PARAM reproduction_lanes allowlist.

SELECT
    'asmvm:repro-queue:' || q.check_id || ':' || q.lane AS finding_key,
    'Reproduction lane outstanding for ' || q.check_id || ' (' || q.lane || ')' AS title,
    COUNT(*)                                        AS affected_count,
    COUNT(DISTINCT q.subject_ip)                    AS exposure_estimate,
    'lane:' || q.lane || ' / producer:' || q.check_id AS record_locator,
    'candidates=' || CAST(COUNT(*) AS VARCHAR) ||
    '; ips=' || CAST(COUNT(DISTINCT q.subject_ip) AS VARCHAR) ||
    '; source_system=' || MIN(q.candidate_source_system) ||
    '; rules=' || CAST(COUNT(DISTINCT q.rule_name) AS VARCHAR) ||
    '; reproduced=false' ||
    '; reproduction_live_fire_bundle_count=' || CAST((SELECT COUNT(*)
                                                       FROM ext_telecom_offsec_asmvm_evidence_bundle b
                                                       WHERE b.run_id = ?1
                                                         AND COALESCE(CAST(b.has_live_fire AS BOOLEAN), false) = true
                                                         AND COALESCE(CAST(b.is_sandboxed AS BOOLEAN), false) = false) AS VARCHAR) ||
    '; reproduction_lab_fixture_bundle_count=' || CAST((SELECT COUNT(*)
                                                        FROM ext_telecom_offsec_asmvm_evidence_bundle b
                                                        WHERE b.run_id = ?1
                                                          AND COALESCE(CAST(b.is_sandboxed AS BOOLEAN), false) = true) AS VARCHAR) ||
    '; sample=' || COALESCE(MIN(q.detail_ref), 'unknown') AS details,
    q.run_id                                        AS run_id,
    CASE WHEN q.lane = 'credentialed_scan' THEN 44 ELSE 40 END AS risk_score
    , '{"live_fire":' ||
    CASE WHEN (SELECT COUNT(*)
               FROM ext_telecom_offsec_asmvm_evidence_bundle b
               WHERE b.run_id = ?1
                 AND COALESCE(CAST(b.has_live_fire AS BOOLEAN), false) = true) > 0
         THEN 'true' ELSE 'false' END ||
    ',"sandboxed":' ||
    CASE WHEN (SELECT COUNT(*)
               FROM ext_telecom_offsec_asmvm_evidence_bundle b
               WHERE b.run_id = ?1
                 AND COALESCE(CAST(b.is_sandboxed AS BOOLEAN), false) = true) > 0
         THEN 'true' ELSE 'false' END ||
    ',"adversarial_verified":' ||
    CASE WHEN (SELECT COUNT(*)
               FROM ext_telecom_offsec_asmvm_evidence_bundle b
               WHERE b.run_id = ?1
                 AND COALESCE(CAST(b.has_adversarial_reverify AS BOOLEAN), false) = true) > 0
         THEN 'true' ELSE 'false' END ||
    CASE WHEN q.lane IN ('credentialed_scan', 'banner_reverify_probe',
                         'live_fire_probe_udp_tcp', 'live_fire_probe_tls',
                         'live_fire_probe_generic')
         THEN ',"lane":"' || q.lane || '"'
         ELSE '' END || '}'                         AS safety_json
FROM (
    SELECT cs.check_id, cs.subject_ip, cs.candidate_source_system, cs.rule_name,
           cs.detail_ref, cs.run_id,
           CASE WHEN cs.candidate_source_system = 'ivanti_neurons'
                     THEN 'credentialed_scan'
                WHEN cs.candidate_source_system = 'cortex_xpanse'
                     AND cs.subject_kind = 'cve'
                     THEN 'banner_reverify_probe'
                WHEN cs.rule_name IN ('SnmpServer', 'IkeV1Server', 'NtpServer',
                                      'SipServer', 'NetBiosServer', 'MssqlServer',
                                      'RdpServer', 'SshServer', 'TelnetServer')
                     THEN 'live_fire_probe_udp_tcp'
                WHEN cs.rule_name LIKE '%Certificate%' OR cs.rule_name LIKE 'InsecureTLS%'
                     OR cs.rule_name LIKE '%CbcCipher%'
                     THEN 'live_fire_probe_tls'
                ELSE 'live_fire_probe_generic' END  AS lane
    FROM ext_telecom_offsec_asmvm_candidate_subject cs
    WHERE cs.run_id = ?1
) q
GROUP BY q.check_id, q.lane, q.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
