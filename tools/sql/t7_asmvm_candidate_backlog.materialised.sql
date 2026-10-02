-- Diagnostic materialised source-identity plan; projection and bounds mirror shipped T7.
-- Materialise repeated identity and queue sets for engine plan comparison.
-- T7 compares source-derived identities with candidate finding_keys. A count
-- match alone cannot establish coverage when one source is missing and an
-- unrelated candidate offsets it. Definite eligibility drives backlog; possible
-- eligibility bounds over-queue. The two bounds can differ when cross-accept
-- chronology is unavailable. Vendor dates are observations, not accept times.
-- Both CVE producers queue one (ip,cve) pair. For the VM critical producer,
-- a pair can exclude a finding at its accept only when all source components
-- share that non-default accept event. A later vendor observation on any of
-- the three pair components identifies a source-time gap, but cannot prove
-- accept order: the VM finding itself may have been accepted still later.
-- Bound params: ?1 = run_id, ?2 = row limit.

WITH candidate_queue AS MATERIALIZED (
    SELECT c.run_id, c.check_id, c.candidate_id,
           MAX(CASE WHEN COALESCE(c.llm_verdict, 'pending') = 'pending' THEN 1 ELSE 0 END) AS pending_seen,
           MAX(CASE WHEN c.llm_verdict = 'duplicate' THEN 1 ELSE 0 END) AS duplicate_seen,
           MAX(CASE WHEN c.llm_verdict = 'confirmed' THEN 1 ELSE 0 END) AS confirmed_seen,
           MAX(CASE WHEN c.llm_verdict = 'rejected' THEN 1 ELSE 0 END) AS rejected_seen,
           MAX(CASE WHEN COALESCE(CAST(c.passed_deterministic_gate AS BOOLEAN), false) = false
                    THEN 1 ELSE 0 END) AS gate_failed_seen,
           COUNT(DISTINCT COALESCE(c.llm_verdict, 'pending')) AS verdict_variants,
           MIN(NULLIF(c.finding_key, '')) AS finding_key,
           CASE WHEN MIN(NULLIF(c.finding_key, '')) IS NULL
                     OR MAX(CASE WHEN NULLIF(TRIM(c.finding_key), '') IS NULL
                                 THEN 1 ELSE 0 END) > 0
                     OR MIN(c.finding_key) <> MAX(c.finding_key)
                THEN 0 ELSE 1 END AS key_consistent,
           MIN(c.first_seen_ts) AS first_seen_ts,
           MAX(c.last_seen_ts) AS last_seen_ts
    FROM ext_telecom_offsec_asmvm_finding_candidate c
    WHERE c.run_id = ?1
    GROUP BY c.run_id, c.check_id, c.candidate_id
),
corroborated_pair AS (
    SELECT DISTINCT a.ip, a.cve
    FROM ext_telecom_offsec_asmvm_cve_observation a
    JOIN ext_telecom_offsec_asmvm_vm_cve_observation v
      ON v.run_id = a.run_id AND v.ip = a.ip AND v.cve = a.cve
     AND CAST(v.is_open AS BOOLEAN)
    WHERE a.run_id = ?1 AND CAST(a.is_active AS BOOLEAN)
),
alert_base_ids AS MATERIALIZED (
    SELECT run_id, engagement_id, alert_id,
           MIN(NULLIF(vendor_alert_id, '')) AS min_vendor_id,
           MAX(NULLIF(vendor_alert_id, '')) AS max_vendor_id
    FROM ext_telecom_offsec_asmvm_alert
    WHERE run_id = ?1
    GROUP BY run_id, engagement_id, alert_id
),
alert_source AS MATERIALIZED (
    SELECT e.engagement_id, e.alert_id, e.ip,
           CASE WHEN a.min_vendor_id IS NOT NULL
                      AND a.min_vendor_id <> a.max_vendor_id
                THEN NULL
                WHEN a.min_vendor_id IS NOT NULL
                      AND a.min_vendor_id = a.max_vendor_id
                THEN a.min_vendor_id
                WHEN e.alert_id LIKE 'xpanse-alert-%'
                THEN SUBSTR(e.alert_id, LENGTH('xpanse-alert-') + 1)
                ELSE e.alert_id END AS vendor_alert_id,
           CASE WHEN a.min_vendor_id IS NOT NULL
                      AND a.min_vendor_id <> a.max_vendor_id
                THEN 1 ELSE 0 END AS source_identity_unknown
    FROM (SELECT DISTINCT run_id, engagement_id, alert_id, ip
          FROM ext_telecom_offsec_asmvm_alert_endpoint
          WHERE run_id = ?1 AND CAST(is_active_state AS BOOLEAN)
            AND severity IN ('High', 'Critical')) e
    LEFT JOIN alert_base_ids a
      ON a.run_id = e.run_id AND a.engagement_id = e.engagement_id
     AND a.alert_id = e.alert_id
),
alert_possible_keys AS (
    SELECT DISTINCT s.engagement_id, s.alert_id, s.ip,
           'xpanse:alert:' || a.vendor_alert_id || ':ip:' || s.ip AS source_key
    FROM alert_source s
    JOIN ext_telecom_offsec_asmvm_alert a
      ON a.run_id = ?1 AND a.engagement_id = s.engagement_id
     AND a.alert_id = s.alert_id
    WHERE s.source_identity_unknown = 1
      AND NULLIF(TRIM(a.vendor_alert_id), '') IS NOT NULL
),
asm_pair_times AS (
    SELECT ip, cve, MAX(first_observed_ts) AS latest_first_observed,
           MAX(CASE WHEN first_observed_ts IS NULL THEN 1 ELSE 0 END)
               AS time_unknown
    FROM ext_telecom_offsec_asmvm_cve_observation
    WHERE run_id = ?1 AND CAST(is_active AS BOOLEAN)
    GROUP BY ip, cve
),
vm_pair_times AS (
    SELECT ip, cve, MAX(last_found_ts) AS latest_last_found,
           MAX(CASE WHEN last_found_ts IS NULL THEN 1 ELSE 0 END)
               AS time_unknown
    FROM ext_telecom_offsec_asmvm_vm_cve_observation
    WHERE run_id = ?1 AND CAST(is_open AS BOOLEAN)
    GROUP BY ip, cve
),
finding_pair_times AS (
    SELECT finding_id, ip, cve,
           MAX(last_found_ts) AS latest_last_found,
           MAX(CASE WHEN last_found_ts IS NULL THEN 1 ELSE 0 END)
               AS time_unknown
    FROM ext_telecom_offsec_asmvm_vm_cve_finding
    WHERE run_id = ?1 AND CAST(is_open AS BOOLEAN)
    GROUP BY finding_id, ip, cve
),
paired_vm_source AS MATERIALIZED (
    SELECT cf.finding_id, cf.ip,
           MAX(a.latest_first_observed) AS latest_asm_observed,
           MAX(v.latest_last_found) AS latest_vm_observed,
           MAX(cf.latest_last_found) AS latest_vm_finding,
           MAX(a.time_unknown) AS asm_time_unknown,
           MAX(v.time_unknown) AS vm_time_unknown,
           MAX(cf.time_unknown) AS finding_time_unknown
    FROM finding_pair_times cf
    JOIN asm_pair_times a ON a.ip = cf.ip AND a.cve = cf.cve
    JOIN vm_pair_times v ON v.ip = cf.ip AND v.cve = cf.cve
    GROUP BY cf.finding_id, cf.ip
),
joint_pair AS (
    SELECT DISTINCT cf.finding_id, cf.ip, cf.accept_event_id
    FROM ext_telecom_offsec_asmvm_vm_cve_finding cf
    JOIN ext_telecom_offsec_asmvm_cve_observation a
      ON a.run_id = cf.run_id AND a.ip = cf.ip AND a.cve = cf.cve
     AND a.accept_event_id = cf.accept_event_id AND CAST(a.is_active AS BOOLEAN)
    JOIN ext_telecom_offsec_asmvm_vm_cve_observation v
      ON v.run_id = cf.run_id AND v.ip = cf.ip AND v.cve = cf.cve
     AND v.accept_event_id = cf.accept_event_id AND CAST(v.is_open AS BOOLEAN)
    WHERE cf.run_id = ?1 AND CAST(cf.is_open AS BOOLEAN)
      AND cf.accept_event_id <> '00000000-0000-0000-0000-000000000000'
),
critical_source_rows AS MATERIALIZED (
    SELECT DISTINCT f.finding_id, f.accept_event_id, f.ip,
           CASE WHEN p.finding_id IS NULL THEN 1 ELSE 0 END
                AS definite_eligible,
           CASE WHEN j.finding_id IS NULL THEN 1 ELSE 0 END
                AS possible_eligible,
           CASE WHEN p.finding_id IS NOT NULL AND j.finding_id IS NULL
                     AND f.last_found_ts IS NOT NULL
                     AND (COALESCE(p.latest_asm_observed > f.last_found_ts, false)
                          OR COALESCE(p.latest_vm_observed > f.last_found_ts, false)
                          OR COALESCE(p.latest_vm_finding > f.last_found_ts, false))
                THEN 1 ELSE 0 END
                AS later_pair_source_seen,
           CASE WHEN p.finding_id IS NOT NULL AND j.finding_id IS NULL
                     AND (f.last_found_ts IS NULL OR p.asm_time_unknown > 0
                          OR p.vm_time_unknown > 0 OR p.finding_time_unknown > 0)
                THEN 1 ELSE 0 END
                AS pair_source_time_unknown
    FROM ext_telecom_offsec_asmvm_vm_finding f
    LEFT JOIN paired_vm_source p
      ON p.finding_id = f.finding_id AND p.ip = f.ip
    LEFT JOIN joint_pair j
      ON j.finding_id = f.finding_id AND j.ip = f.ip
     AND j.accept_event_id = f.accept_event_id
    WHERE f.run_id = ?1 AND CAST(f.is_open AS BOOLEAN) AND f.severity >= 9.0
      AND EXISTS (
          SELECT 1 FROM ext_telecom_offsec_asmvm_asm_vm_surface s
          WHERE s.run_id = f.run_id AND s.ip = f.ip
            AND CAST(s.has_active_service AS BOOLEAN))
),
source_identities AS MATERIALIZED (
    SELECT 'vm.scan.critical_open_exposed' AS producer,
           'ivanti:finding:' || finding_id AS source_key,
           'vcand-' || finding_id AS required_candidate_id,
           MAX(definite_eligible) AS definite_eligible,
           MAX(possible_eligible) AS possible_eligible,
           MAX(later_pair_source_seen) AS later_pair_source_seen,
           MAX(pair_source_time_unknown) AS pair_source_time_unknown,
           NULL AS source_engagement_id, NULL AS source_alert_id,
           NULL AS source_ip, 0 AS source_identity_unknown
    FROM critical_source_rows GROUP BY finding_id
    UNION ALL
    SELECT 'asm.alert.high_active',
           CASE WHEN vendor_alert_id IS NULL THEN NULL
                ELSE 'xpanse:alert:' || vendor_alert_id || ':ip:' || ip END,
           NULL, CASE WHEN source_identity_unknown = 1 THEN 0 ELSE 1 END,
           1, 0, 0, engagement_id, alert_id, ip, source_identity_unknown
    FROM alert_source
    UNION ALL
    SELECT 'asm.inferred_cve', 'xpanse:cve:' || cve || ':ip:' || ip,
           NULL, 1, 1, 0, 0, NULL, NULL, NULL, 0 FROM corroborated_pair
    UNION ALL
    SELECT 'vm.scan.cve', 'ivanti:cve:' || cve || ':ip:' || ip,
           NULL, 1, 1, 0, 0, NULL, NULL, NULL, 0 FROM corroborated_pair
),
source_with_queue AS MATERIALIZED (
    SELECT s.*,
           CASE WHEN EXISTS (
               SELECT 1 FROM candidate_queue c
               WHERE c.check_id = s.producer AND c.key_consistent = 1
                 AND (c.finding_key = s.source_key OR
                      (s.source_identity_unknown = 1 AND EXISTS (
                          SELECT 1 FROM alert_possible_keys k
                          WHERE k.engagement_id = s.source_engagement_id
                            AND k.alert_id = s.source_alert_id
                            AND k.ip = s.source_ip
                            AND k.source_key = c.finding_key)))
                 AND (s.required_candidate_id IS NULL
                      OR c.candidate_id = s.required_candidate_id))
                THEN 1 ELSE 0 END AS queued,
           CASE WHEN s.source_identity_unknown = 1 THEN
                CASE WHEN NOT EXISTS (
                    SELECT 1 FROM alert_possible_keys k
                    WHERE k.engagement_id = s.source_engagement_id
                      AND k.alert_id = s.source_alert_id AND k.ip = s.source_ip
                      AND NOT EXISTS (
                          SELECT 1 FROM candidate_queue c
                          WHERE c.check_id = s.producer AND c.key_consistent = 1
                            AND c.finding_key = k.source_key))
                THEN 1 ELSE 0 END
                ELSE CASE WHEN EXISTS (
                    SELECT 1 FROM candidate_queue c
                    WHERE c.check_id = s.producer AND c.key_consistent = 1
                      AND c.finding_key = s.source_key
                      AND (s.required_candidate_id IS NULL
                           OR c.candidate_id = s.required_candidate_id))
                THEN 1 ELSE 0 END END AS definitely_queued
    FROM source_identities s
),
known_candidate_support AS (
    SELECT c.check_id AS producer, COUNT(*) AS possibly_supported_candidates
    FROM candidate_queue c
    WHERE c.key_consistent = 1 AND EXISTS (
        SELECT 1 FROM source_identities s
        WHERE s.producer = c.check_id AND s.possible_eligible = 1
          AND (c.finding_key = s.source_key OR
               (s.source_identity_unknown = 1 AND EXISTS (
                   SELECT 1 FROM alert_possible_keys k
                   WHERE k.engagement_id = s.source_engagement_id
                     AND k.alert_id = s.source_alert_id AND k.ip = s.source_ip
                     AND k.source_key = c.finding_key)))
          AND (s.required_candidate_id IS NULL
               OR c.candidate_id = s.required_candidate_id))
    GROUP BY c.check_id
),
source_totals AS MATERIALIZED (
    SELECT producer,
           SUM(definite_eligible) AS eligible_rows,
           SUM(possible_eligible) AS possible_eligible_rows,
           SUM(CASE WHEN definite_eligible = 1 AND queued = 0 THEN 1 ELSE 0 END)
               AS backlog,
           SUM(CASE WHEN possible_eligible = 1 AND definitely_queued = 0
                    THEN 1 ELSE 0 END)
               AS possible_backlog,
           SUM(CASE WHEN definite_eligible = 1 AND definitely_queued = 1
                    THEN 1 ELSE 0 END)
               AS definitely_supported_queue,
           SUM(CASE WHEN possible_eligible = 1 AND queued = 1 THEN 1 ELSE 0 END)
               AS possibly_supported_queue,
           SUM(later_pair_source_seen) AS later_pair_source_seen,
           SUM(pair_source_time_unknown) AS pair_source_time_unknown,
           SUM(source_identity_unknown) AS source_identity_unknown
    FROM source_with_queue GROUP BY producer
),
queue_totals AS MATERIALIZED (
    SELECT check_id AS producer, COUNT(*) AS queued,
           SUM(pending_seen) AS pending_seen,
           SUM(duplicate_seen) AS duplicate_seen,
           SUM(confirmed_seen) AS confirmed_seen,
           SUM(rejected_seen) AS rejected_seen,
           SUM(gate_failed_seen) AS gate_failed_seen,
           SUM(CASE WHEN verdict_variants > 1 THEN 1 ELSE 0 END)
               AS multi_state_candidates,
           SUM(CASE WHEN key_consistent = 0 THEN 1 ELSE 0 END)
               AS queue_identity_unknown,
           MIN(first_seen_ts) AS oldest_seen,
           MAX(last_seen_ts) AS newest_seen
    FROM candidate_queue GROUP BY check_id
),
eligible AS (
    SELECT p.producer, ?1 AS run_id,
           COALESCE(s.eligible_rows, 0) AS eligible_rows,
           COALESCE(s.possible_eligible_rows, 0) AS possible_eligible_rows,
           COALESCE(s.backlog, 0) AS backlog,
           COALESCE(s.possible_backlog, 0) AS possible_backlog,
           COALESCE(s.definitely_supported_queue, 0) AS definitely_supported_queue,
           COALESCE(s.possibly_supported_queue, 0) AS possibly_supported_queue,
           COALESCE(k.possibly_supported_candidates, 0)
               AS possibly_supported_candidates,
           COALESCE(s.later_pair_source_seen, 0) AS later_pair_source_seen,
           COALESCE(s.pair_source_time_unknown, 0) AS pair_source_time_unknown,
           COALESCE(s.source_identity_unknown, 0) AS source_identity_unknown,
           COALESCE(q.queued, 0) AS queued,
           COALESCE(q.pending_seen, 0) AS pending_seen,
           COALESCE(q.duplicate_seen, 0) AS duplicate_seen,
           COALESCE(q.confirmed_seen, 0) AS confirmed_seen,
           COALESCE(q.rejected_seen, 0) AS rejected_seen,
           COALESCE(q.gate_failed_seen, 0) AS gate_failed_seen,
           COALESCE(q.multi_state_candidates, 0) AS multi_state_candidates,
           COALESCE(q.queue_identity_unknown, 0) AS queue_identity_unknown,
           q.oldest_seen, q.newest_seen
    FROM (SELECT 'vm.scan.critical_open_exposed' AS producer
          UNION ALL SELECT 'asm.alert.high_active'
          UNION ALL SELECT 'asm.inferred_cve'
          UNION ALL SELECT 'vm.scan.cve') p
    LEFT JOIN source_totals s ON s.producer = p.producer
    LEFT JOIN queue_totals q ON q.producer = p.producer
    LEFT JOIN known_candidate_support k ON k.producer = p.producer
),
bounds AS (
    SELECT e.*,
           CASE WHEN e.possibly_supported_queue < e.possibly_supported_candidates
                THEN e.possibly_supported_queue
                ELSE e.possibly_supported_candidates END AS known_possible_support,
           CASE WHEN e.backlog > e.queue_identity_unknown
                THEN e.backlog - e.queue_identity_unknown ELSE 0 END
                AS definite_backlog
    FROM eligible e
),
assessed AS (
    SELECT b.*,
           -- Count at most one known candidate per source and one source per
           -- known candidate. Unknown-key rows use only the remaining source
           -- capacity; possible_backlog is not unused capacity.
           CASE WHEN b.queued > b.known_possible_support +
                     CASE WHEN b.queue_identity_unknown <
                                   b.possible_eligible_rows - b.known_possible_support
                          THEN b.queue_identity_unknown
                          ELSE b.possible_eligible_rows - b.known_possible_support END
                THEN b.queued - b.known_possible_support -
                     CASE WHEN b.queue_identity_unknown <
                                   b.possible_eligible_rows - b.known_possible_support
                          THEN b.queue_identity_unknown
                          ELSE b.possible_eligible_rows - b.known_possible_support END
                ELSE 0 END AS definite_over_queued
    FROM bounds b
)
SELECT
    'asmvm:queue:' || e.producer AS finding_key,
    'Cumulative accepted-source candidate coverage for ' || e.producer AS title,
    CAST(e.eligible_rows AS BIGINT) AS affected_count,
    CAST(e.definite_backlog AS BIGINT) AS exposure_estimate,
    'queue:' || e.producer AS record_locator,
    'eligible=' || CAST(e.eligible_rows AS VARCHAR) ||
    '; queued=' || CAST(e.queued AS VARCHAR) ||
    '; backlog=' || CAST(e.definite_backlog AS VARCHAR) ||
    '; over_queued=' || CAST(e.definite_over_queued AS VARCHAR) ||
    '; possible_eligible=' || CAST(e.possible_eligible_rows AS VARCHAR) ||
    '; possible_backlog=' || CAST(e.possible_backlog AS VARCHAR) ||
    '; possible_over_queued=' || CAST(e.queued - e.definitely_supported_queue AS VARCHAR) ||
    '; uncertain_sources=' || CAST(e.possible_eligible_rows - e.eligible_rows AS VARCHAR) ||
    '; later_pair_source_seen=' || CAST(e.later_pair_source_seen AS VARCHAR) ||
    '; pair_source_time_unknown=' || CAST(e.pair_source_time_unknown AS VARCHAR) ||
    '; queue_identity_unknown=' || CAST(e.queue_identity_unknown AS VARCHAR) ||
    '; source_identity_unknown=' || CAST(e.source_identity_unknown AS VARCHAR) ||
    '; pending_seen=' || CAST(e.pending_seen AS VARCHAR) ||
    '; duplicate_seen=' || CAST(e.duplicate_seen AS VARCHAR) ||
    '; confirmed_seen=' || CAST(e.confirmed_seen AS VARCHAR) ||
    '; rejected_seen=' || CAST(e.rejected_seen AS VARCHAR) ||
    '; gate_failed_seen=' || CAST(e.gate_failed_seen AS VARCHAR) ||
    '; multi_state_candidates=' || CAST(e.multi_state_candidates AS VARCHAR) ||
    '; oldest_seen=' || COALESCE(SUBSTR(CAST(e.oldest_seen AS VARCHAR), 1, 19), '') ||
    '; newest_seen=' || COALESCE(SUBSTR(CAST(e.newest_seen AS VARCHAR), 1, 19), '') AS details,
    e.run_id AS run_id,
    CASE WHEN e.definite_over_queued > 0 THEN 34
         WHEN e.definite_backlog > 1000 THEN 34
         WHEN e.definite_backlog > 0 OR e.possible_eligible_rows > e.eligible_rows
           OR e.queued > e.definitely_supported_queue
           OR e.queue_identity_unknown > 0
           OR e.source_identity_unknown > 0 THEN 26
         ELSE 20 END AS risk_score
FROM assessed e
WHERE e.possible_eligible_rows > 0 OR e.queued > 0
ORDER BY risk_score DESC, exposure_estimate DESC, finding_key
LIMIT ?2;
