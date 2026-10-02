-- ext_telecom_offsec_asmvm_t7_asmvm_candidate_backlog.sql - T7 (resumable,
-- batched, additive runs), queue-depth half.
--
-- The candidate queue is emitted as a bounded batch. This check compares, per
-- producer, the size of the ELIGIBLE population against the number of candidates
-- that actually entered the queue. A batch that silently truncated its population
-- is a coverage hole: the run looks green, the queue looks worked, and a slice of
-- the estate was never queued at all. The eligible-vs-queued delta is what makes
-- the next run additive (resume from the cursor) instead of a re-scan.
--
-- Producer ids are ingest-time values (mapping_spec.yaml value_map on
-- ext_telecom_offsec_asmvm_finding_candidate.check_id): the ASM high-severity alert
-- queue, the ASM inferred-CVE queue, and the two VM queues. The eligible
-- population is recomputed here from silver, which is the point - it does not
-- trust the producer's own count.
--
-- Why each eligible population is a scalar subquery and not a CTE: when the two
-- CVE branches were written as one non-aggregate CTE holding a correlated EXISTS
-- (`WHERE EXISTS (... v.ip = a.ip AND v.cve = a.cve ...)`) and then joined to the
-- queue, SQLite flattened the CTE into the outer query and re-ran that EXISTS per
-- candidate row. Each branch as an uncorrelated scalar aggregate is
-- evaluated before joining and preserves row equality across both engines.
-- Pre-aggregating while leaving the correlation does not fix it; removing
-- the correlation did. DuckDB is the production engine; SQLite is the development
-- and isolation engine, and it needs to be able to run this check too.
--
-- Tables: ext_telecom_offsec_asmvm_finding_candidate, ext_telecom_offsec_asmvm_vm_finding,
-- ext_telecom_offsec_asmvm_asm_vm_surface, ext_telecom_offsec_asmvm_alert_endpoint,
-- ext_telecom_offsec_asmvm_cve_observation, ext_telecom_offsec_asmvm_vm_cve_finding.
-- Bound params: ?1 = run_id, ?2 = row limit.

WITH eligible AS (
    SELECT producer, eligible_rows FROM (
        SELECT 'vm.scan.critical_open_exposed' AS producer,
               (SELECT COUNT(*)
                FROM ext_telecom_offsec_asmvm_vm_finding f
                JOIN ext_telecom_offsec_asmvm_asm_vm_surface s
                    ON s.ip = f.ip
                   AND s.run_id = f.run_id
                WHERE f.run_id = ?1
                  AND CAST(f.is_open AS BOOLEAN)
                  AND f.severity >= 9.0
                  AND CAST(s.has_active_service AS BOOLEAN))  AS eligible_rows
        UNION ALL
        SELECT 'asm.alert.high_active',
               (SELECT COUNT(*)
                FROM ext_telecom_offsec_asmvm_alert_endpoint a
                WHERE a.run_id = ?1
                  AND CAST(a.is_active_state AS BOOLEAN)
                  AND a.severity IN ('High', 'Critical'))
        UNION ALL
        -- ASM-inferred CVEs corroborated by an open VM CVE on the same (ip, cve).
        -- Aggregated inside the branch: nothing correlated survives into the
        -- outer query.
        SELECT 'asm.inferred_cve',
               (SELECT COUNT(*)
                FROM ext_telecom_offsec_asmvm_cve_observation a
                WHERE a.run_id = ?1
                  AND CAST(a.is_active AS BOOLEAN)
                  AND EXISTS (
                        SELECT 1
                        FROM ext_telecom_offsec_asmvm_vm_cve_observation v
                        WHERE v.run_id = a.run_id
                          AND v.ip = a.ip
                          AND v.cve = a.cve
                          AND CAST(v.is_open AS BOOLEAN)))
        UNION ALL
        -- The same corroboration from the VM side.
        SELECT 'vm.scan.cve',
               (SELECT COUNT(*)
                FROM ext_telecom_offsec_asmvm_vm_cve_finding v
                WHERE v.run_id = ?1
                  AND CAST(v.is_open AS BOOLEAN)
                  AND EXISTS (
                        SELECT 1
                        FROM ext_telecom_offsec_asmvm_cve_observation a
                        WHERE a.run_id = v.run_id
                          AND a.ip = v.ip
                          AND a.cve = v.cve
                          AND CAST(a.is_active AS BOOLEAN)))
    )
    WHERE eligible_rows > 0
)
SELECT
    'asmvm:queue:' || c.check_id                    AS finding_key,
    'Candidate queue coverage / backlog for ' || c.check_id AS title,
    CAST(MAX(e.eligible_rows) AS BIGINT)            AS affected_count,
    CAST(MAX(e.eligible_rows) - COUNT(*) AS BIGINT) AS exposure_estimate,
    'queue:' || c.check_id                          AS record_locator,
    'eligible=' || CAST(MAX(e.eligible_rows) AS VARCHAR) ||
    '; queued=' || CAST(COUNT(*) AS VARCHAR) ||
    '; backlog=' || CAST(MAX(e.eligible_rows) - COUNT(*) AS VARCHAR) ||
    '; pending=' || CAST(COUNT(CASE WHEN COALESCE(c.llm_verdict, 'pending') = 'pending' THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; duplicates=' || CAST(COUNT(CASE WHEN c.llm_verdict = 'duplicate' THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; confirmed=' || CAST(COUNT(CASE WHEN c.llm_verdict = 'confirmed' THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; gate_failed=' || CAST(COUNT(CASE WHEN COALESCE(CAST(c.passed_deterministic_gate AS BOOLEAN), false) = false THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; oldest_seen=' || COALESCE(SUBSTR(CAST(MIN(c.first_seen_ts) AS VARCHAR), 1, 19), '') ||
    '; newest_seen=' || COALESCE(SUBSTR(CAST(MAX(c.last_seen_ts) AS VARCHAR), 1, 19), '') AS details,
    c.run_id                                        AS run_id,
    CASE WHEN MAX(e.eligible_rows) - COUNT(*) > 1000 THEN 34
         WHEN MAX(e.eligible_rows) - COUNT(*) > 0 THEN 26
         ELSE 20 END                                AS risk_score
FROM ext_telecom_offsec_asmvm_finding_candidate c
JOIN eligible e
    ON e.producer = c.check_id
   AND e.eligible_rows > 0
WHERE c.run_id = ?1
GROUP BY c.check_id, c.run_id
ORDER BY risk_score DESC, exposure_estimate DESC, finding_key
LIMIT ?2;
