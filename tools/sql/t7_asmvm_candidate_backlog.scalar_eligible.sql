-- tools/sql/t7_asmvm_candidate_backlog.scalar_eligible.sql
-- (scalar-aggregate form; the rewrite that actually fixed SQLite)
--
-- Same row contract and same eligible-population definition as the shipped
-- check; only the shape changes. This is the same rewrite as
-- t7_asmvm_candidate_backlog.materialised.sql (variant 1) with each branch
-- wrapped in an UNCORRELATED scalar subquery.
--
-- WHY: the shipped form puts four filtered selects, two of them containing a
-- correlated EXISTS over unindexed ingest tables (vm_cve_observation 412k rows,
-- asm_vm_surface 108k rows, vm_finding 240k rows, vm_cve_finding 446k rows),
-- into one non-aggregate CTE that the outer query joins once. DuckDB builds hash
-- joins and finishes the whole 21-check pack in 12.5 s. SQLite FLATTENS a
-- non-aggregate CTE into the outer query, so each EXISTS re-scans its table for
-- every finding_candidate row - a nested loop with no index to help it, because
-- the runner creates none (tables arrive through CREATE TABLE ... INSERT, the
-- same shape as the product's accept path). Measured on the same evidence: the
-- rest of the pack finishes in minutes, this check alone was still running after
-- 2 hours when the run was terminated.
--
-- FIX: aggregate first, join key sets instead of rows. GROUP BY makes each
-- branch non-flattenable, so SQLite has to materialise it. Variant 2 goes one
-- step further and hides each aggregate behind an uncorrelated scalar subquery:
-- SQLite evaluates an uncorrelated scalar subquery once and treats the value as
-- a constant, so the plan no longer depends on the planner choosing to index the
-- materialised CTE.
--
-- EQUIVALENCE ARGUMENT (verified cell-for-cell against the shipped SQL on DuckDB
-- with check_probe.py, and against the shipped SQL's expected 4 rows on SQLite):
--   * branch vm.scan.critical_open_exposed is an INNER JOIN count whose
--     cardinality is, over ip, vm_rows(ip) * svc_rows(ip); the shipped form and
--     this form both compute that product, so no one-row-per-ip grain assumption
--     about asm_vm_surface is needed.
--   * branches asm.inferred_cve / vm.scan.cve are semi-join counts (EXISTS), so
--     the multiplicity that matters is the outer side's only: SUM(outer_rows)
--     restricted to keys present on both sides.
--   * NULL keys: an equality join or correlated EXISTS drops NULL ip / NULL cve.
--     A GROUP BY would keep a NULL-key group, so both sides filter IS NOT NULL.
--   * branch asm.alert.high_active is a single-table count and is unchanged.
--   * COUNT(*) over an empty input returns one row with 0 and
--     COALESCE(SUM(...), 0) preserves that, so eligible still yields exactly
--     four producer rows and the UNION ALL shape is unchanged.
--   * The outer SELECT (grouping by producer/check_id, details string, risk
--     score, ORDER BY, LIMIT ?2) is copied verbatim from the shipped check.
--
-- Bound params: ?1 = run_id, ?2 = row limit.

WITH eligible AS (
    SELECT 'vm.scan.critical_open_exposed' AS producer,
           (SELECT COALESCE(SUM(k.vm_rows * k.svc_rows), 0)
            FROM (
                SELECT u.ip AS ip, u.run_id AS run_id,
                       SUM(CASE WHEN u.src = 'vm' THEN 1 ELSE 0 END)  AS vm_rows,
                       SUM(CASE WHEN u.src = 'svc' THEN 1 ELSE 0 END) AS svc_rows
                FROM (
                    SELECT f.ip AS ip, f.run_id AS run_id, 'vm' AS src
                    FROM ext_telecom_asmvm_vm_finding f
                    WHERE f.run_id = ?1
                      AND CAST(f.is_open AS BOOLEAN) AND f.severity >= 9.0
                      AND f.ip IS NOT NULL
                    UNION ALL
                    SELECT s.ip AS ip, s.run_id AS run_id, 'svc' AS src
                    FROM ext_telecom_asmvm_asm_vm_surface s
                    WHERE s.run_id = ?1
                      AND CAST(s.has_active_service AS BOOLEAN)
                      AND s.ip IS NOT NULL
                ) u
                GROUP BY u.ip, u.run_id
            ) k
            WHERE k.vm_rows > 0 AND k.svc_rows > 0)                   AS eligible_rows

    UNION ALL

    -- single-table count, no join to reorder
    SELECT 'asm.alert.high_active',
           (SELECT COUNT(*)
            FROM ext_telecom_asmvm_alert_endpoint a
            WHERE a.run_id = ?1
              AND CAST(a.is_active_state AS BOOLEAN)
              AND a.severity IN ('High', 'Critical'))                AS eligible_rows

    UNION ALL

    SELECT 'asm.inferred_cve',
           (SELECT COALESCE(SUM(k.asm_rows), 0)
            FROM (
                SELECT u.ip AS ip, u.cve AS cve, u.run_id AS run_id,
                       SUM(CASE WHEN u.src = 'asm' THEN 1 ELSE 0 END) AS asm_rows,
                       SUM(CASE WHEN u.src = 'vm' THEN 1 ELSE 0 END)  AS vm_rows
                FROM (
                    SELECT a.ip AS ip, a.cve AS cve, a.run_id AS run_id, 'asm' AS src
                    FROM ext_telecom_asmvm_cve_observation a
                    WHERE a.run_id = ?1
                      AND CAST(a.is_active AS BOOLEAN)
                      AND a.ip IS NOT NULL AND a.cve IS NOT NULL
                    UNION ALL
                    SELECT v.ip AS ip, v.cve AS cve, v.run_id AS run_id, 'vm' AS src
                    FROM ext_telecom_asmvm_vm_cve_observation v
                    WHERE v.run_id = ?1
                      AND CAST(v.is_open AS BOOLEAN)
                      AND v.ip IS NOT NULL AND v.cve IS NOT NULL
                ) u
                GROUP BY u.ip, u.cve, u.run_id
            ) k
            WHERE k.asm_rows > 0 AND k.vm_rows > 0)                   AS eligible_rows

    UNION ALL

    SELECT 'vm.scan.cve',
           (SELECT COALESCE(SUM(k.vm_rows), 0)
            FROM (
                SELECT u.ip AS ip, u.cve AS cve, u.run_id AS run_id,
                       SUM(CASE WHEN u.src = 'vm' THEN 1 ELSE 0 END)  AS vm_rows,
                       SUM(CASE WHEN u.src = 'asm' THEN 1 ELSE 0 END) AS asm_rows
                FROM (
                    SELECT v.ip AS ip, v.cve AS cve, v.run_id AS run_id, 'vm' AS src
                    FROM ext_telecom_asmvm_vm_cve_finding v
                    WHERE v.run_id = ?1
                      AND CAST(v.is_open AS BOOLEAN)
                      AND v.ip IS NOT NULL AND v.cve IS NOT NULL
                    UNION ALL
                    SELECT a.ip AS ip, a.cve AS cve, a.run_id AS run_id, 'asm' AS src
                    FROM ext_telecom_asmvm_cve_observation a
                    WHERE a.run_id = ?1
                      AND CAST(a.is_active AS BOOLEAN)
                      AND a.ip IS NOT NULL AND a.cve IS NOT NULL
                ) u
                GROUP BY u.ip, u.cve, u.run_id
            ) k
            WHERE k.vm_rows > 0 AND k.asm_rows > 0)                   AS eligible_rows
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
    '; oldest_seen=' || COALESCE(CAST(MIN(c.first_seen_ts) AS VARCHAR), '') ||
    '; newest_seen=' || COALESCE(CAST(MAX(c.last_seen_ts) AS VARCHAR), '') AS details,
    c.run_id                                        AS run_id,
    CASE WHEN MAX(e.eligible_rows) - COUNT(*) > 1000 THEN 34
         WHEN MAX(e.eligible_rows) - COUNT(*) > 0 THEN 26
         ELSE 20 END                                AS risk_score
FROM ext_telecom_asmvm_finding_candidate c
JOIN eligible e
    ON e.producer = c.check_id
   AND e.eligible_rows > 0
WHERE c.run_id = ?1
GROUP BY c.check_id, c.run_id
ORDER BY risk_score DESC, exposure_estimate DESC, finding_key
LIMIT ?2;
