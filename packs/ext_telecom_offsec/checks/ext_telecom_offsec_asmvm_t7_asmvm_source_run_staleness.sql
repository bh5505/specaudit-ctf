-- ext_telecom_offsec_asmvm_t7_asmvm_source_run_staleness.sql - T7 (resumable,
-- batched, additive runs), currency half.
--
-- ext_telecom_offsec_asmvm_t7_resumable_runs catches interrupted ledger rows. For an
-- ASM/VM engagement the more dangerous failure is a *stale but 'completed'*
-- source run: the scanner reports a completed run whose last checkpoint is older
-- than the source's freshness SLA, so coverage silently rots while every
-- downstream artefact still looks green and every T1 exposure statement is
-- computed against an out-of-date view of the estate.
--
-- Freshness arithmetic is done at INGEST time and carried on the ledger
-- (reference_ts, freshness_sla_days, stale_days): check SQL has to stay portable
-- across the DuckDB engine and the SQLite loopback runner, where date_diff()
-- exists but julianday() does not, and vice versa. A missing checkpoint is
-- reported as unknown, never as zero days stale - a 0 would read as a compliant
-- same-day refresh.
--
-- Tables: ext_telecom_offsec_asmvm_check_run.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'asmvm:stale-run:' || cr.source_run_id          AS finding_key,
    'Stale source run beyond freshness SLA: ' || cr.source_run_id AS title,
    1                                               AS affected_count,
    CAST(COALESCE(cr.population_size, 0) AS BIGINT) AS exposure_estimate,
    cr.source_run_id || ' / ' || COALESCE(cr.accept_event_id, '') || ' / ' ||
        COALESCE(cr.status, '')                     AS record_locator,
    'status=' || COALESCE(cr.status, '') ||
    '; source_system=' || COALESCE(cr.source_system, '') ||
    '; started_at=' || COALESCE(SUBSTR(CAST(cr.started_at AS VARCHAR), 1, 19), '') ||
    '; finished_at=' || COALESCE(SUBSTR(CAST(cr.finished_at AS VARCHAR), 1, 19), '') ||
    '; checkpoint_ts=' || COALESCE(SUBSTR(CAST(cr.checkpoint_ts AS VARCHAR), 1, 19), 'unknown') ||
    '; reference_ts=' || COALESCE(SUBSTR(CAST(cr.reference_ts AS VARCHAR), 1, 19), 'unknown') ||
    '; stale_days=' || CASE WHEN cr.stale_days IS NULL THEN 'unknown'
                            ELSE CAST(cr.stale_days AS VARCHAR) END ||
    '; freshness_sla_days=' || CAST(COALESCE(cr.freshness_sla_days, 14) AS VARCHAR) ||
    '; population_size=' || CAST(COALESCE(cr.population_size, 0) AS VARCHAR) ||
    '; pages_completed=' || CAST(COALESCE(cr.pages_completed, 0) AS VARCHAR) AS details,
    cr.run_id                                       AS run_id,
    CASE WHEN cr.checkpoint_ts IS NULL THEN 45
         WHEN cr.stale_days > 2 * COALESCE(cr.freshness_sla_days, 14) THEN 38
         ELSE 30 END                                AS risk_score
FROM ext_telecom_offsec_asmvm_check_run cr
WHERE cr.run_id = ?1
  AND (
    COALESCE(cr.status, '') <> 'completed'
    OR cr.finished_at IS NULL
    OR cr.checkpoint_ts IS NULL
    OR COALESCE(cr.stale_days, -1) > COALESCE(cr.freshness_sla_days, 14)
  )
ORDER BY risk_score DESC, cr.checkpoint_ts, finding_key
LIMIT ?2;
