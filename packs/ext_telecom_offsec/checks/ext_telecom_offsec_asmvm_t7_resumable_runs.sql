-- ext_telecom_offsec_asmvm_t7_resumable_runs.sql - T7 (resumable, batched, additive
-- runs). Flags check-run ledger rows that are interrupted (status
-- 'interrupted') or internally inconsistent (no finish time and a checkpoint
-- older than the start), so coverage stays checkpointed and resumable.
-- source_run_id identifies the source ledger row; run_id is the engine scope.
-- Bound params: ?1 = run_id, ?2 = row limit.
--
-- The ASM/VM ledger is scoped separately from AWS process evidence.
-- Booleans are CAST explicitly so the SQL stays valid under the CSV loopback
-- runner, which types an all-true/all-false column as INTEGER.

SELECT
    'asmvm:run:' || CAST(LENGTH(cr.source_run_id) AS VARCHAR) || ':' ||
        cr.source_run_id || ':' || CAST(LENGTH(cr.accept_event_id) AS VARCHAR) || ':' ||
        cr.accept_event_id AS finding_key,
    'Interrupted or non-resumable check run: ' || cr.source_run_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    cr.source_run_id || ' / ' || cr.accept_event_id || ' / ' || COALESCE(cr.status, '') AS record_locator,
    'status=' || COALESCE(cr.status, '') ||
    '; started_at=' || COALESCE(SUBSTR(CAST(cr.started_at AS VARCHAR), 1, 19), '') ||
    '; finished_at=' || COALESCE(SUBSTR(CAST(cr.finished_at AS VARCHAR), 1, 19), '') ||
    '; checkpoint_ts=' || COALESCE(SUBSTR(CAST(cr.checkpoint_ts AS VARCHAR), 1, 19), '') ||
    '; pages_completed=' || COALESCE(CAST(cr.pages_completed AS VARCHAR), '') AS details,
    cr.run_id AS run_id,
    25 AS risk_score
FROM ext_telecom_offsec_asmvm_check_run cr
WHERE cr.run_id = ?1
  AND (
    cr.status = 'interrupted'
    OR (cr.finished_at IS NULL AND cr.checkpoint_ts < cr.started_at)
  )
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
