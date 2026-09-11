-- ext_telecom_t7_resumable_runs.sql - method T7 (resumable, batched, additive
-- runs). Flags check-run ledger rows that are interrupted (status
-- 'interrupted') or internally inconsistent (no finish time and a checkpoint
-- older than the start), so coverage stays checkpointed and resumable.
-- source_run_id identifies the source ledger row; run_id is the engine scope.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'run:' || cr.source_run_id || ':' || cr.accept_event_id AS finding_key,
    'Interrupted or non-resumable check run: ' || cr.source_run_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    cr.source_run_id || ' / ' || cr.accept_event_id || ' / ' || COALESCE(cr.status, '') AS record_locator,
    'status=' || COALESCE(cr.status, '') ||
    '; started_at=' || COALESCE(CAST(cr.started_at AS VARCHAR), '') ||
    '; finished_at=' || COALESCE(CAST(cr.finished_at AS VARCHAR), '') ||
    '; checkpoint_ts=' || COALESCE(CAST(cr.checkpoint_ts AS VARCHAR), '') ||
    '; pages_completed=' || COALESCE(CAST(cr.pages_completed AS VARCHAR), '') AS details,
    cr.run_id AS run_id,
    25 AS risk_score
FROM gw_silver_ext_telecom_check_run cr
WHERE cr.run_id = ?1
  AND (
    cr.status = 'interrupted'
    OR (cr.finished_at IS NULL AND cr.checkpoint_ts < cr.started_at)
  )
ORDER BY finding_key
LIMIT ?2;
