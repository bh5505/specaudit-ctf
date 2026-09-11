-- 000_ext_telecom_bootstrap.sql - idempotent ext_telecom bootstrap.
--
-- Creates the pack-owned audit-period reference table. T1-T7 checks scope
-- themselves to the ambient run with `<alias>.run_id = ?1`; this table carries
-- the declared period bounds the CTF evidence generator and engagement configs
-- reference. Purely additive and idempotent (CREATE TABLE IF NOT EXISTS).

CREATE TABLE IF NOT EXISTS ext_telecom_audit_period (
    audit_year   INTEGER PRIMARY KEY,
    period_start DATE NOT NULL,
    period_end   DATE NOT NULL,
    is_open      BOOLEAN DEFAULT true
);
