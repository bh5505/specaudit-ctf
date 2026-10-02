-- 000_ext_telecom_offsec_asmvm_bootstrap.sql - idempotent ext_telecom_offsec_asmvm bootstrap.
--
-- Creates the pack-owned audit-period reference table. The ASM/VM checks scope
-- themselves to the ambient run with `<alias>.run_id = ?1`; this table carries
-- the declared period bounds the evidence builders and engagement configs
-- reference, and is the table an auditor reads to see which period a run claims
-- to cover. Purely additive and idempotent (CREATE TABLE IF NOT EXISTS).
--
-- Deliberately NOT seeded here: migrations own DDL, not data (the
-- seed-backdoor anti-pattern). Period rows arrive through the ingest mapping
-- (synthetic/mapping_spec.yaml) or the fixture-engagement path.

CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_audit_period (
    audit_year   INTEGER PRIMARY KEY,
    period_start DATE NOT NULL,
    period_end   DATE NOT NULL,
    is_open      BOOLEAN DEFAULT true
);
