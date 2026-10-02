-- 004_ext_telecom_offsec_asmvm_vm_finding_distinct.sql - sanctioned distinct VM
-- finding/CVE read path for the ext_telecom_offsec_asmvm namespace.
--
-- The pack base table ext_telecom_offsec_asmvm_vm_cve_finding is already collapsed
-- to its primary-key grain by the projector before insert. Raw CVE arrays
-- can repeat a finding/CVE pair. This migration documents
-- the distinct (run_id, ip, cve, finding_id) grain for downstream pack readers.
--
-- The pack relation carrying this grain is
-- ext_telecom_offsec_asmvm_vm_cve_finding (not ext_telecom_offsec_asmvm_vm_finding, whose
-- scanner-finding grain has no cve column). The projection deliberately keeps
-- only the business identity columns, so accept-event provenance cannot turn
-- one finding/CVE triple into several analytical observations.

CREATE VIEW IF NOT EXISTS ext_telecom_offsec_asmvm_vm_finding_distinct AS
SELECT DISTINCT
    run_id,
    ip,
    cve,
    finding_id
FROM ext_telecom_offsec_asmvm_vm_cve_finding;
