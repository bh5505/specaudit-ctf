"""Bounded trusted-side acquisition, reader observations, and demo slices.

Acquisition binds operator-held bytes by digest inside an approved root; it
establishes no custody, origin, signing, or applicability, and the recorded
locator is not identity. Deliberately narrow: no network, no subprocess, no
clock reads -- callers supply every timestamp.
"""
from __future__ import annotations

from reader_evidence.acquisition import (
    AcquisitionError,
    AcquisitionRecord,
    DirectoryManifest,
    acquire,
    acquire_directory,
    verify_directory_unchanged,
    verify_unchanged,
)
from reader_evidence.custody import (
    CUSTODY_JOURNAL_SCHEMA,
    CUSTODY_OPERATOR_ASSERTED,
    CUSTODY_SOURCE_AUTHENTIC,
    CUSTODY_VERIFIED,
    CustodyError,
    VerificationResult,
    acquisition_digest,
    append_observation,
    journal_identity,
    observation_digest,
    record_digest,
    verify_journal,
)
from reader_evidence.data_slices import (
    DataSliceError,
    DataSliceRecord,
    check_freshness,
    detections_demo_slice,
    require_upstream_admission,
    rule_lookup,
    synthetic_rule_index,
    verify_slice_bytes,
    vulnify_demo_slice,
)
from reader_evidence.observations import (
    CUSTODY,
    EVIDENCE_CLASS,
    LIMITATIONS,
    SCHEMA,
    SCHEMA_VERSION,
    ObservationError,
    VerificationResult,
    bind_directory_observation,
    bind_reader_observation,
    directory_manifest_digest,
    observation_identity,
    verify_reader_observation,
)

__all__ = [
    "AcquisitionError", "AcquisitionRecord", "DirectoryManifest", "acquire",
    "acquire_directory", "verify_directory_unchanged", "verify_unchanged",
    "CUSTODY_JOURNAL_SCHEMA", "CUSTODY_OPERATOR_ASSERTED",
    "CUSTODY_SOURCE_AUTHENTIC", "CUSTODY_VERIFIED", "CustodyError",
    "acquisition_digest", "append_observation", "journal_identity",
    "observation_digest", "record_digest", "verify_journal",
    "DataSliceError", "DataSliceRecord", "check_freshness", "detections_demo_slice",
    "require_upstream_admission", "rule_lookup", "synthetic_rule_index",
    "verify_slice_bytes", "vulnify_demo_slice",
    "CUSTODY", "EVIDENCE_CLASS", "LIMITATIONS", "SCHEMA", "SCHEMA_VERSION",
    "ObservationError", "VerificationResult", "bind_directory_observation",
    "bind_reader_observation", "directory_manifest_digest", "observation_identity",
    "verify_reader_observation",
]
