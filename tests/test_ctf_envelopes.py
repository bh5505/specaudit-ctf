"""Golden fixtures for capability-manifest and execution-result v1 envelopes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "extension" / "schema"
MANIFEST_SCHEMA_PATH = SCHEMA_DIR / "capability.manifest.v1.schema.json"
RESULT_SCHEMA_PATH = SCHEMA_DIR / "execution-result.v1.schema.json"
GOLDENS = Path(__file__).resolve().parent / "goldens"
MANIFESTS = GOLDENS / "capability-manifest"
RESULTS = GOLDENS / "execution-result"

MANIFEST_SCHEMA_ID = "specaudit.ctf.capability.manifest.v1"
RESULT_SCHEMA_ID = "specaudit.ctf.execution-result.v1"

VALID_MANIFESTS = (
    "complete-synthetic-readonly.json",
    "range-observe.json",
    "cleanup-required.json",
    "methodology-only.json",
    "held.json",
    "unknown-capability.json",
    "agent-wiz.list_tools.json",
)
INVALID_MANIFESTS = (
    "unknown-schema.json",
    "unknown-tier.json",
)
VALID_RESULTS = (
    "complete-synthetic-readonly.json",
    "optional-unavailable-degraded.json",
    "required-arm-error-failed.json",
    "transport-ok-unowned-failed.json",
    "cleanup-unproven-failed.json",
    "unknown-capability-failed.json",
    "unknown-tier-failed.json",
    "methodology-only-failed.json",
    "held-failed.json",
)
DIGEST_RE = r"^sha256:[0-9a-f]{64}$"


def _envelopes() -> Any:
    import extension.envelopes as envelopes

    return envelopes


def _load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _schema(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


class _Spy:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def __call__(self, manifest: Any) -> None:
        self.calls.append(manifest)


def _gate(
    path: Path,
    dispatcher: Callable[..., Any] | None = None,
    **kwargs: Any,
) -> Any:
    return _envelopes().gate_dispatch(path, dispatcher=dispatcher, **kwargs)


# --- schema files exist and lock the envelope ids ----------------------


def test_manifest_schema_file_declares_v1() -> None:
    schema = _schema(MANIFEST_SCHEMA_PATH)
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert MANIFEST_SCHEMA_ID in schema["title"]
    assert schema["properties"]["schema"]["const"] == MANIFEST_SCHEMA_ID
    assert schema["properties"]["schema_version"]["const"] == 1
    assert schema["additionalProperties"] is False


def test_result_schema_file_declares_v1() -> None:
    schema = _schema(RESULT_SCHEMA_PATH)
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert RESULT_SCHEMA_ID in schema["title"]
    description = str(schema["description"]).lower()
    assert "transport_ok" in description
    assert "parser" in description
    assert schema["properties"]["schema"]["const"] == RESULT_SCHEMA_ID
    assert schema["properties"]["schema_version"]["const"] == 1
    assert schema["properties"]["status"]["enum"] == ["complete", "degraded", "failed"]
    status_description = str(schema["properties"]["status"].get("description", "")).lower()
    assert "parser" in status_description
    assert schema["additionalProperties"] is False


def test_envelope_module_schema_constants() -> None:
    env = _envelopes()
    assert env.MANIFEST_SCHEMA_ID == MANIFEST_SCHEMA_ID
    assert env.RESULT_SCHEMA_ID == RESULT_SCHEMA_ID
    assert env.SCHEMA_VERSION == 1


# --- jsonschema vs goldens --------------------------------------------


@pytest.mark.parametrize("name", VALID_MANIFESTS)
def test_valid_manifest_goldens_match_schema(name: str) -> None:
    jsonschema.validate(
        instance=_load(MANIFESTS / name), schema=_schema(MANIFEST_SCHEMA_PATH)
    )


@pytest.mark.parametrize("name", INVALID_MANIFESTS)
def test_invalid_manifest_goldens_fail_schema(name: str) -> None:
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            instance=_load(MANIFESTS / name), schema=_schema(MANIFEST_SCHEMA_PATH)
        )


@pytest.mark.parametrize("name", VALID_RESULTS)
def test_valid_result_goldens_match_schema(name: str) -> None:
    jsonschema.validate(
        instance=_load(RESULTS / name), schema=_schema(RESULT_SCHEMA_PATH)
    )


def test_unknown_schema_result_fails_jsonschema() -> None:
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            instance=_load(RESULTS / "unknown-schema-failed.json"),
            schema=_schema(RESULT_SCHEMA_PATH),
        )


@pytest.mark.parametrize("name", VALID_MANIFESTS)
def test_capability_goldens_are_default_off_synthetic_only(name: str) -> None:
    payload = _load(MANIFESTS / name)
    assert payload["default_off"] is True
    assert payload["synthetic_only"] is True
    assert "*" not in payload["authorized_scope"]
    assert "0.0.0.0/0" not in payload["authorized_scope"]
    assert "::/0" not in payload["authorized_scope"]


# --- parse + roundtrip ------------------------------------------------


@pytest.mark.parametrize("name", VALID_MANIFESTS)
def test_parse_manifest_roundtrip(name: str) -> None:
    payload = _load(MANIFESTS / name)
    parsed = _envelopes().parse_capability_manifest(payload)
    assert parsed.schema_ok is True
    assert parsed.manifest is not None
    assert parsed.manifest.to_dict() == payload


@pytest.mark.parametrize("name", VALID_RESULTS)
def test_parse_result_roundtrip_payload_fields(name: str) -> None:
    payload = _load(RESULTS / name)
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.schema_ok is True
    assert parsed.result is not None
    assert parsed.result.to_dict() == payload
    assert parsed.status == payload["status"]


# --- required scenario goldens ----------------------------------------


def test_complete_synthetic_readonly_success() -> None:
    env = _envelopes()
    manifest = env.parse_capability_manifest(
        MANIFESTS / "complete-synthetic-readonly.json"
    )
    result = env.parse_execution_result(
        RESULTS / "complete-synthetic-readonly.json"
    )
    assert manifest.schema_ok is True
    assert manifest.dispatch_allowed is False
    assert "default-off" in manifest.reasons
    enabled = env.parse_capability_manifest(
        MANIFESTS / "complete-synthetic-readonly.json", enabled=True
    )
    assert enabled.dispatch_allowed is True
    assert manifest.manifest is not None
    assert manifest.manifest.capability_id == "fixture.local-read"
    assert manifest.manifest.safety_class == "R0"
    assert manifest.manifest.side_effects == ("local-read",)
    assert result.status == "complete"
    assert result.schema_ok is True
    assert result.result is not None
    assert result.result.transport_ok is True
    assert result.result.artifacts
    digest = result.result.artifacts[0].digest
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
    assert digest[7:] == digest[7:].lower()
    assert "attempt_id" not in result.result.to_dict()


def test_optional_unavailable_arm_is_degraded() -> None:
    parsed = _envelopes().parse_execution_result(
        RESULTS / "optional-unavailable-degraded.json"
    )
    assert parsed.status == "degraded"
    assert parsed.schema_ok is True
    assert parsed.result is not None
    assert "fixture.optional-probe" in parsed.result.coverage.skipped
    assert "fixture.optional-probe" not in parsed.result.coverage.required
    assert env_reason(parsed, "optional-limitation")
    assert parsed.result.to_dict()["status"] != "complete"


def test_required_arm_error_is_failed() -> None:
    parsed = _envelopes().parse_execution_result(
        RESULTS / "required-arm-error-failed.json"
    )
    assert parsed.status == "failed"
    assert parsed.result is not None
    assert "fixture.required-scan" in parsed.result.coverage.failed
    assert "fixture.required-scan" in parsed.result.coverage.required
    assert env_reason(parsed, "required-step-failed")


def test_transport_ok_unowned_artifact_is_failed() -> None:
    parsed = _envelopes().parse_execution_result(
        RESULTS / "transport-ok-unowned-failed.json"
    )
    assert parsed.status == "failed"
    assert parsed.result is not None
    assert parsed.result.transport_ok is True
    assert parsed.result.artifacts == ()
    assert parsed.result.coverage.complete == ("fixture.local-read",)
    assert env_reason(parsed, "unowned-evidence")


def test_claimed_complete_with_unowned_artifact_is_still_failed() -> None:
    payload = _load(RESULTS / "transport-ok-unowned-failed.json")
    payload["status"] = "complete"
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "failed"
    assert env_reason(parsed, "unowned-evidence")


def test_cleanup_required_without_proof_is_failed() -> None:
    parsed = _envelopes().parse_execution_result(
        RESULTS / "cleanup-unproven-failed.json"
    )
    assert parsed.status == "failed"
    assert parsed.result is not None
    assert parsed.result.cleanup.required is True
    assert parsed.result.cleanup.proof_digest is None
    assert parsed.result.cleanup.residual is True
    assert env_reason(parsed, "cleanup-unproven")


def test_claimed_complete_without_cleanup_proof_is_still_failed() -> None:
    payload = _load(RESULTS / "cleanup-unproven-failed.json")
    payload["status"] = "complete"
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "failed"
    assert env_reason(parsed, "cleanup-unproven")


def env_reason(parsed: Any, code: str) -> bool:
    return code in parsed.reasons


# --- unknown schema / capability / tier: failed + zero dispatch -------


@pytest.mark.parametrize(
    ("manifest_name", "result_name", "reason"),
    [
        ("unknown-schema.json", "unknown-schema-failed.json", "unknown-schema"),
        ("unknown-capability.json", "unknown-capability-failed.json", "unknown-capability"),
        ("unknown-tier.json", "unknown-tier-failed.json", "unknown-tier"),
    ],
)
def test_unknown_schema_capability_tier_failed_zero_dispatch(
    manifest_name: str, result_name: str, reason: str
) -> None:
    spy = _Spy()
    env = _envelopes()
    gated = env.gate_dispatch(MANIFESTS / manifest_name, dispatcher=spy)
    assert gated.dispatch_allowed is False
    assert gated.schema_ok is (reason == "unknown-capability")
    assert reason in gated.reasons
    assert spy.calls == []
    parsed = env.parse_execution_result(RESULTS / result_name)
    assert parsed.status == "failed"
    if reason != "unknown-tier":
        assert reason in parsed.reasons
    assert spy.calls == []


def test_unknown_schema_result_is_failed_before_any_invoke() -> None:
    spy = _Spy()
    parsed = _envelopes().parse_execution_result(
        RESULTS / "unknown-schema-failed.json"
    )
    assert parsed.schema_ok is False
    assert parsed.status == "failed"
    assert parsed.result is None
    assert "unknown-schema" in parsed.reasons
    assert spy.calls == []


# --- methodology-only and held: failed + zero dispatch ----------------


def test_methodology_only_failed_zero_dispatch() -> None:
    spy = _Spy()
    env = _envelopes()
    gated = env.gate_dispatch(MANIFESTS / "methodology-only.json", dispatcher=spy)
    assert gated.schema_ok is True
    assert gated.dispatch_allowed is False
    assert "methodology-only" in gated.reasons
    assert spy.calls == []
    parsed = env.parse_execution_result(RESULTS / "methodology-only-failed.json")
    assert parsed.status == "failed"
    assert "methodology-only" in parsed.reasons
    assert spy.calls == []


def test_held_failed_zero_dispatch() -> None:
    spy = _Spy()
    env = _envelopes()
    gated = env.gate_dispatch(MANIFESTS / "held.json", dispatcher=spy)
    assert gated.schema_ok is True
    assert gated.dispatch_allowed is False
    assert "held" in gated.reasons
    assert spy.calls == []
    parsed = env.parse_execution_result(RESULTS / "held-failed.json")
    assert parsed.status == "failed"
    assert spy.calls == []


def test_eligible_manifest_dispatcher_is_called() -> None:
    spy = _Spy()
    gated = _gate(
        MANIFESTS / "complete-synthetic-readonly.json",
        dispatcher=spy,
        enabled=True,
    )
    assert gated.dispatch_allowed is True
    assert len(spy.calls) == 1
    assert spy.calls[0].capability_id == "fixture.local-read"


def test_gate_dispatch_without_dispatcher_does_not_raise() -> None:
    gated = _gate(MANIFESTS / "complete-synthetic-readonly.json", enabled=True)
    assert gated.dispatch_allowed is True


# --- extra fail-closed locks ------------------------------------------


def test_blanket_authorized_scope_is_refused() -> None:
    payload = _load(MANIFESTS / "complete-synthetic-readonly.json")
    payload["authorized_scope"] = ["*"]
    spy = _Spy()
    parsed = _envelopes().gate_dispatch(payload, dispatcher=spy)
    assert parsed.dispatch_allowed is False
    assert parsed.schema_ok is False
    assert "blanket-scope" in parsed.reasons
    assert spy.calls == []


def test_noncanonical_artifact_digest_is_failed() -> None:
    payload = _load(RESULTS / "complete-synthetic-readonly.json")
    payload["artifacts"][0]["digest"] = (
        "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
    )
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "failed"
    assert parsed.schema_ok is False


def test_degraded_is_not_execution_complete() -> None:
    payload = _load(RESULTS / "optional-unavailable-degraded.json")
    payload["status"] = "complete"
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "degraded"
    assert parsed.status != "complete"


def test_malformed_json_is_failed_zero_dispatch(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not-json", encoding="utf-8")
    spy = _Spy()
    gated = _envelopes().gate_dispatch(path, dispatcher=spy)
    assert gated.dispatch_allowed is False
    assert gated.schema_ok is False
    assert spy.calls == []
    parsed = _envelopes().parse_execution_result(path)
    assert parsed.status == "failed"
    assert spy.calls == []


# --- R-P3: reserved ids + default_off deny dispatch -----------------------


def test_default_off_eligible_spy_path_does_not_dispatch() -> None:
    spy = _Spy()
    gated = _gate(MANIFESTS / "complete-synthetic-readonly.json", dispatcher=spy)
    assert gated.schema_ok is True
    assert gated.dispatch_allowed is False
    assert "default-off" in gated.reasons
    assert spy.calls == []


def test_rewritten_methodology_id_does_not_dispatch() -> None:
    payload = _load(MANIFESTS / "methodology-only.json")
    payload["kind"] = "arm"
    payload["tier"] = "research"
    spy = _Spy()
    gated = _envelopes().gate_dispatch(payload, dispatcher=spy, enabled=True)
    assert gated.schema_ok is True
    assert gated.dispatch_allowed is False
    assert "methodology-only" in gated.reasons
    assert spy.calls == []


def test_held_tier_never_dispatches_but_admitted_read_tier_does() -> None:
    """burp-mcp.list_tools is admitted now (read admission, 2026-09-03):
    the held reservation is gone and an honest manifest dispatches when
    enabled. A declared held tier still refuses - the tier rule, not a
    per-id reservation, is the enforcement."""
    env = _envelopes()
    spy = _Spy()
    payload = _load(MANIFESTS / "held.json")
    payload["kind"] = "arm"
    gated = env.gate_dispatch(payload, dispatcher=spy, enabled=True)
    assert gated.schema_ok is True
    assert gated.dispatch_allowed is False
    assert "held" in gated.reasons
    assert spy.calls == []
    rewritten = dict(payload)
    rewritten["tier"] = "research"
    rewritten["capability_id"] = "burp-mcp.list_tools"
    rewritten["tool"] = {"name": "burp-mcp", "version": "0.0.0"}
    rewritten["side_effects"] = ["local-read"]
    spy2 = _Spy()
    gated2 = env.gate_dispatch(rewritten, dispatcher=spy2, enabled=True)
    assert gated2.schema_ok is True
    assert gated2.dispatch_allowed is True
    assert len(spy2.calls) == 1  # admitted + enabled: dispatcher runs


def test_fail_closed_reason_denies_dispatch_even_when_enabled() -> None:
    payload = _load(MANIFESTS / "complete-synthetic-readonly.json")
    payload["authorized_scope"] = ["0.0.0.0/0"]
    spy = _Spy()
    gated = _envelopes().gate_dispatch(payload, dispatcher=spy, enabled=True)
    assert gated.dispatch_allowed is False
    assert "blanket-scope" in gated.reasons
    assert spy.calls == []


# --- R-P4: parser-owned complete, residual, scope, coverage, pair ---------


def test_semantic_complete_is_parser_not_json_schema() -> None:
    payload = _load(RESULTS / "complete-synthetic-readonly.json")
    payload["artifacts"] = []
    jsonschema.validate(instance=payload, schema=_schema(RESULT_SCHEMA_PATH))
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "failed"
    assert parsed.status != "complete"
    assert "unowned-evidence" in parsed.reasons


def test_transport_ok_false_does_not_prevent_complete() -> None:
    payload = _load(RESULTS / "complete-synthetic-readonly.json")
    payload["transport_ok"] = False
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "complete"
    assert parsed.result is not None
    assert parsed.result.transport_ok is False


def test_transport_ok_true_does_not_upgrade_failed() -> None:
    payload = _load(RESULTS / "required-arm-error-failed.json")
    payload["transport_ok"] = True
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "failed"
    assert parsed.result is not None
    assert parsed.result.transport_ok is True


def test_cleanup_residual_true_is_failed_even_with_proof() -> None:
    payload = _load(RESULTS / "cleanup-unproven-failed.json")
    payload["cleanup"] = {
        "required": True,
        "proof_digest": (
            "sha256:1fa61777032b52af38d63ab38b5e4024e01de821e63224baa5b4cd7d6cdaa22b"
        ),
        "residual": True,
    }
    payload["status"] = "complete"
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "failed"
    assert parsed.result is not None
    assert parsed.result.cleanup.residual is True
    assert env_reason(parsed, "cleanup-unproven")


def test_touched_outside_authorized_is_failed() -> None:
    payload = _load(RESULTS / "complete-synthetic-readonly.json")
    payload["scope"]["touched"] = ["file:///etc/passwd"]
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "failed"
    assert "scope-overflow" in parsed.reasons


def test_touched_nested_path_within_authorized_prefix_is_ok() -> None:
    payload = _load(RESULTS / "complete-synthetic-readonly.json")
    payload["scope"]["touched"] = [
        "file:///extension/range/tf_s3_public_access/input/main.tf"
    ]
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "complete"
    assert "scope-overflow" not in parsed.reasons


def test_coverage_sets_must_be_consistent() -> None:
    payload = _load(RESULTS / "complete-synthetic-readonly.json")
    payload["coverage"] = {
        "attempted": ["fixture.local-read", "fixture.optional-probe"],
        "complete": ["fixture.local-read", "fixture.optional-probe"],
        "skipped": ["fixture.optional-probe"],
        "unsupported": [],
        "failed": [],
        "required": ["fixture.local-read"],
    }
    parsed = _envelopes().parse_execution_result(payload)
    assert parsed.status == "failed"
    assert "coverage-inconsistent" in parsed.reasons


def test_accept_pair_complete_synthetic_readonly() -> None:
    env = _envelopes()
    pair = env.accept_pair(
        MANIFESTS / "complete-synthetic-readonly.json",
        RESULTS / "complete-synthetic-readonly.json",
    )
    assert pair.accepted is True
    assert pair.status == "complete"
    assert pair.manifest.dispatch_allowed is False
    assert pair.result.schema_ok is True


def test_accept_pair_optional_unavailable_is_degraded() -> None:
    pair = _envelopes().accept_pair(
        MANIFESTS / "range-observe.json",
        RESULTS / "optional-unavailable-degraded.json",
    )
    assert pair.accepted is True
    assert pair.status == "degraded"
    assert pair.status != "complete"


def test_accept_pair_capability_mismatch_is_failed() -> None:
    payload = _load(RESULTS / "complete-synthetic-readonly.json")
    payload["capability_id"] = "fixture.range-observe"
    pair = _envelopes().accept_pair(
        MANIFESTS / "complete-synthetic-readonly.json", payload
    )
    assert pair.accepted is False
    assert pair.status == "failed"
    assert "capability-mismatch" in pair.reasons


def test_accept_pair_result_cannot_relax_cleanup() -> None:
    payload = _load(RESULTS / "cleanup-unproven-failed.json")
    payload["cleanup"] = {
        "required": False,
        "proof_digest": None,
        "residual": False,
    }
    payload["status"] = "complete"
    pair = _envelopes().accept_pair(MANIFESTS / "cleanup-required.json", payload)
    assert pair.accepted is False
    assert pair.status == "failed"
    assert "cleanup-policy-mismatch" in pair.reasons


def test_accept_pair_result_cannot_expand_manifest_scope() -> None:
    payload = _load(RESULTS / "complete-synthetic-readonly.json")
    payload["scope"] = {
        "authorized": [
            "file:///extension/range/tf_s3_public_access",
            "file:///tmp",
        ],
        "touched": ["file:///tmp"],
    }
    pair = _envelopes().accept_pair(
        MANIFESTS / "complete-synthetic-readonly.json", payload
    )
    assert pair.accepted is False
    assert pair.status == "failed"
    assert "scope-overflow" in pair.reasons


def test_accept_pair_cleanup_residual_is_failed() -> None:
    pair = _envelopes().accept_pair(
        MANIFESTS / "cleanup-required.json",
        RESULTS / "cleanup-unproven-failed.json",
    )
    assert pair.status == "failed"
    assert "cleanup-unproven" in pair.reasons


def test_accept_pair_observed_side_effect_cannot_exceed_manifest() -> None:
    payload = _load(RESULTS / "complete-synthetic-readonly.json")
    payload["side_effects"] = ["local-read", "cloud-mutate"]
    payload["approval_ref"] = "approval:synthetic-local-write"
    pair = _envelopes().accept_pair(
        MANIFESTS / "complete-synthetic-readonly.json", payload
    )
    assert pair.accepted is False
    assert pair.status == "failed"
    assert "side-effect-mismatch" in pair.reasons
