"""Offline STIX 2.1 bundle reader for the attack-stix-data arm.

Stdlib-only, in-process, fail-closed: anything unexpected in the file
raises :class:`BundleError`, which the arm converts into an evaluated
non-success. Object projections are deliberately narrow (stable field
lists, truncated descriptions) so output shape stays bounded and
comparable across bundles.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .policy import DESCRIPTION_CHARS

# Verified against the official mitreattack-python constants
# (mitreattack/constants.py, MITRE_ATTACK_ID_SOURCE_NAMES): the ATT&CK
# external id rides external_references with one of these source names.
MITRE_ATTACK_ID_SOURCE_NAMES = frozenset(
    {"mitre-attack", "mobile-attack", "mitre-mobile-attack", "mitre-ics-attack"}
)

# Relationship types this arm may return. The corpus also carries
# revocations and derived relationships; those stay off the allowlist.
ALLOWED_RELATIONSHIP_TYPES = frozenset({"uses", "subtechnique-of", "mitigates"})

_SOFTWARE_TYPES = ("tool", "malware")


class BundleError(ValueError):
    """The bundle file is not a readable STIX 2.1 bundle."""


@dataclass(frozen=True)
class Subject:
    """One lookpable object: technique, software, or group."""

    stix_id: str
    kind: str  # technique | software | group
    attack_id: str | None
    name: str
    aliases: tuple[str, ...] = field(default_factory=tuple)


def load_bundle(path: Any) -> dict[str, Any]:
    """Parse and index a local STIX 2.1 bundle file."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise BundleError(f"bundle could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BundleError(f"bundle is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("type") != "bundle":
        raise BundleError("bundle must be a STIX object with type 'bundle'")
    objects = data.get("objects")
    if not isinstance(objects, list):
        raise BundleError("bundle must carry an objects list")

    subjects: list[Subject] = []
    by_id: dict[str, dict[str, Any]] = {}
    for row in objects:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            continue
        by_id[row["id"]] = row
        subject = _subject_from(row)
        if subject is not None:
            subjects.append(subject)

    relationships = [
        row
        for row in objects
        if isinstance(row, dict)
        and row.get("type") == "relationship"
        and isinstance(row.get("relationship_type"), str)
        and row["relationship_type"] in ALLOWED_RELATIONSHIP_TYPES
        and isinstance(row.get("source_ref"), str)
        and isinstance(row.get("target_ref"), str)
    ]
    return {
        "subjects": subjects,
        "by_id": by_id,
        "relationships": relationships,
    }


def _subject_from(row: dict[str, Any]) -> Subject | None:
    stype = row.get("type")
    stix_id = row["id"]
    if stype == "attack-pattern":
        return Subject(
            stix_id=stix_id,
            kind="technique",
            attack_id=_attack_id_of(row),
            name=str(row.get("name") or ""),
            aliases=_aliases(row),
        )
    if stype in _SOFTWARE_TYPES:
        return Subject(
            stix_id=stix_id,
            kind="software",
            attack_id=None,
            name=str(row.get("name") or ""),
            aliases=_aliases(row),
        )
    if stype == "intrusion-set":
        return Subject(
            stix_id=stix_id,
            kind="group",
            attack_id=None,
            name=str(row.get("name") or ""),
            aliases=_aliases(row),
        )
    return None


def _aliases(row: dict[str, Any]) -> tuple[str, ...]:
    raw = row.get("aliases") or row.get("x_mitre_aliases") or []
    if not isinstance(raw, list):
        return ()
    return tuple(str(item) for item in raw if isinstance(item, str))


def _attack_id_of(row: dict[str, Any]) -> str | None:
    return _external_id_of(row, tuple(MITRE_ATTACK_ID_SOURCE_NAMES))


def _external_id_of(row: dict[str, Any], source: Any) -> str | None:
    refs = row.get("external_references")
    if not isinstance(refs, list):
        return None
    names = set(source) if isinstance(source, (list, tuple, frozenset, set)) else {source}
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        # isinstance first: a list/dict source_name is unhashable and
        # would raise TypeError out of set membership.
        if (
            isinstance(ref.get("source_name"), str)
            and ref["source_name"] in names
            and isinstance(ref.get("external_id"), str)
            and ref["external_id"]
        ):
            return ref["external_id"]
    return None


def find_technique(
    index: dict[str, Any], *, attack_id: str | None = None, name: str | None = None
) -> Subject | None:
    if attack_id is not None:
        wanted = attack_id.strip().upper()
        for subject in index["subjects"]:
            if subject.kind == "technique" and (subject.attack_id or "").upper() == wanted:
                return subject
        return None
    return _by_name(index, "technique", name)


def find_software(index: dict[str, Any], name: str) -> Subject | None:
    return _by_name(index, "software", name)


def find_group(index: dict[str, Any], name: str) -> Subject | None:
    return _by_name(index, "group", name)


def _by_name(
    index: dict[str, Any], kind: str, name: str | None
) -> Subject | None:
    if not isinstance(name, str) or not name.strip():
        return None
    wanted = name.strip().casefold()
    for subject in index["subjects"]:
        if subject.kind != kind:
            continue
        if subject.name.casefold() == wanted:
            return subject
        if any(alias.casefold() == wanted for alias in subject.aliases):
            return subject
    return None


def relationships_for(
    index: dict[str, Any],
    subject: Subject,
    *,
    relationship_type: str | None = None,
) -> list[dict[str, Any]]:
    """Relationships touching the subject, endpoints projected."""
    rows: list[dict[str, Any]] = []
    for rel in index["relationships"]:
        if relationship_type and rel["relationship_type"] != relationship_type:
            continue
        if rel["source_ref"] != subject.stix_id and rel["target_ref"] != subject.stix_id:
            continue
        rows.append(
            {
                "relationship_type": rel["relationship_type"],
                "source": _endpoint(index, rel["source_ref"]),
                "target": _endpoint(index, rel["target_ref"]),
            }
        )
    rows.sort(key=lambda row: (row["relationship_type"], _sort_key(row["source"]), _sort_key(row["target"])))
    return rows


def _sort_key(endpoint: dict[str, Any]) -> tuple[str, str]:
    return (str(endpoint.get("kind") or ""), str(endpoint.get("label") or endpoint.get("stix_id") or ""))


def _endpoint(index: dict[str, Any], stix_id: str) -> dict[str, Any]:
    row = index["by_id"].get(stix_id)
    if row is None:
        return {"stix_id": stix_id, "kind": "unknown", "label": None}
    subject = _subject_from(row)
    if subject is None:
        return {
            "stix_id": stix_id,
            "kind": str(row.get("type") or "unknown"),
            "label": str(row.get("name") or "") or None,
        }
    return {
        "stix_id": subject.stix_id,
        "kind": subject.kind,
        "label": subject.attack_id or subject.name,
    }


def project_technique(index: dict[str, Any], subject: Subject) -> dict[str, Any]:
    row = index["by_id"][subject.stix_id]
    phases = sorted(
        {
            str(phase.get("phase_name") or "")
            for phase in (row.get("kill_chain_phases") or [])
            if isinstance(phase, dict) and phase.get("phase_name")
        }
    )
    return {
        "stix_id": subject.stix_id,
        "attack_id": subject.attack_id,
        "name": subject.name,
        "description": _truncate(row.get("description")),
        "kill_chain_phases": phases,
        "platforms": _string_list(row.get("x_mitre_platforms")),
        "is_subtechnique": row.get("x_mitre_is_subtechnique") is True,
        "deprecated": row.get("x_mitre_deprecated") is True,
        "revoked": row.get("revoked") is True,
    }


def project_software(index: dict[str, Any], subject: Subject) -> dict[str, Any]:
    row = index["by_id"][subject.stix_id]
    return {
        "stix_id": subject.stix_id,
        "kind": str(row.get("type") or "tool"),
        "name": subject.name,
        "description": _truncate(row.get("description")),
        "aliases": list(subject.aliases),
        "platforms": _string_list(row.get("x_mitre_platforms")),
    }


def project_group(index: dict[str, Any], subject: Subject) -> dict[str, Any]:
    row = index["by_id"][subject.stix_id]
    return {
        "stix_id": subject.stix_id,
        "name": subject.name,
        "description": _truncate(row.get("description")),
        "aliases": list(subject.aliases),
    }


def _string_list(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    return sorted({str(item) for item in raw if isinstance(item, str) and item})


def _truncate(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw:
        return None
    if len(raw) <= DESCRIPTION_CHARS:
        return raw
    return raw[: DESCRIPTION_CHARS - 3].rstrip() + "..."
