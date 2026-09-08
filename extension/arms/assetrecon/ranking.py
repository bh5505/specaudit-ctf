"""Deterministic, evidence-linked owned-or-managed association ranking.

The rank is an audit lead, never a claim of legal or physical ownership.  A
small declarative relation table lets future adapters add graph dimensions
without teaching the traversal about provider-specific response formats.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


MAX_SIGNALS = 8
MAX_SIGNAL_EVIDENCE = 16
MAX_PROPAGATION_PASSES = 32


@dataclass(frozen=True)
class RelationProfile:
    dimension: str
    cap: int
    decay: int
    reason: str
    preserve: tuple[str, ...] = ()


RELATIONS = {
    "san": RelationProfile(
        "certificate", 86, 5, "certificate SAN evidence connects this node to scoped infrastructure"
    ),
    "served_certificate": RelationProfile(
        "certificate", 86, 5, "an observed certificate deployment connects this node to scoped infrastructure"
    ),
    "co_certificate_name": RelationProfile(
        "certificate", 62, 14, "names co-observed in one CT record provide qualified certificate evidence"
    ),
    "resolves_to": RelationProfile(
        "forward_dns", 78, 5, "forward DNS control connects this node to a scoped name"
    ),
    "cname": RelationProfile(
        "forward_dns", 76, 8, "a CNAME relationship connects this node to a scoped name"
    ),
    "ptr": RelationProfile(
        "reverse_dns", 43, 15, "reverse DNS corroborates an association but can be stale or owner-controlled"
    ),
    "announced_by": RelationProfile(
        "registry",
        48,
        18,
        "routing registry evidence connects this node to an announced network",
        ("organization",),
    ),
    "registered_to": RelationProfile(
        "organization", 58, 14, "registry organization evidence corroborates an organizational association"
    ),
    "observed_hostname": RelationProfile(
        "shodan", 40, 18, "a bounded third-party observation supplies a candidate association"
    ),
    "observed_organization": RelationProfile(
        "organization", 40, 18, "a bounded third-party provider label supplies qualified organization context"
    ),
    "query_match": RelationProfile(
        "source_query", 48, 18, "a bounded source query returned this candidate within the scoped namespace"
    ),
    "scope_contains": RelationProfile(
        "source_query", 48, 18, "a bounded source query returned this candidate within the scoped namespace"
    ),
    "discovered_under": RelationProfile(
        "source_query", 48, 18, "a bounded source query returned this candidate within the scoped namespace"
    ),
}


def _remember(store, node_id, dimension, score, reason, evidence):
    if score <= 0 or node_id not in store:
        return False
    kept_evidence = tuple(sorted(set(evidence)))[:MAX_SIGNAL_EVIDENCE]
    candidate = {
        "dimension": dimension,
        "score": min(99, int(score)),
        "reason": reason,
        "evidence": kept_evidence,
    }
    previous = store[node_id].get(dimension)
    if previous is not None:
        previous_key = (previous["score"], len(previous["evidence"]), previous["evidence"])
        candidate_key = (candidate["score"], len(candidate["evidence"]), candidate["evidence"])
        if candidate_key <= previous_key:
            return False
    store[node_id][dimension] = candidate
    return True


def _domain_signal(value, roots, wildcard=False):
    name = value.removeprefix("*.")
    best = None
    for root in roots:
        if name == root:
            candidate = (55, "base-domain agreement with a scoped namespace is a valid but broad signal")
        elif name.endswith("." + root):
            extra_labels = name[: -(len(root) + 1)].count(".") + 1
            if extra_labels == 1:
                candidate = (69, "a full one-label hostname match strengthens namespace association")
            else:
                candidate = (77, "a deeper full-hostname match strongly associates the name with the scoped namespace")
        elif len(root.split(".")) == 2:
            root_stem = root.split(".")[0]
            labels = name.split(".")
            if len(labels) >= 2 and labels[-2] == root_stem and labels[-1] != root.split(".")[-1]:
                candidate = (31, "an organization stem shared across suffixes is a weak cross-TLD signal")
            else:
                continue
        else:
            continue
        if best is None or candidate[0] > best[0]:
            best = candidate
    if best is None:
        return None
    score, reason = best
    if wildcard:
        return max(1, score - 8), reason + "; wildcard coverage is limited to one label"
    return score, reason


def _organization_terms(roots, hints):
    terms = set()
    for root in roots:
        labels = root.split(".")
        if len(labels) == 2 and len(labels[0]) >= 3:
            terms.add(labels[0].lower())
    for hint in hints:
        if isinstance(hint, str):
            terms.update(token.lower() for token in re.findall(r"[A-Za-z0-9]{3,}", hint))
    return terms


def _organization_signal(value, roots, hints):
    tokens = set(token.lower() for token in re.findall(r"[A-Za-z0-9]{3,}", value))
    matched = tokens & _organization_terms(roots, hints)
    if not matched:
        return None
    explicit = any(
        matched & set(token.lower() for token in re.findall(r"[A-Za-z0-9]{3,}", hint))
        for hint in hints
        if isinstance(hint, str)
    )
    if explicit:
        return 60, "registry organization tokens match an explicit operator-supplied organization hint"
    return 47, "registry organization tokens match a conservative stem derived from a scoped root"


def _grade(score):
    if score >= 80:
        return "strong"
    if score >= 55:
        return "moderate"
    if score >= 25:
        return "weak"
    return "unassessed"


def _combined(signals):
    if not signals:
        return 0
    ordered = sorted((signal["score"] for signal in signals), reverse=True)
    score = ordered[0]
    # Corroboration is useful, but bounded bonuses avoid laundering several
    # weak or correlated observations into certainty.
    for index, support in enumerate(ordered[1:4], start=1):
        ceiling = (8, 5, 3)[index - 1]
        score += min(ceiling, max(1, support // 12))
    return min(99, score)


def rank(nodes, edges, evidence, roots, organization_hints=()):
    """Return node copies with bounded, deterministic association explanations.

    ``evidence`` and ``edges`` must already be output-trimmed.  Evidence IDs
    absent from that retained set are discarded, so association provenance is
    closed over the emitted artifact.
    """
    roots = tuple(sorted(set(root for root in roots if isinstance(root, str))))
    hints = tuple(hint for hint in organization_hints if isinstance(hint, str))
    node_by_id = {
        node["id"]: dict(node)
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
    allowed_evidence = {
        item["id"]
        for item in evidence
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    incident = {node_id: set() for node_id in node_by_id}
    adjacency = {node_id: [] for node_id in node_by_id}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        left, right, relation = edge.get("source"), edge.get("target"), edge.get("relation")
        profile = RELATIONS.get(relation)
        if left not in node_by_id or right not in node_by_id or profile is None:
            continue
        retained = tuple(
            item for item in edge.get("evidence", ()) if isinstance(item, str) and item in allowed_evidence
        )[:MAX_SIGNAL_EVIDENCE]
        incident[left].update(retained)
        incident[right].update(retained)
        adjacency[left].append((right, profile, retained))
        adjacency[right].append((left, profile, retained))

    signals = {node_id: {} for node_id in node_by_id}
    for node_id, node in node_by_id.items():
        kind, value = node.get("type"), node.get("value")
        retained = incident[node_id]
        if kind in ("domain", "dns_pattern") and isinstance(value, str):
            domain_support = _domain_signal(value, roots, kind == "dns_pattern")
            if domain_support:
                score, reason = domain_support
                if node.get("seed") and value.removeprefix("*.") in roots:
                    score = 95
                    reason = "operator-supplied root is a scope anchor, not independent proof of ownership"
                    retained = ()
                _remember(signals, node_id, "namespace", score, reason, retained)
        elif kind == "certificate" and node.get("seed"):
            _remember(
                signals,
                node_id,
                "scope_certificate",
                90,
                "operator-supplied certificate fingerprint is a scope anchor, not proof of current deployment",
                (),
            )
        elif kind == "organization" and isinstance(value, str):
            organization_support = _organization_signal(value, roots, hints)
            if organization_support:
                _remember(signals, node_id, "organization", *organization_support, retained)

    # Scores only rise and are capped; this converges even when the graph has
    # cycles.  The explicit pass bound is a second termination guarantee.
    # Every profile decays by at least five points, so a signal starting at
    # the maximum score is exhausted in fewer than 20 hops.  The fixed bound
    # also keeps future profile mistakes from turning a large cyclic graph
    # into an unbounded ranking pass.
    for _ in range(MAX_PROPAGATION_PASSES):
        changed = False
        snapshot = {
            node_id: tuple(dimensions.values()) for node_id, dimensions in signals.items()
        }
        for node_id, candidates in snapshot.items():
            for target, profile, edge_evidence in adjacency[node_id]:
                for source_signal in candidates:
                    propagated = min(profile.cap, source_signal["score"] - profile.decay)
                    path_evidence = tuple(source_signal["evidence"]) + tuple(edge_evidence)
                    dimension = (
                        source_signal["dimension"]
                        if source_signal["dimension"] in profile.preserve
                        else profile.dimension
                    )
                    reason = (
                        source_signal["reason"]
                        if source_signal["dimension"] in profile.preserve
                        else profile.reason
                    )
                    changed |= _remember(
                        signals,
                        target,
                        dimension,
                        propagated,
                        reason,
                        path_evidence,
                    )
        if not changed:
            break

    output = []
    caveat = (
        "Association is not ownership proof; shared hosting, CDNs, delegated services, stale data, "
        "and owner-controlled records can mislead."
    )
    for node in nodes:
        item = dict(node)
        dimensions = sorted(
            signals.get(node.get("id"), {}).values(),
            key=lambda signal: (-signal["score"], signal["dimension"], signal["evidence"]),
        )[:MAX_SIGNALS]
        score = _combined(dimensions)
        item["association"] = {
            "score": score,
            "grade": _grade(score),
            "reasons": ([signal["reason"] for signal in dimensions[:4]] or ["no retained evidence links this node to a scope anchor"])
            + [caveat],
            "signals": [
                {
                    "dimension": signal["dimension"],
                    "score": signal["score"],
                    "evidence": list(signal["evidence"]),
                }
                for signal in dimensions
            ],
        }
        output.append(item)
    return output
