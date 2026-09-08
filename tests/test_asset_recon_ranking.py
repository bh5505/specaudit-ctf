from extension.arms.assetrecon.ranking import MAX_PROPAGATION_PASSES, RELATIONS, _remember, rank


def _node(kind, value, *, seed=False):
    return {"id": f"{kind}:{value}", "type": kind, "value": value, "depth": 0, "seed": seed}


def _evidence(number):
    return {"id": f"e{number}", "source": "fixture", "artifact_sha256": "a" * 64, "observation": {}}


def _edge(left, relation, right, number):
    return {"source": left["id"], "target": right["id"], "relation": relation, "evidence": [f"e{number}"]}


def test_namespace_strength_is_graded_and_cross_tld_is_weaker():
    nodes = [
        _node("domain", "acme.com", seed=True),
        _node("domain", "api.acme.com"),
        _node("domain", "deep.api.acme.com"),
        _node("dns_pattern", "*.acme.com"),
        _node("domain", "acme.net"),
    ]
    ranked = rank(nodes, [], [], ["acme.com"])
    scores = {item["value"]: item["association"]["score"] for item in ranked}
    assert scores["acme.com"] == 95
    assert scores["deep.api.acme.com"] > scores["api.acme.com"] > scores["*.acme.com"] > scores["acme.net"]


def test_forward_dns_and_certificate_control_corroborate_an_ip():
    root = _node("domain", "acme.com", seed=True)
    cert = _node("certificate", "a" * 64, seed=True)
    ip = _node("ip", "203.0.113.10")
    evidence = [_evidence(1), _evidence(2)]
    edges = [_edge(root, "resolves_to", ip, 1), _edge(ip, "served_certificate", cert, 2)]
    ranked = rank([root, cert, ip], edges, evidence, ["acme.com"])
    association = next(item["association"] for item in ranked if item["id"] == ip["id"])
    assert association["grade"] == "strong"
    assert {signal["dimension"] for signal in association["signals"]} >= {"forward_dns", "certificate"}
    assert {item for signal in association["signals"] for item in signal["evidence"]} == {"e1", "e2"}


def test_ptr_registry_and_matching_organization_add_separate_dimensions():
    root = _node("domain", "acme.com", seed=True)
    ip = _node("ip", "203.0.113.20")
    ptr = _node("domain", "edge.acme.net")
    asn = _node("asn", "64500")
    org = _node("organization", "ACME Telecom LLC")
    nodes = [root, ip, ptr, asn, org]
    edges = [
        _edge(root, "resolves_to", ip, 1),
        _edge(ip, "ptr", ptr, 2),
        _edge(ip, "announced_by", asn, 3),
        _edge(asn, "registered_to", org, 4),
    ]
    ranked = rank(nodes, edges, [_evidence(i) for i in range(1, 5)], ["acme.com"])
    by_id = {item["id"]: item["association"] for item in ranked}
    assert {signal["dimension"] for signal in by_id[ip["id"]]["signals"]} >= {
        "forward_dns",
        "reverse_dns",
        "registry",
        "organization",
    }
    assert by_id[asn["id"]]["score"] < by_id[ip["id"]]["score"]
    assert "ownership proof" in by_id[ip["id"]]["reasons"][-1]


def test_ranking_closes_signal_provenance_over_retained_evidence():
    root = _node("domain", "acme.com", seed=True)
    ip = _node("ip", "203.0.113.30")
    edge = _edge(root, "resolves_to", ip, 1)
    edge["evidence"].append("trimmed-away")
    ranked = rank([root, ip], [edge], [_evidence(1)], ["acme.com"])
    association = next(item["association"] for item in ranked if item["id"] == ip["id"])
    assert {item for signal in association["signals"] for item in signal["evidence"]} == {"e1"}


def test_cycles_terminate_and_unknown_relations_do_not_create_confidence():
    root = _node("domain", "acme.com", seed=True)
    ip = _node("ip", "203.0.113.40")
    unknown = _node("asn", "64501")
    edges = [
        _edge(root, "resolves_to", ip, 1),
        _edge(ip, "resolves_to", root, 2),
        _edge(ip, "future_untrusted_relation", unknown, 3),
    ]
    ranked = rank([root, ip, unknown], edges, [_evidence(i) for i in range(1, 4)], ["acme.com"])
    by_id = {item["id"]: item["association"] for item in ranked}
    assert by_id[ip["id"]]["grade"] == "moderate"
    assert by_id[unknown["id"]]["grade"] == "unassessed"
    assert by_id[unknown["id"]]["signals"] == []


def test_every_relation_decays_inside_the_fixed_cycle_bound():
    assert MAX_PROPAGATION_PASSES == 32
    assert all(profile.decay >= 5 for profile in RELATIONS.values())


def test_equal_score_signal_retains_the_path_with_more_evidence():
    store = {"node": {}}
    assert _remember(store, "node", "certificate", 70, "short path", ("e1",))
    assert _remember(store, "node", "certificate", 70, "corroborated path", ("e1", "e2"))
    assert store["node"]["certificate"]["evidence"] == ("e1", "e2")
