"""Import a hashed, synthetic k8scout report without contacting Kubernetes."""
import argparse
import hashlib
import json
from pathlib import Path

REVISION = "031c8bc4fc6579aab9d1df2e781697968028a427"
MAX_BYTES = 1_048_576
MAX_ROWS = 500
TOP = {"meta", "identity", "permissions", "cluster_objects", "graph", "risk_findings", "audit_footprint"}
NODE_KINDS = {"Identity", "ServiceAccount", "Namespace", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "Workload", "Pod", "Secret", "ConfigMap", "Node", "Webhook", "CRD", "CloudIdentity"}
EDGE_KINDS = {"can_list", "can_get", "can_create", "can_patch", "can_delete", "can_exec", "can_portforward", "can_impersonate", "can_escalate", "can_bind", "mounts", "runs_as", "runs_on", "bound_to", "grants", "granted_by", "member_of", "inferred", "authenticates_as", "assumes_cloud_role", "serves_webhook", "can_mutate_workloads"}


class InvalidCapture(ValueError):
    pass


def _obj(value, where):
    if not isinstance(value, dict):
        raise InvalidCapture(f"{where}: object required")
    return value


def _list(value, where):
    if not isinstance(value, list):
        raise InvalidCapture(f"{where}: list required")
    if len(value) > MAX_ROWS:
        raise InvalidCapture(f"{where}: maximum {MAX_ROWS} rows")
    return value


def _str(value, where):
    if not isinstance(value, str) or not value.strip():
        raise InvalidCapture(f"{where}: nonempty text required")
    return value


def _keys(value, allowed, required, where):
    extra = set(value) - set(allowed)
    missing = set(required) - set(value)
    if extra or missing:
        raise InvalidCapture(f"{where}: extra={sorted(extra)}, missing={sorted(missing)}")


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise InvalidCapture(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique_pairs)
    except InvalidCapture:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidCapture("invalid JSON or duplicate keys") from exc


def normalize(raw_bytes, capture):
    """Return a source-attributed subset. No report statement becomes a verified fact."""
    if len(raw_bytes) > MAX_BYTES:
        raise InvalidCapture("report exceeds 1 MiB")
    capture = _obj(capture, "capture")
    _keys(capture, {"schema", "source_revision", "sha256", "producer", "captured_at", "subject", "scope", "limitations", "ssar_complete", "test_cases"},
          {"schema", "source_revision", "sha256", "producer", "captured_at", "subject", "scope", "limitations", "ssar_complete", "test_cases"}, "capture")
    if capture["schema"] != "specaudit.k8scout-capture.v1" or capture["source_revision"] != REVISION:
        raise InvalidCapture("capture schema or source revision mismatch")
    if capture["sha256"] != hashlib.sha256(raw_bytes).hexdigest():
        raise InvalidCapture("raw report hash mismatch")
    for key in ("producer", "captured_at", "subject", "scope", "limitations"):
        _str(capture[key], f"capture.{key}")
    if not isinstance(capture["ssar_complete"], bool):
        raise InvalidCapture("capture.ssar_complete: boolean required")
    report = _json(raw_bytes)
    report = _obj(report, "report")
    _keys(report, TOP, {"meta", "identity", "permissions", "cluster_objects", "graph", "risk_findings"}, "report")
    meta = _obj(report["meta"], "meta")
    identity = _obj(report["identity"], "identity")
    if meta.get("tool") != "k8scout" or not isinstance(meta.get("timeout_s"), int) or isinstance(meta["timeout_s"], bool):
        raise InvalidCapture("meta: expected k8scout and integer timeout_s")
    for key in ("version", "timestamp"):
        _str(meta.get(key), f"meta.{key}")
    username = _str(identity.get("username"), "identity.username")
    if username != capture["subject"]:
        raise InvalidCapture("subject differs from report identity")
    namespace = _str(identity.get("namespace"), "identity.namespace")
    sa_name = _str(identity.get("sa_name"), "identity.sa_name")
    if username != f"system:serviceaccount:{namespace}:{sa_name}":
        raise InvalidCapture("identity service-account fields disagree")
    objects = _obj(report["cluster_objects"], "cluster_objects")
    namespaces = set()
    for i, value in enumerate(_list(objects.get("namespaces", []), "cluster_objects.namespaces")):
        namespaces.add(_str(_obj(value, f"namespaces[{i}]").get("name"), f"namespaces[{i}].name"))
    permissions = _obj(report["permissions"], "permissions")
    _obj(permissions.get("ssrr_by_namespace"), "permissions.ssrr_by_namespace")
    checks = _list(permissions.get("ssar_checks"), "permissions.ssar_checks")
    normalized_checks = []
    for i, value in enumerate(checks):
        check = _obj(value, f"ssar_checks[{i}]")
        for key in ("verb", "resource"):
            _str(check.get(key), f"ssar_checks[{i}].{key}")
        if not isinstance(check.get("allowed"), bool):
            raise InvalidCapture(f"ssar_checks[{i}].allowed: boolean required")
        normalized_checks.append({k: check.get(k, "") for k in ("verb", "resource", "namespace", "subresource", "allowed", "reason")})
    graph = _obj(report["graph"], "graph")
    nodes = {}
    for i, value in enumerate(_list(graph.get("nodes"), "graph.nodes")):
        node = _obj(value, f"nodes[{i}]")
        key = _str(node.get("id"), f"nodes[{i}].id")
        if key in nodes or not isinstance(node.get("kind"), str) or node["kind"] not in NODE_KINDS:
            raise InvalidCapture(f"nodes[{i}]: duplicate ID or unknown kind")
        nodes[key] = {"id": key, "kind": node["kind"], "name": _str(node.get("name"), f"nodes[{i}].name"), "namespace": node.get("namespace", "")}
        if not isinstance(nodes[key]["namespace"], str):
            raise InvalidCapture(f"nodes[{i}].namespace: text required")
    matching_sa = [node["id"] for node in nodes.values() if node["kind"] == "ServiceAccount" and node["namespace"] == namespace and node["name"] == sa_name]
    if len(matching_sa) != 1:
        raise InvalidCapture("graph lacks unique subject service-account node")
    subject_sa = matching_sa[0]
    edges = []
    edge_set = set()
    for i, value in enumerate(_list(graph.get("edges"), "graph.edges")):
        edge = _obj(value, f"edges[{i}]")
        start = _str(edge.get("from"), f"edges[{i}].from")
        end = _str(edge.get("to"), f"edges[{i}].to")
        kind = edge.get("kind")
        if start not in nodes or end not in nodes or not isinstance(kind, str) or kind not in EDGE_KINDS:
            raise InvalidCapture(f"edges[{i}]: dangling endpoint or unknown kind")
        if "inferred" in edge and not isinstance(edge["inferred"], bool):
            raise InvalidCapture(f"edges[{i}].inferred: boolean required")
        key = (start, end, kind)
        if key in edge_set:
            raise InvalidCapture(f"edges[{i}]: duplicate")
        edge_set.add(key)
        edges.append({"from": start, "to": end, "kind": kind, "inferred": edge.get("inferred", False), "classification": "tool-inferred" if edge.get("inferred", False) else "tool-reported"})
    findings = []
    ids = set()
    for i, value in enumerate(_list(report["risk_findings"], "risk_findings")):
        finding = _obj(value, f"risk_findings[{i}]")
        key = _str(finding.get("id"), f"risk_findings[{i}].id")
        if key in ids:
            raise InvalidCapture(f"risk_findings[{i}]: duplicate ID")
        ids.add(key)
        for field in ("rule_id", "title"):
            _str(finding.get(field), f"risk_findings[{i}].{field}")
        if finding.get("severity") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            raise InvalidCapture(f"risk_findings[{i}]: invalid severity")
        affected = _list(finding.get("affected_nodes", []), f"risk_findings[{i}].affected_nodes")
        if any(not isinstance(n, str) or n not in nodes for n in affected):
            raise InvalidCapture(f"risk_findings[{i}]: unknown affected node")
        steps = _list(finding.get("attack_path", []), f"risk_findings[{i}].attack_path")
        path = []
        for j, value in enumerate(steps):
            step = _obj(value, f"risk_findings[{i}].attack_path[{j}]")
            node = _obj(step.get("node"), "path node")
            nid = _str(node.get("id"), "path node ID")
            if nid not in nodes or step.get("hop") != j or isinstance(step.get("hop"), bool):
                raise InvalidCapture(f"risk_findings[{i}].attack_path[{j}]: unknown node or nonsequential hop")
            if node.get("kind") != nodes[nid]["kind"] or node.get("name") != nodes[nid]["name"] or node.get("namespace", "") != nodes[nid]["namespace"]:
                raise InvalidCapture(f"risk_findings[{i}].attack_path[{j}]: embedded node differs from graph")
            if j:
                edge = _obj(step.get("edge"), "path edge")
                if not all(isinstance(edge.get(k), str) for k in ("from", "to", "kind")) or (edge["from"], edge["to"], edge["kind"]) not in edge_set or edge["from"] != path[-1] or edge["to"] != nid:
                    raise InvalidCapture(f"risk_findings[{i}].attack_path[{j}]: unbacked path edge")
            path.append(nid)
        findings.append({"id": key, "rule_id": finding["rule_id"], "severity": finding["severity"], "title": finding["title"], "affected_nodes": affected, "attack_path": path, "classification": "tool-reported-hypothesis"})
    evaluations = []
    seen_cases = set()
    for i, value in enumerate(_list(capture["test_cases"], "capture.test_cases")):
        case = _obj(value, f"test_cases[{i}]")
        _keys(case, {"id", "verb", "resource", "namespace", "binding_node"},
              {"id", "verb", "resource", "namespace", "binding_node"}, f"test_cases[{i}]")
        for field in ("id", "verb", "resource", "namespace", "binding_node"):
            _str(case[field], f"test_cases[{i}].{field}")
        if case["id"] in seen_cases:
            raise InvalidCapture(f"test_cases[{i}]: duplicate ID")
        seen_cases.add(case["id"])
        matching = [check for check in normalized_checks if all(check[k] == case[k] for k in ("verb", "resource", "namespace")) and not check["subresource"]]
        if len(matching) > 1:
            raise InvalidCapture(f"test_cases[{i}]: ambiguous duplicate SSAR checks")
        prerequisites = []
        if case["namespace"] not in namespaces:
            prerequisites.append("namespace-not-enumerated")
        if case["binding_node"] not in nodes or nodes[case["binding_node"]]["kind"] not in ("RoleBinding", "ClusterRoleBinding"):
            prerequisites.append("binding-not-enumerated")
        else:
            binding = nodes[case["binding_node"]]
            if binding["kind"] == "RoleBinding" and binding["namespace"] != case["namespace"]:
                prerequisites.append("binding-namespace-mismatch")
            if (subject_sa, case["binding_node"], "granted_by") not in edge_set:
                prerequisites.append("subject-binding-edge-missing")
        if not matching:
            prerequisites.append("permission-check-missing")
        if matching and not matching[0]["allowed"]:
            outcome = "blocked-permission"
        elif prerequisites:
            outcome = "unknown-prerequisite"
        else:
            outcome = "allowed-check-candidate"
        evaluations.append({"id": case["id"], "outcome": outcome, "unknown_prerequisites": prerequisites,
                            "basis": "reported SSAR and enumerated metadata only; never proof of effective access"})
    return {"schema": "specaudit.k8scout-normalized.v1", "producer": capture["producer"], "source_revision": REVISION,
            "report_version": meta["version"], "report_time": meta["timestamp"], "captured_at": capture["captured_at"],
            "raw_sha256": capture["sha256"], "subject": username, "scope": capture["scope"],
            "limitations": capture["limitations"], "ssar_complete": capture["ssar_complete"],
            "ssar_checks": normalized_checks, "nodes": list(nodes.values()), "edges": edges, "findings": findings,
            "case_evaluations": evaluations,
            "conclusion": "reported paths require independent permission and prerequisite validation"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.report.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        with args.capture.open("rb") as stream:
            capture_raw = stream.read(MAX_BYTES + 1)
        if len(capture_raw) > MAX_BYTES:
            raise InvalidCapture("capture exceeds 1 MiB")
        capture = _json(capture_raw)
        normalized = normalize(raw, capture)
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    print(json.dumps({"ok": True, "result": normalized}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
