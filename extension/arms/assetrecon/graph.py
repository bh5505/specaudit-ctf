"""One graph, retaining only reachable evidence and explainable associations."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from dataclasses import asdict

from .model import Refusal
from .ranking import rank
from .sources import ADAPTERS


def ident(kind, value):
    return kind + ":" + value


class Graph:
    def __init__(self, seed_nodes, exclusions, budget):
        self.budget = budget
        self.exclusions = exclusions
        self.nodes = {}
        self.edges = {}
        self.evidence = {}
        self.limitations = []
        self.roots = [value for kind, value in seed_nodes if kind == "domain"]
        self.organization_hints = []
        self.context = {}
        self.record_visits = 0
        for kind, value in seed_nodes:
            self.add_node(kind, value, 0, True)

    def limit(self, reason):
        if reason not in self.limitations:
            self.limitations.append(reason)

    def add_node(self, kind, value, depth, seed=False):
        key = ident(kind, value)
        if self.exclusions.denies(kind, value):
            return None
        if key not in self.nodes:
            if len(self.nodes) >= self.budget.values["max_nodes"]:
                raise Refusal("node budget reached")
            self.nodes[key] = dict(id=key, type=kind, value=value, depth=depth, seed=seed)
        else:
            self.nodes[key]["depth"] = min(self.nodes[key]["depth"], depth)
        return key

    def expand(self, records, recursive=True):
        # Both directions permit a fingerprint seed to reach names and an IP
        # seed to reach a certificate; relation direction remains unchanged.
        maximum = self.budget.values["max_depth"] if recursive else 1
        adjacency = defaultdict(list)
        for obs, digest in records:
            self.budget.remaining()
            for key in {ident(obs.left_kind, obs.left), ident(obs.right_kind, obs.right)}:
                adjacency[key].append((obs, digest))
        queue = deque((key, node["depth"]) for key, node in self.nodes.items())
        visited_depth = {}
        while queue:
            self.budget.remaining()
            key, depth = queue.popleft()
            if depth >= visited_depth.get(key, maximum + 1):
                continue
            visited_depth[key] = depth
            for obs, digest in adjacency.get(key, ()):
                self.record_visits += 1
                self.budget.remaining()
                left = ident(obs.left_kind, obs.left)
                right = ident(obs.right_kind, obs.right)
                if key not in (left, right):
                    continue
                if self.exclusions.denies(obs.left_kind, obs.left) or self.exclusions.denies(obs.right_kind, obs.right):
                    continue
                if depth >= maximum and (left not in self.nodes or right not in self.nodes):
                    self.limit("depth budget reached")
                    continue
                evidence_id = hashlib.sha256(json.dumps([asdict(obs), digest], sort_keys=True).encode()).hexdigest()
                edgekey = (left, obs.relation, right, obs.source, digest, evidence_id)
                is_new_edge = edgekey not in self.edges
                if is_new_edge and len(self.edges) >= self.budget.values["max_edges"]:
                    raise Refusal("edge budget reached")
                needed = sum(k not in self.nodes for k in {left, right})
                if len(self.nodes) + needed > self.budget.values["max_nodes"]:
                    raise Refusal("node budget reached")
                for kind, value in ((obs.left_kind, obs.left), (obs.right_kind, obs.right)):
                    nodekey = self.add_node(kind, value, depth + 1)
                    if self.nodes[nodekey]["depth"] < visited_depth.get(nodekey, maximum + 1):
                        queue.append((nodekey, self.nodes[nodekey]["depth"]))
                if is_new_edge:
                    self.evidence[evidence_id] = dict(id=evidence_id, source=obs.source, artifact_sha256=digest,
                                                       origin=obs.attributes.get("origin", "local-fixture"),
                                                       locator=(ADAPTERS[obs.source].endpoint if obs.attributes.get("origin") == "provider" else "fixture:sha256:" + digest),
                                                       observation=asdict(obs))
                    self.edges[edgekey] = dict(source=left, target=right, relation=obs.relation, evidence=[evidence_id])

    def output(self):
        all_edges = list(self.edges.values())
        all_nodes = list(self.nodes.values())
        def retained(count, seed_count=None):
            edges = all_edges[:count]
            keep_evidence = {e for edge in edges for e in edge["evidence"]}
            evidence = [e for e in self.evidence.values() if e["id"] in keep_evidence]
            keep_nodes = {edge[k] for edge in edges for k in ("source", "target")}
            selected_seeds = [n["id"] for n in all_nodes if n["seed"]][:seed_count]
            nodes = [n for n in all_nodes if n["id"] in keep_nodes or n["id"] in selected_seeds]
            omitted = len(nodes) != len(all_nodes) or count != len(all_edges)
            limitations = list(self.limitations) + (["output budget reached"] if omitted else [])
            ranked = rank(nodes, edges, evidence, self.roots, self.organization_hints)
            return dict(schema="specaudit.ctf.asset-recon.v1", status="partial" if limitations else "complete",
                        context=dict(self.context),
                        nodes=ranked, edges=edges, evidence=evidence, limitations=limitations,
                        requests=self.budget.requests, counts=dict(nodes=len(ranked), edges=len(edges), evidence=len(evidence)))
        result = retained(len(all_edges))
        maximum = self.budget.values["max_output_bytes"]
        def fits(value):
            return len(json.dumps(value).encode()) <= maximum
        if fits(result):
            return result
        # Binary search prunes whole edge/evidence units in logarithmic passes;
        # ranking is recomputed from exactly the retained provenance each time.
        low, high = 0, len(all_edges)
        result = retained(0)
        while low <= high:
            middle = (low + high) // 2
            candidate = retained(middle)
            if fits(candidate):
                result = candidate
                low = middle + 1
            else:
                high = middle - 1
        if fits(result):
            return result
        low, high = 0, len(all_nodes)
        result = retained(0, 0)
        while low <= high:
            middle = (low + high) // 2
            candidate = retained(0, middle)
            if fits(candidate):
                result = candidate
                low = middle + 1
            else:
                high = middle - 1
        return result
