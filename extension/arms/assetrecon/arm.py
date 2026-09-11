"""Public arm: explicit source collection, shared discovery, separate probes."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace

from ...contract import Result
from ..dispatch import log_dispatch
from .graph import Graph
from .model import Budget, CEILINGS, DEFAULTS, Exclusions, Observation, Refusal, bounded_list, closed, live_value, normalize, pattern_covers, seeds
from .runner import WorkerRefusal, run_worker
from .probe_policy import validate_target
from .sources import ADAPTERS, read_fixture

ARM_ID = "asset-recon"
ACTIONS = ("list_tools", "plan", "parse", "ct", "ptr", "discover", "probe")
COMMON = ("seeds", "exclusions", "limits", "organization_hints")


def exclusion_context(exclusions):
    """Retain policy identity without echoing suppressed values in results."""
    policy = dict(domains=list(exclusions.domains), networks=[str(network) for network in exclusions.networks])
    return dict(
        domain_count=len(exclusions.domains),
        network_count=len(exclusions.networks),
        policy_sha256=hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    )


def manifest_context(values):
    """Bounded identity for caller policy that need not be echoed verbatim."""
    encoded = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    return dict(count=len(values), sha256=hashlib.sha256(encoded).hexdigest())


class AssetReconArm:
    protocol = "cli"

    def installed(self, spec):
        return spec.id == ARM_ID

    def invoke(self, spec, action, args):
        graph = None
        try:
            if spec.id != ARM_ID or action not in ACTIONS:
                raise Refusal("unknown arm or action")
            if action == "list_tools":
                closed(args, ())
                return Result(True, ARM_ID, action, dict(actions=list(ACTIONS), live_providers=sorted(set(ADAPTERS) - {"dns"}), fixture_sources=sorted(ADAPTERS),
                              provider_families=dict(ct=["crtsh", "certspotter"], ptr=["google", "cloudflare"], discover=sorted(set(ADAPTERS) - {"dns"})),
                              seed_fields=["domains", "ips", "fingerprints", "asns", "networks", "domains_file", "targets_file"],
                              exclusion_fields=["domains", "networks"],
                              probe_methods=["tcp", "tls", "http", "tcp-hello", "udp-hello", "nmap", "zgrab2"],
                              literal_hello_values=["hello", "hello\n", "hello\r\n"],
                              default_limits=dict(DEFAULTS), maximum_limits=dict(CEILINGS),
                              provider_grant="ASSET_RECON_PROVIDERS", probe_scope="ASSET_RECON_PROBE_SCOPE",
                              default_off=True, recursive_probes=False))
            allowed = COMMON + (() if action == "plan" else ("fixtures",))
            if action in ("ct", "ptr", "discover"):
                allowed += ("live", "providers")
            if action == "probe":
                allowed = ("live", "targets", "exclusions", "limits")
            payload = closed(dict(args), allowed)
            budget = Budget(payload.get("limits"))
            exclusions = Exclusions(payload.get("exclusions"))
            if action == "probe":
                return self._probe(action, payload, exclusions, budget)
            seed_values = payload.get("seeds", {})
            targets_file_digest = None
            domains_file_digest = None
            if isinstance(seed_values, dict) and ({"targets_file", "domains_file"} & set(seed_values)):
                if action == "plan":
                    raise Refusal("plan does not read seed files")
                seed_values = dict(seed_values)
                if "targets_file" in seed_values:
                    file_values, targets_file_digest = read_fixture(seed_values["targets_file"])
                    file_values = bounded_list(file_values, 256)
                    seed_values["ips"] = bounded_list(seed_values.get("ips", [])) + file_values
                    if len(seed_values["ips"]) > 256:
                        raise Refusal("targets file exceeds address cap")
                    del seed_values["targets_file"]
                if "domains_file" in seed_values:
                    file_values, domains_file_digest = read_fixture(seed_values["domains_file"])
                    file_values = bounded_list(file_values, 64)
                    seed_values["domains"] = bounded_list(seed_values.get("domains", [])) + file_values
                    if len(seed_values["domains"]) > 64:
                        raise Refusal("domains file exceeds domain cap")
                    del seed_values["domains_file"]
            seed_nodes = seeds(seed_values, exclusions)
            if action == "ct" and any(kind != "domain" for kind, _ in seed_nodes):
                raise Refusal("ct collection accepts domain seeds only")
            if action == "ptr" and any(kind != "ip" for kind, _ in seed_nodes):
                raise Refusal("ptr collection accepts IP seeds only")
            graph = Graph(seed_nodes, exclusions, budget)
            graph.organization_hints = [normalize("organization", value) for value in bounded_list(payload.get("organization_hints", []), 16)]
            graph.context = dict(
                action=action,
                seeds=manifest_context([dict(type=kind, value=value) for kind, value in seed_nodes]),
                exclusions=exclusion_context(exclusions),
                limits=dict(budget.values),
                organization_hints=manifest_context(list(graph.organization_hints)),
                domains_file_sha256=domains_file_digest,
                targets_file_sha256=targets_file_digest,
            )
            if not seed_nodes:
                raise Refusal("no permitted seeds remain")
            if action == "plan":
                output = graph.output()
                output["plan"] = dict(seeds=[dict(type=k, value=v) for k, v in seed_nodes],
                                      exclusions=dict(domains=list(exclusions.domains), networks=[str(n) for n in exclusions.networks]), limits=budget.values,
                                      organization_hints=list(graph.organization_hints),
                                      excluded_seed_count=len(seeds(seed_values, Exclusions())) - len(seed_nodes),
                                      task_families=["certificate-transparency", "forward-dns", "reverse-dns", "asn-registry", "optional-shodan"],
                                      estimated_request_cap=budget.values["max_requests"], collection_performed=False)
                output["nodes"] = []
                output["counts"]["nodes"] = 0
                if len(json.dumps(output).encode()) > budget.values["max_output_bytes"]:
                    raise Refusal("plan exceeds output budget")
                return Result(True, ARM_ID, action, output)
            fixtures = bounded_list(payload.get("fixtures", []), 16)
            if action == "parse" and not fixtures:
                raise Refusal("parse requires fixture files")
            live = payload.get("live", False)
            if type(live) is not bool:
                raise Refusal("live must be a boolean")
            if action == "discover" and not live and not fixtures:
                raise Refusal("offline discovery requires fixtures; use plan for preparation")
            if action in ("ct", "ptr") and not live:
                raise Refusal("collection requires explicit live true and ASSET_RECON_PROVIDERS")
            providers = bounded_list(payload.get("providers", ["crtsh"] if action == "ct" else ["google"] if action == "ptr" else []), 8)
            if providers and not live:
                raise Refusal("providers require explicit live true")
            if live:
                self._grants(providers)
                families = {"ct": {"crtsh", "certspotter"}, "ptr": {"google", "cloudflare"}, "discover": set(ADAPTERS) - {"dns"}}
                if not set(providers) <= families[action]:
                    raise Refusal("provider does not belong to action family")
            records = []
            fixture_sources = []
            for fixture in fixtures:
                try:
                    closed(fixture, ("source", "path"))
                    source = fixture.get("source")
                    if source not in ADAPTERS:
                        raise Refusal("unknown fixture source")
                    if source not in fixture_sources:
                        fixture_sources.append(source)
                    data, digest = read_fixture(fixture.get("path"))
                    self._records(records, source, data, digest, budget, graph.roots)
                except Refusal as exc:
                    graph.limit(str(exc))
            graph.context.update(live=live, providers=list(providers), fixture_sources=fixture_sources)
            graph.expand(records)
            if live:
                self._collect(graph, records, providers, action)
            return self._result(action, graph)
        except (Refusal, TypeError, KeyError, ValueError, OverflowError):
            # Refusal messages are constant; unexpected parser exceptions are
            # intentionally not reflected into result or terminal output.
            if graph is not None:
                graph.limit("operation refused or budget exhausted")
                return self._result(action, graph)
            return Result(False, ARM_ID, action, dict(schema="specaudit.ctf.asset-recon.v1", status="failed",
                          nodes=[], edges=[], evidence=[], limitations=["operation refused [REDACTED]"], requests=0,
                          counts=dict(nodes=0, edges=0, evidence=0)), "operation refused [REDACTED]")

    def _result(self, action, graph):
        output = graph.output()
        complete = output["status"] == "complete"
        return Result(complete, ARM_ID, action, output, None if complete else "partial reconnaissance; inspect limitations")

    def _records(self, records, source, data, digest, budget, roots=(), origin="local-fixture"):
        digest = normalize("certificate", digest)
        for obs in ADAPTERS[source].parse(data):
            budget.record()
            obs = replace(obs, source=source, attributes=dict(obs.attributes, origin=origin))
            records.append((obs, digest))
            if source in ("crtsh", "certspotter"):
                for kind, value in ((obs.left_kind, obs.left), (obs.right_kind, obs.right)):
                    for root in roots:
                        if (kind == "domain" and value != root and value.endswith("." + root)) or (kind == "dns_pattern" and (pattern_covers(value, root) or value[2:] == root or value[2:].endswith("." + root))):
                            budget.record()
                            records.append((Observation(source, "domain", root, "discovered_under", kind, value, "inferred", dict(obs.attributes)), digest))

    def _grants(self, providers):
        if not providers or any(p not in ADAPTERS or p == "dns" for p in providers):
            raise Refusal("explicit fixed provider selection required")
        grants = os.environ.get("ASSET_RECON_PROVIDERS", "").split(",")
        if any(g not in ADAPTERS or g == "dns" for g in grants) or any(p not in grants for p in providers):
            raise Refusal("ASSET_RECON_PROVIDERS does not grant selected adapters")

    def _collect(self, graph, records, providers, action):
        budget = graph.budget
        attempted = set()
        dns_results = {}
        for node in graph.nodes.values():
            if node["seed"] and not any(node["type"] in ADAPTERS[p].query_kinds for p in providers):
                graph.limit("selected providers cannot query one or more seed types")
        while True:
            pending = []
            for node in list(graph.nodes.values()):
                if action in ("ct", "ptr") and not node["seed"]:
                    continue
                if not any(node["type"] in ADAPTERS[p].query_kinds for p in providers):
                    continue
                if node["depth"] >= budget.values["max_depth"]:
                    graph.limit("depth budget reached")
                    continue
                if not live_value(node["type"], node["value"]):
                    graph.limit("non-global or reserved value omitted from live queries")
                    continue
                for source in providers:
                    if node["type"] not in ADAPTERS[source].query_kinds:
                        continue
                    variants = ("A", "AAAA") if source in ("google", "cloudflare") and node["type"] == "domain" else ("prefixes", "overview") if source == "registry" and node["type"] == "asn" else ("exact", "subdomains") if source == "crtsh" else (None,)
                    for variant in variants:
                        key = (source, node["type"], node["value"], variant)
                        if key not in attempted:
                            pending.append(key)
            if not pending:
                break
            for source, kind, value, variant in pending:
                attempted.add((source, kind, value, variant))
                try:
                    cursors = set()
                    while True:
                        response = None
                        for retry in range(budget.values["retries"] + 1):
                            try:
                                budget.request()
                                response = run_worker(dict(operation="collect", live=True, source=source, kind=kind, value=value, variant=variant), min(12, budget.remaining()))
                                break
                            except Refusal:
                                if retry == budget.values["retries"]:
                                    raise
                        self._records(records, source, response["data"], response["digest"], budget, graph.roots, "provider")
                        if source in ("google", "cloudflare"):
                            status = response.get("dns_status")
                            if type(status) is not int or status not in (0, 3):
                                raise Refusal("invalid DNS outcome")
                            result_key = (kind, value, variant)
                            summary = (status, tuple(sorted((str(row.get("name", "")).lower().rstrip("."), row.get("type"), str(row.get("value", "")).lower().rstrip(".")) for row in response["data"])))
                            previous = dns_results.get(result_key)
                            if previous is not None and previous != summary:
                                graph.limit("DNS providers disagree on answer or negative outcome")
                            dns_results[result_key] = summary
                        if not response["data"]:
                            budget.record()
                            relation = "dns_nxdomain" if response.get("dns_status") == 3 else "dns_nodata" if source in ("google", "cloudflare") else "pagination_exhausted" if source == "certspotter" and cursors else "no_result"
                            records.append((Observation(source, kind, value, relation, kind, value, attributes={"origin": "provider"}), response["digest"]))
                        if response.get("limitations"):
                            graph.limit("provider coverage is bounded to returned snapshot")
                        graph.expand(records)
                        if source != "certspotter" or not response["data"]:
                            break
                        cursor = response.get("cursor")
                        if not isinstance(cursor, str) or cursor in cursors:
                            raise Refusal("pagination cycle or missing cursor")
                        cursors.add(cursor)
                        variant = cursor
                except (Refusal, KeyError, TypeError, ValueError):
                    graph.limit("provider request or parsing incomplete")
                    # Preserve valid earlier records if a later row/page fails.
                    try:
                        graph.expand(records)
                    except Refusal:
                        graph.limit("graph budget reached")
                    if budget.requests >= budget.values["max_requests"]:
                        return
            if action in ("ct", "ptr"):
                break

    def _probe(self, action, payload, exclusions, budget):
        if payload.get("live") is not True:
            raise Refusal("probe requires explicit live true")
        targets = bounded_list(payload.get("targets"), 16)
        if not targets:
            raise Refusal("probe requires explicit targets")
        checked = []
        for target in targets:
            checked.append(validate_target(target, exclusions))
        output = dict(
            schema="specaudit.ctf.asset-recon.v1",
            status="complete",
            context=dict(
                action=action,
                live=True,
                exclusions=exclusion_context(exclusions),
                limits=dict(budget.values),
            ),
            nodes=[], edges=[], evidence=[], probes=[], limitations=[], requests=0,
        )
        for target, scope, auth_target in checked:
            try:
                budget.request()
                log_dispatch(ARM_ID, "probe", scope, auth_target)
                response = run_worker(dict(operation="probe", live=True, target=target), min(12, budget.remaining()))
                output["probes"].append(dict(target={k: v for k, v in target.items() if k != "hello"}, observation=response))
                if response.get("complete") is False:
                    output["status"] = "partial"
                    output["limitations"].append("explicit probe capture incomplete")
            except WorkerRefusal as exc:
                output["status"] = "partial"
                output["limitations"].append(f"explicit probe refused: {exc.reason}")
                break
            except Refusal:
                output["status"] = "partial"
                output["limitations"].append("explicit probe failed or budget exhausted")
                break
        output["requests"] = budget.requests
        output["counts"] = dict(nodes=0, edges=0, evidence=0, probes=len(output["probes"]))
        while len(json.dumps(output).encode()) > budget.values["max_output_bytes"] and output["probes"]:
            output["probes"].pop()
            output["status"] = "partial"
            if "probe output budget reached" not in output["limitations"]:
                output["limitations"].append("probe output budget reached")
        output["counts"]["probes"] = len(output["probes"])
        error = None
        if output["status"] != "complete":
            refusal = next(
                (item.rpartition(": ")[2] for item in output["limitations"]
                 if item.startswith("explicit probe refused: ")),
                None,
            )
            error = f"reason:probe_{refusal}" if refusal else "partial probe results"
        return Result(output["status"] == "complete", ARM_ID, action, output, error)
