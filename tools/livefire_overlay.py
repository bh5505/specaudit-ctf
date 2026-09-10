#!/usr/bin/env python3
"""Turn live-fire receipts into evidence rows for a second pack run.

Baseline evidence (pack_evidence/) is never modified. The overlay directory
(pack_evidence_livefire/) is the baseline with:

  * unchanged CSVs hard-linked in (so an overlay run reads the identical bytes),
  * live-fire rows appended / reconciled by the rules below,
  * a manifest (livefire_overlay_manifest.json) that records every appended and
    every patched row, and the receipt line that justifies it.

Rules, and why they are not free-form:

R1 bundle provenance.  A vendor bundle's has_live_fire/has_receipt flag may only
  flip when a receipt actually re-observed something that came out of that
  bundle. The link is made through the ingested ip ledger (ip -> source_file)
  and evidence_bundle.source_file, never by hand.
R2 live-fire bundle.  The capture itself becomes a bundle (source_system
  = live_fire_capture). has_adversarial_reverify stays false: nobody tried to
  disprove these observations, which is exactly what t2_adversarial_validation
  asks. is_sandboxed is true: probes ran from an isolated lab VM against lab
  space only (egress policy), never against a host we do not own.
R3 service_endpoint.  One row per receipt, is_active true only for endpoints
  that answered (open/refused/unreachable are all recorded: a refused port is a
  negative receipt and must not silently disappear). service_type uses the
  vendor taxonomy already present in the table - no invented vocabulary.
R4 asm_vm_surface.  The spine is one row per IP, so a live-fire observation on
  an IP the spine already carries must RECONCILE that row (has_active_service,
  asm_exposed_services, seen_via, source_system); appending would count the same
  IP twice in every per-prefix COUNT(*).  IPs the spine does not carry get a new
  row, with inside_owned_range computed from the ingested owned_ip_range ledger
  (not from RFC1918 convention).
R5 website_endpoint.  HTTP(S) receipts are recorded there too. No check in the
  pack reads that table (see report); the rows are recorded anyway so the
  evidence is not lost to the table that was built for it.

R6 a probe of a lab fixture does not reproduce anything.  `--dataset-ips` names
  the addresses the feeds actually describe. A receipt whose target is one of
  those is a `dataset_endpoint` observation - a genuine attempt to reproduce a
  claim. A receipt of anything else (loopback, a lab gateway, a fixture we
  started for the purpose) is a `lab_fixture`: it proves the capture path works,
  and nothing about the estate. Only dataset_endpoint receipts may flip a
  bundle's has_live_fire (R1) and only they may touch asm_vm_surface (R4) -
  appending our own lab host to the estate spine invents an asset, which is the
  one thing an ASM audit must not do. Lab-fixture receipts are still written to
  service_endpoint/website_endpoint (with `mapping_version` saying so) and are
  counted in the manifest, so the plumbing evidence is kept and labelled instead
  of being thrown away or mistaken for reproduction.

run_id/engagement_id/accept_event_id are stamped by the runner at load
(ctr_run_checks.stamp_accept_lineage), so they carry the analytic run scope;
live-fire provenance travels in lineage_batch_id / source_system / source_file /
source_row_id, which stamping does not touch.
"""

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import shutil
import sys

RUN_ANNOTATION = "live_fire_capture"
# asm_vm_surface.source_row_id is numeric in the vendor spine (DuckDB infers
# BIGINT from its sample and the --fast-csv load is strict), so live-fire rows
# take a reserved numeric id block; the human-readable receipt pointer lives in
# source_file + lineage_batch_id and in the overlay manifest.
LIVEFIRE_SOURCE_ROW_BASE = 9100000
BANNER_SERVICE_TYPE = [
    # (matcher on (port, protocol, banner), service_type, product_version fn)
    ("http", "HttpServer"),
    ("dns", "DnsServer"),
    ("ntp", "NtpServer"),
    ("ssh", "SshServer"),
    ("smb", "SmbFileServer"),
    ("netbios", "NetBiosSessionService"),
    ("rpc", "RpcbindServer"),
]


DATASET_ENDPOINT = "dataset_endpoint"
LAB_FIXTURE = "lab_fixture"

# Rule R6, applied to every estate silver table, not just asm_vm_surface. A lab
# fixture is something we observed; it is not something the feeds describe. If it
# lands in service_endpoint/website_endpoint it sits there as a row whose ip has
# no ip-ledger row, and the next ingest that happens to cover the lab range turns
# it into estate exposure without any new observation having been made. The
# capture is still auditable: R2 keeps the capture bundle (with has_live_fire
# false) and every skipped append is named in the manifest.
LAB_FIXTURE_SKIP_REASON = (
    "lab fixture: observed by us, not described by the feeds; rule R6 keeps "
    "lab observations out of estate silver tables (override: "
    "--allow-lab-fixture-live-fire)")


def load_dataset_ips(path):
    """Addresses the feeds describe: a CSV with an `ip` column, or a plain list.

    This is what separates a reproduction attempt from a lab fixture, so it is
    loaded from an explicit file rather than inferred from RFC1918 conventions -
    our own lab is RFC1918 too, and so is part of the estate.
    """
    if not path or not os.path.exists(path):
        return set()
    ips = set()
    with open(path, encoding="utf-8-sig", newline="") as fh:
        first = fh.readline()
        fh.seek(0)
        if "," in first and "ip" in first.split(",")[0].lower():
            for row in csv.DictReader(fh):
                ip = (row.get("ip") or "").strip()
                if ip:
                    ips.add(ip)
        else:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    ips.add(line)
    return ips


def observation_class(receipt, dataset_ips):
    """R6: does this receipt observe something the feeds describe, or our own
    lab fixture?"""
    return (DATASET_ENDPOINT if (receipt.get("target_ip") or "").strip()
            in dataset_ips else LAB_FIXTURE)


def classify(port, proto, status, banner, tls_proto):
    """Map a capture to the vendor service taxonomy already used by the pack."""
    low = (banner or "").lower()
    if tls_proto or port == 443:
        return "HttpServer" if ("http" in low or port == 443) else \
            "TlsServiceRunningUnidentifiedProtocol"
    if low.startswith("http/") or " http/" in low:
        return "HttpServer"
    if "dns rcode=" in low:
        return "DnsServer"
    if "ntp " in low:
        return "NtpServer"
    if low.startswith("ssh-"):
        return "SshServer"
    if port == 445:
        return "SmbFileServer"
    if port == 139:
        return "NetBiosSessionService"
    if port == 135:
        return "RpcbindServer"
    if port in (53,):
        return "DnsServer"
    if port in (123, 323):
        return "NtpServer"
    if status == "open":
        return "UnidentifiedService"
    return "UnidentifiedService"


def product_version(rec):
    bits = []
    if rec.get("http_server_header"):
        bits.append(rec["http_server_header"])
    if rec.get("tls_protocol"):
        bits.append(rec["tls_protocol"] + "/" + rec.get("tls_cipher", ""))
    if rec.get("cert_subject"):
        bits.append("cert %s" % rec["cert_subject"])
        if rec.get("self_signed") in (True, "True", "true"):
            bits.append("(self-signed)")
    if rec.get("http_status"):
        bits.append("HTTP " + rec["http_status"])
    if rec.get("dns_rcode"):
        bits.append("DNS rcode " + rec["dns_rcode"])
    return " ".join(bits)[:200]


def md5(*parts):
    return hashlib.md5("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as fh:
        rd = csv.DictReader(fh)
        return list(rd), list(rd.fieldnames or [])


def write_csv(path, rows, fieldnames):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def load_owned_ranges(base):
    """Owned ranges exactly as the pack ingested them (first_ip/last_ip).

    inside_owned_range is decided from the engagement's declared owned ranges,
    never from RFC1918 convention: the pack's own T1 checks key off this
    column, and RFC1918 membership is not what the vendor declared.
    """
    rows, _ = read_csv(os.path.join(base, "ext_telecom_asmvm_owned_ip_range.csv"))
    spans = []
    for r in rows:
        try:
            first = int(ipaddress.ip_address((r.get("first_ip") or "").strip("'")))
            last = int(ipaddress.ip_address((r.get("last_ip") or "").strip("'")))
        except ValueError:
            continue
        if first <= last:
            spans.append((first, last))
    spans.sort()
    return spans


def inside_owned(spans, ip):
    try:
        n = int(ipaddress.ip_address(ip))
    except ValueError:
        return False
    for first, last in spans:
        if first <= n <= last:
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default="../pack_evidence")
    ap.add_argument("--out", default="../pack_evidence_livefire")
    ap.add_argument("--receipts", default="livefire_receipts.csv")
    ap.add_argument("--run-id", default="gw-asmvm-20260902")
    ap.add_argument("--livefire-run-id", default="gw-livefire-20260909")
    ap.add_argument("--engagement-id", default="asmvm-rehearsal-2026")
    ap.add_argument("--dataset-ips", default=None,
                    help="CSV with an ip column (or a plain ip list): the "
                         "addresses the feeds describe. Receipts of anything "
                         "else are lab fixtures and cannot flip has_live_fire "
                         "or touch the estate spine (rule R6).")
    ap.add_argument("--allow-lab-fixture-live-fire", action="store_true",
                    help="override R6: let lab-fixture receipts flip "
                         "has_live_fire. Recorded in the manifest, so a run "
                         "that used it is distinguishable from one that did not.")
    args = ap.parse_args()

    base = os.path.abspath(args.baseline)
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    receipts, _ = read_csv(args.receipts)
    dataset_ips = load_dataset_ips(args.dataset_ips)
    receipt_class = {id(r): observation_class(r, dataset_ips) for r in receipts}
    live_receipts = [r for r in receipts
                     if receipt_class[id(r)] == DATASET_ENDPOINT
                     or args.allow_lab_fixture_live_fire]
    dataset_receipt_count = sum(1 for c in receipt_class.values()
                                if c == DATASET_ENDPOINT)
    lab_receipt_count = sum(1 for c in receipt_class.values()
                            if c == LAB_FIXTURE)
    nets = load_owned_ranges(base)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(sep=" ")

    manifest = {
        "livefire_run_id": args.livefire_run_id,
        "analytic_run_id": args.run_id,
        "built_at_utc": now,
        "receipts_file": os.path.abspath(args.receipts),
        "receipt_rows": len(receipts),
        "dataset_ips_file": os.path.abspath(args.dataset_ips)
        if args.dataset_ips else None,
        "dataset_ips_loaded": len(dataset_ips),
        "receipts_dataset_endpoints": sum(
            1 for c in receipt_class.values() if c == DATASET_ENDPOINT),
        "receipts_lab_fixtures": sum(1 for c in receipt_class.values()
                                     if c == LAB_FIXTURE),
        "lab_fixture_live_fire_override": bool(args.allow_lab_fixture_live_fire),
        "has_live_fire": "true" if live_receipts else "false",
        # The reason has to stay true when the override is used. Saying "at least
        # one receipt re-observed an address the feeds describe" while
        # receipts_dataset_endpoints == 0 makes the manifest assert something the
        # run did not do, and a reader cannot tell estate live fire from a wiring
        # test without also reading the override flag.
        "has_live_fire_reason": (
            "at least one receipt re-observed an address the feeds describe"
            if dataset_receipt_count else (
                "no receipt re-observed an address the feeds describe "
                "(dataset receipts=%d, lab fixtures=%d); has_live_fire=true "
                "only because --allow-lab-fixture-live-fire was passed, which "
                "records a lab fixture as reproduction - a wiring test, not "
                "estate evidence" % (dataset_receipt_count, lab_receipt_count)
                if args.allow_lab_fixture_live_fire else
                "every receipt was a lab fixture: it exercises the capture "
                "path, it does not reproduce a claim about the estate "
                "(rule R6)")),
        "rules": ["R1 bundle provenance via ip->source_file->bundle",
                  "R2 live-fire bundle row", "R3 service_endpoint per receipt",
                  "R4 asm_vm_surface reconcile-or-append per IP",
                  "R5 website_endpoint for HTTP(S) receipts",
                  "R6 lab-fixture receipts cannot flip has_live_fire and are not "
                  "appended to service_endpoint, asm_vm_surface or "
                  "website_endpoint unless --allow-lab-fixture-live-fire is set"],
        "added_rows": [], "patched_rows": [], "skipped": [],
        "bundle_flips": [],
    }

    # ---- R1: which vendor bundles did the live-fire leg actually re-observe?
    # R1 + R6: only an observation of an address the feeds describe can tie a
    # receipt back to the bundle that described it.
    receipt_ips = sorted({r["target_ip"] for r in live_receipts})
    ip_rows, _ = read_csv(os.path.join(base, "ext_telecom_asmvm_ip.csv"))
    src_files = {r["source_file"] for r in ip_rows if r["ip"] in set(receipt_ips)}
    bundles, bundle_fields = read_csv(
        os.path.join(base, "ext_telecom_asmvm_evidence_bundle.csv"))
    reproduced = {b["bundle_id"]: sorted(
        {r["target_ip"] for r in live_receipts}) for b in bundles
        if b["source_file"] in src_files}
    for b in bundles:
        if b["bundle_id"] in reproduced:
            manifest["bundle_flips"].append({
                "bundle_id": b["bundle_id"],
                "source_file": b["source_file"],
                "has_live_fire_before": b["has_live_fire"],
                "reproduced_ips": reproduced[b["bundle_id"]],
            })
            b["has_live_fire"] = "true"
            b["has_receipt"] = "true"

    # ---- R2: the capture itself as a bundle
    lb = {k: "" for k in bundle_fields}
    lb.update({
        "run_id": args.run_id, "engagement_id": args.engagement_id,
        "accept_event_id": "00000000-0000-0000-0000-000000000000",
        "bundle_id": "livefire-%s" % args.livefire_run_id,
        "project_id": args.engagement_id,
        "source_lane": "reachability",
        "has_report": "true", "has_receipt": "true",
        # R2 + R6: receipts always exist; live fire is only true when one of
        # them observed an address the feeds describe.
        "has_live_fire": "true" if live_receipts else "false",
        "has_adversarial_reverify": "false", "is_sandboxed": "true",
        "audit_year": "2026", "source_system": RUN_ANNOTATION,
        "source_file": os.path.basename(args.receipts),
        "source_row_id": "1-%d" % len(receipts),
        "record_hash": md5("livefire-bundle", args.livefire_run_id),
        "lineage_batch_id": args.livefire_run_id,
        "mapping_version": "asmvm-fit-1-livefire",
        "model_version": "fit-1",
    })
    bundles.append(lb)
    manifest["added_rows"].append({"table": "evidence_bundle",
                                  "row": lb, "justification": "R2"})
    write_csv(os.path.join(out, "ext_telecom_asmvm_evidence_bundle.csv"),
              bundles, bundle_fields)

    # ---- R3: service_endpoint, one row per receipt (incl. negative receipts)
    se_path = os.path.join(base, "ext_telecom_asmvm_service_endpoint.csv")
    se_rows, se_fields = read_csv(se_path)
    se_baseline_len = len(se_rows)
    for i, r in enumerate(receipts, start=1):
        if (receipt_class[id(r)] == LAB_FIXTURE
                and not args.allow_lab_fixture_live_fire):
            manifest["skipped"].append({
                "table": "service_endpoint", "rule": "R6", "key": "%s:%s/%s" % (
                    r["target_ip"], r["proto"], r["port"]),
                "endpoint_status": r["endpoint_status"],
                "reason": LAB_FIXTURE_SKIP_REASON})
            continue
        active = r["endpoint_status"] in ("open", "answered")
        row = {k: "" for k in se_fields}
        sid = md5("livefire", args.livefire_run_id, r["target_ip"],
                  r["proto"], r["port"])
        row.update({
            "run_id": args.run_id, "engagement_id": args.engagement_id,
            "accept_event_id": "00000000-0000-0000-0000-000000000000",
            "service_endpoint_id": sid,
            "service_id": "livefire-svc-" + sid[:16],
            "ip": r["target_ip"],
            "service_name": "%s at %s:%s/%s" % (
                classify(r["port"], r["proto"], r["endpoint_status"],
                         r["banner"], r["tls_protocol"]),
                r["target_ip"], r["port"], r["proto"]),
            "service_type": classify(r["port"], r["proto"], r["endpoint_status"],
                                     r["banner"], r["tls_protocol"]),
            "port": r["port"], "protocol": r["proto"],
            "is_active": "true" if active else "false",
            "inferred_vuln_score": "",
            "inferred_cves": "",
            "product_version": product_version(r),
            "audit_year": "2026", "source_system": RUN_ANNOTATION,
            "source_file": os.path.basename(args.receipts),
            "source_row_id": str(i), "record_hash": sid,
            "lineage_batch_id": args.livefire_run_id,
            "mapping_version": "asmvm-v1-livefire-" + receipt_class[id(r)],
            "model_version": "livefire-1",
        })
        se_rows.append(row)
        manifest["added_rows"].append({
            "table": "service_endpoint", "justification": "R3",
            "key": "%s:%s/%s" % (r["target_ip"], r["proto"], r["port"]),
            "endpoint_status": r["endpoint_status"], "is_active": row["is_active"],
            "observation_class": receipt_class[id(r)]})
    write_csv(os.path.join(out, "ext_telecom_asmvm_service_endpoint.csv"),
              se_rows, se_fields)
    manifest["service_endpoint_rows_added"] = len(se_rows) - se_baseline_len

    # ---- R4: asm_vm_surface, reconcile-or-append
    sv_path = os.path.join(base, "ext_telecom_asmvm_asm_vm_surface.csv")
    sv_rows, sv_fields = read_csv(sv_path)
    by_ip = {r["ip"]: r for r in sv_rows}
    per_ip = {}
    for r in receipts:
        per_ip.setdefault(r["target_ip"], []).append(r)
    for ip, recs in sorted(per_ip.items()):
        open_recs = [r for r in recs
                     if r["endpoint_status"] in ("open", "answered")]
        owned = inside_owned(nets, ip)
        classes = {receipt_class[id(r)] for r in recs}
        if classes == {LAB_FIXTURE} and not args.allow_lab_fixture_live_fire:
            # R6: our own fixture is not an asset of the estate. Recording it in
            # asm_vm_surface would give every per-prefix COUNT(*) a host that
            # belongs to us, so it is skipped here and kept in the manifest. The
            # reason string is shared with the R3/R5 skips so one grep finds all
            # three and each one names the override.
            manifest["skipped"].append({
                "table": "asm_vm_surface", "key": ip, "rule": "R6",
                "reason": LAB_FIXTURE_SKIP_REASON,
                "receipts": ["%s/%s=%s" % (r["proto"], r["port"],
                                           r["endpoint_status"]) for r in recs]})
            continue
        # Only OBSERVATION columns are patched onto an existing spine row: the
        # vendor provenance columns (source_system / source_file / source_row_id
        # / lineage_batch_id) keep pointing at the export the spine row came
        # from, and the live-fire channel is recorded in seen_via plus in the
        # service_endpoint rows this capture adds.
        patch = {
            "has_active_service": "true" if open_recs else "false",
            "asm_exposed_services": str(len(open_recs)),
            "seen_via": "live_fire" if open_recs else "live_fire_probe_only",
        }
        if ip in by_ip:
            row = by_ip[ip]
            # Reconciled spine row keeps its VENDOR provenance (source_system /
            # source_file / source_row_id / lineage_batch_id point at the export
            # the spine row came from). Only observations change; the live-fire
            # channel is recorded in seen_via and in service_endpoint rows.
            before = {k: row.get(k) for k in
                      ("has_active_service", "asm_exposed_services", "seen_via")}
            row["has_active_service"] = "true" if (
                row.get("has_active_service") == "true" or open_recs) else "false"
            row["asm_exposed_services"] = str(max(
                int(row.get("asm_exposed_services") or 0), len(open_recs)))
            if "live_fire" not in (row.get("seen_via") or ""):
                row["seen_via"] = (row.get("seen_via") or "") + "+live_fire"
            manifest["patched_rows"].append({
                "table": "asm_vm_surface", "key": ip, "before": before,
                "after": {k: row.get(k) for k in patch},
                "justification": "R4 reconcile (spine is one row per IP)",
                "receipts": ["%s/%s=%s" % (r["proto"], r["port"],
                                           r["endpoint_status"]) for r in recs]})
        else:
            row = {k: "" for k in sv_fields}
            addr = ipaddress.ip_address(ip)
            row.update({
                "run_id": args.run_id, "engagement_id": args.engagement_id,
                "accept_event_id": "00000000-0000-0000-0000-000000000000",
                "ip": ip, "ip_bigint": str(int(addr)),
                "prefix_16": str(ipaddress.ip_network(
                    "%s/16" % ip, strict=False)),
                "prefix_24": str(ipaddress.ip_network(
                    "%s/24" % ip, strict=False)),
                "has_active_service": "true" if open_recs else "false",
                "inside_owned_range": "true" if owned else "false",
                "in_vm_estate": "false",
                "vm_open_findings": "0", "vm_open_critical": "0",
                "asm_inferred_cves": "0", "asm_active_alerts": "0",
                "asm_high_alerts": "0",
                "asm_exposed_services": str(len(open_recs)),
                "asm_exposed_websites": "0",
                "seen_via": "live_fire,service" if open_recs else "live_fire",
                "audit_year": "2026", "source_system": RUN_ANNOTATION,
                "source_file": os.path.basename(args.receipts),
                "source_row_id": str(
                    LIVEFIRE_SOURCE_ROW_BASE + len(manifest["added_rows"])),
                "record_hash": md5("livefire-surface", ip),
                "lineage_batch_id": args.livefire_run_id,
                "mapping_version": "asmvm-v1-livefire",
                "model_version": "livefire-1",
            })
            sv_rows.append(row)
            manifest["added_rows"].append({
                "table": "asm_vm_surface", "justification": "R4 append",
                "key": ip, "has_active_service": row["has_active_service"],
                "inside_owned_range": row["inside_owned_range"],
                "prefix_24": row["prefix_24"]})
    write_csv(os.path.join(out, "ext_telecom_asmvm_asm_vm_surface.csv"),
              sv_rows, sv_fields)

    # ---- R5: website_endpoint for HTTP(S) receipts
    we_path = os.path.join(base, "ext_telecom_asmvm_website_endpoint.csv")
    we_rows, we_fields = read_csv(we_path)
    we_added = 0
    for i, r in enumerate(receipts, start=1):
        if r["endpoint_status"] not in ("open", "answered"):
            continue
        if not (r["http_status"] or r["tls_protocol"]):
            continue
        if (receipt_class[id(r)] == LAB_FIXTURE
                and not args.allow_lab_fixture_live_fire):
            manifest["skipped"].append({
                "table": "website_endpoint", "rule": "R6", "key": "%s:%s/%s" % (
                    r["target_ip"], r["proto"], r["port"]),
                "endpoint_status": r["endpoint_status"],
                "reason": LAB_FIXTURE_SKIP_REASON})
            continue
        row = {k: "" for k in we_fields}
        wid = md5("livefire-web", args.livefire_run_id, r["target_ip"],
                  r["proto"], r["port"])
        row.update({
            "run_id": args.run_id, "engagement_id": args.engagement_id,
            "accept_event_id": "00000000-0000-0000-0000-000000000000",
            "website_endpoint_id": wid,
            "website_id": "livefire-web-" + wid[:16],
            "ip": r["target_ip"], "host": r["target_ip"], "port": r["port"],
            "is_active": "true",
            "http_type": "HTTPS" if r["tls_protocol"] else "HTTP Only",
            "has_failed_assessment": "",
            "failed_security_assessments": "",
            "inferred_cves": "",
            "audit_year": "2026", "source_system": RUN_ANNOTATION,
            "source_file": os.path.basename(args.receipts),
            "source_row_id": str(i), "record_hash": wid,
            "lineage_batch_id": args.livefire_run_id,
            "mapping_version": "asmvm-v1-livefire", "model_version": "livefire-1",
        })
        we_rows.append(row)
        we_added += 1
        manifest["added_rows"].append({"table": "website_endpoint",
                                       "justification": "R5",
                                       "key": "%s:%s" % (r["target_ip"],
                                                         r["port"])})
    write_csv(os.path.join(out, "ext_telecom_asmvm_website_endpoint.csv"),
              we_rows, we_fields)
    manifest["website_endpoint_rows_added"] = we_added

    # ---- every other CSV is linked in unchanged (identical bytes)
    patched = {"ext_telecom_asmvm_evidence_bundle.csv",
               "ext_telecom_asmvm_service_endpoint.csv",
               "ext_telecom_asmvm_asm_vm_surface.csv",
               "ext_telecom_asmvm_website_endpoint.csv"}
    for name in sorted(os.listdir(base)):
        if not name.endswith(".csv") or name in patched:
            continue
        dst = os.path.join(out, name)
        if os.path.exists(dst):
            os.remove(dst)
        try:
            os.link(os.path.join(base, name), dst)
        except OSError:
            shutil.copy2(os.path.join(base, name), dst)

    with open(os.path.join(out, "livefire_overlay_manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    print(json.dumps({
        "receipts": len(receipts),
        "bundle_flips": [f["bundle_id"] for f in manifest["bundle_flips"]],
        "bundles_total": len(bundles),
        "receipts_dataset_endpoints": manifest["receipts_dataset_endpoints"],
        "receipts_lab_fixtures": manifest["receipts_lab_fixtures"],
        "has_live_fire": manifest["has_live_fire"],
        "has_live_fire_reason": manifest["has_live_fire_reason"],
        "asm_vm_surface_skipped_lab_fixtures": [
            s["key"] for s in manifest["skipped"]
            if s.get("table") == "asm_vm_surface"],
        "service_endpoint_rows_added": manifest["service_endpoint_rows_added"],
        "website_endpoint_rows_added": we_added,
        "asm_vm_surface_patched": [p["key"] for p in manifest["patched_rows"]
                                   if p["table"] == "asm_vm_surface"],
        "asm_vm_surface_added": [a["key"] for a in manifest["added_rows"]
                                 if a["table"] == "asm_vm_surface"],
        "owned_range_check": {ip: inside_owned(nets, ip)
                              for ip in sorted(per_ip)},
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
