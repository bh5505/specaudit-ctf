#!/usr/bin/env python3
"""Indirect recon over the pack's own evidence: corroborate ASM service claims
without sending a packet.

The reproduction queue in this pack is long because nothing outside the two
feeds ever checked the ASM's claims. Active checking means traffic to hosts that
belong to whoever the ASM is describing, which is not ours to probe. Most of the
question can still be asked with data we already hold plus knowledge that is
local to this machine:

1. the VM/vulnerability feed reports ports it saw on the same IP - an
   independent sensor of the same estate, already in the pack's tables;
2. this machine's local services file says what a port is normally used for -
   read from the file, not looked up, so nothing leaves the host;
3. the pack's own port classes (telecom control plane, management ports) say
   what kind of exposure a port would be if the claim is right.

Combining them answers, per claimed endpoint: does another sensor in our data
agree that this port is open, and does the service name the ASM attached match
what this port normally carries? A disagreement is a real audit finding - either
a mislabelled service or a non-standard listener - and it costs zero packets.

What it does NOT do: it is not live fire and not independent *active*
reproduction. The receipt says `packets_sent: 0` and the summary names the
gates it does not satisfy, so nobody can mistake the tallies for reproduction.

Usage:
    python tools/indirect_recon.py --evidence-dir DIR --out-dir DIR [--run-id ID]

Writes:
    <out>/indirect_recon_receipts.csv   one row per claimed endpoint
    <out>/indirect_recon_summary.json   tallies, disagreements, caveats
"""
import argparse
import csv
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict

RECON_VERSION = "indirect-recon-1"
EVIDENCE_CLASS = "indirect_dataset_and_local_registry"
PACKETS_SENT = 0

# Mirrors the pack's port classes (the pack's engagement_configs/default.yaml).
# Kept as data here so the tool can run against an exported evidence directory;
# the pack's config stays authoritative - change it there and here, and the
# class names are asserted in the smoke tests so drift shows up as a failure.
TELECOM_PORT_CLASS = {
    2123: "gtp_core", 2152: "gtp_core", 3386: "gtp_core",
    7547: "cpe_management",
    2905: "signalling", 2904: "signalling", 2901: "signalling",
    123: "timing",
    53: "resolver",
    500: "vpn_anchor", 4500: "vpn_anchor",
}
MANAGEMENT_PORTS = {22, 23, 53, 161, 389, 1521, 3306, 3389, 5432, 5900, 7680,
                    9200, 27017}

# Ports this platform's services file does not know but whose assignment is
# not in doubt, with where the name comes from. Nothing here is looked up at
# runtime; it is a table, so the run is reproducible on a host with no
# services file at all.
KNOWN_UNREGISTERED = {
    2123: ("gtp-c2", "3GPP TS 29.060 (GTP-C, Gn/Gp)"),
    2152: ("gtpu", "3GPP TS 29.281 (GTP-U, N3/N9/Tnl)"),
    3386: ("gtp", "3GPP TS 29.060 (GTP', Sm/Gp)"),
    2905: ("m3ua", "RFC 4666 (MTP3 user adaptation)"),
    2904: ("m2pa", "RFC 4165 (MTP2 peer adaptation)"),
    2901: ("smsc", "common signalling-gateway assignment"),
    7547: ("cwmp", "TR-069 CPE WAN Management Protocol"),
    7510: ("satp", "SATP-Message"),
    4123: ("cisco-tps", "Cisco TPS"),
    830: ("netconf-be", "RFC 6242 (NETCONF over SSH)"),
    8342: ("abstraction", "RFC 6243 (NETCONF with EXI)"),
}


def services_file_paths():
    """Local services files, in the order the platform would read them."""
    if os.name == "nt":
        windir = os.environ.get("WINDIR", r"C:\\Windows")
        return [os.path.join(windir, "System32", "drivers", "etc", "services")]
    return ["/etc/services"]


def load_local_services():
    """port -> (canonical name, sorted aliases), from the local services file.

    Parsed here rather than through socket.getservbyport so the result cannot
    depend on a name service, and so a miss means "not in the file" instead of
    "the resolver did something".
    """
    by_port = {}
    for path in services_file_paths():
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2 or "/" not in parts[1]:
                    continue
                name, portproto = parts[0], parts[1]
                port_text = portproto.split("/", 1)[0]
                try:
                    port = int(port_text)
                except ValueError:
                    continue
                aliases = [p for p in parts[2:] if "/" in p]
                aliases = [a.split("/", 1)[0] for a in aliases]
                current = by_port.setdefault(port, (name, set()))
                current[1].update(aliases)
                current[1].add(name)
    return by_port



    if port in TELECOM_PORT_CLASS:
        return TELECOM_PORT_CLASS[port]
    if port in MANAGEMENT_PORTS:
        return "management_port"
    return "other"


def classify(port):
    if port in TELECOM_PORT_CLASS:
        return TELECOM_PORT_CLASS[port]
    if port in MANAGEMENT_PORTS:
        return "management_port"
    return "other"


# Names that mean the same service for this comparison, so that "http" on 443
# (HTTP inside TLS) is not reported as a contradiction, and neither is the
# vendor spelling of a database.
SERVICE_EQUIVALENCE = [
    {"http", "https", "www", "http-alt", "https-alt", "ssl/http", "world-wide-web"},
    {"ssh", "secure-shell", "sftp-ssh"},
    {"smtp", "smtps", "submission", "mail"},
    {"dns", "domain"},
    {"ntp", "ntdp", "ntp-mon"},
    {"snmp", "snmptrap"},
    {"rdp", "ms-wbt-server", "termserver", "xrdp", "ms-wbt-server-2"},
    {"vnc", "rfb", "vnc-server", "vnc-http"},
    {"mysql", "msql", "mysql-alias"},
    {"mssql", "ms-sql-s", "ms-sql-server", "sqlserver", "sql-server"},
    {"postgresql", "postgres"},
    {"redis", "redis-server"},
    {"mongodb", "mongo", "mongodb-27017"},
    {"elasticsearch", "elastic"},
    {"ldap", "ldaps", "globalcatldap", "ldapssl"},
    {"ftp", "ftp-data", "ftps"},
    {"syslog", "syslog-tls"},
    {"gtp-c2", "gtpv2-c", "gtp", "gtpu"},
    {"cwmp", "tr-069", "cpe-wan-management"},
    {"m3ua", "sua", "m2pa", "sigtran"},
    {"ipsec", "isakmp", "ike", "natt", "ipsec-nat-t"},
    {"winrm", "wsman", "http", "https"},
]


def claim_tokens(claim):
    """Service-ish words out of an ASM service_name claim.

    These fields carry banner prose ("http server at api.internal:443"), not
    service tokens. Hostname-ish tokens (containing a dot) and bare numbers are
    dropped: they say where, not what.
    """
    tokens = []
    for raw in re.split(r"[^0-9A-Za-z+./_-]+", (claim or "").lower()):
        token = raw.strip("-_.")
        if not token or token.isdigit():
            continue
        if "." in token and not token.startswith(("ms-sql", "ms-wbt", "ssl/")):
            continue
        tokens.append(token)
    return tokens


def label_agreement(port, claim, known_names):
    """agree | agree_by_equivalent_name | label_disagreement | claim_not_comparable.

    Deliberately conservative about calling a contradiction: prose that names the
    right service (or an accepted equivalent) is agreement, and only a claim that
    actually names a service and names a different one is a disagreement - a
    wrong disagreement sends an auditor to a port that is fine.
    """
    tokens = claim_tokens(claim)
    if not tokens:
        return "no_claim"
    if not known_names:
        return "no_local_reference"
    names = {str(n).replace(" ", "-").lower() for n in known_names}
    token_set = set(tokens)
    if token_set & names:
        return "agree"
    # One group has to contain both the claimed name and the port's name; two
    # unrelated groups (the claim says ftp, the port carries cwmp) must not be
    # unioned into agreement.
    for group in SERVICE_EQUIVALENCE:
        if (token_set & group) and (names & group):
            return "agree_by_equivalent_name"
    prose = (" at " in (claim or "").lower()) or len(tokens) > 2
    if len(tokens) == 1 and not prose:
        return "label_disagreement"
    return "claim_not_comparable"


def table_file(evidence_dir, table):
    """Find a table's CSV: bare `<table>.csv` or a pack-prefixed export.

    Evidence directories come out of the pack loader with the pack's table
    prefix (`ext_telecom_asmvm_service_endpoint.csv`); hand-built and exported
    directories often use the bare name. Both are accepted rather than
    hardcoding one pack's prefix into the tool.
    """
    direct = os.path.join(evidence_dir, table + ".csv")
    if os.path.exists(direct):
        return direct
    matches = sorted(f for f in os.listdir(evidence_dir)
                     if f.endswith("_" + table + ".csv"))
    return os.path.join(evidence_dir, matches[0]) if matches else direct


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def index_vm_ports(rows):
    """ip -> {port: open finding count} from the VM feed.

    The VM feed is a different sensor from the ASM: credentialed/agent scanning
    of the estate. When it reports the same port on the same IP, that is
    corroboration we already own. Findings can carry port 0 or an empty port
    (not a per-port finding); those say nothing about a port and are ignored.
    """
    out = defaultdict(dict)
    for row in rows:
        ip = (row.get("ip") or "").strip()
        port_text = (row.get("port") or "").strip()
        if not ip or not port_text:
            continue
        try:
            port = int(float(port_text))
        except ValueError:
            continue
        if port <= 0:
            continue
        open_flag = str(row.get("is_open") or "").strip().lower()
        if open_flag in ("false", "0", "no", ""):
            continue
        out[ip][port] = out[ip].get(port, 0) + 1
    return out


def assess_endpoint(row, services, vm_ports):
    ip = (row.get("ip") or "").strip()
    try:
        port = int(float(row.get("port")))
    except (TypeError, ValueError):
        return None
    protocol = ((row.get("protocol") or "tcp").strip().lower() or "tcp")
    claim = (row.get("service_name") or "").strip().lower()
    entry = services.get(port)
    known_names = set(entry[1]) if entry else set()
    if port in KNOWN_UNREGISTERED:
        known_names.add(KNOWN_UNREGISTERED[port][0])
    label = label_agreement(port, claim, known_names)

    ports = vm_ports.get(ip, {})
    if port in ports:
        corroboration = "vm_feed_same_port"
    elif ports:
        corroboration = "vm_feed_same_ip_other_port"
    else:
        corroboration = "no_vm_feed_observation"

    return {
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "asm_service_name": claim,
        "asm_service_type": (row.get("service_type") or "").strip(),
        "local_reference_names": "|".join(sorted(known_names)),
        "label_agreement": label,
        "port_class": classify(port),
        "vm_corroboration": corroboration,
        "vm_open_findings_on_port": ports.get(port, 0),
        "product_version_claim": (row.get("product_version") or "").strip()[:120],
        "source_system": (row.get("source_system") or "").strip(),
        "packets_sent": PACKETS_SENT,
        "evidence_class": EVIDENCE_CLASS,
        "recon_version": RECON_VERSION,
    }


def run(evidence_dir, out_dir, run_id=None, limit=None):
    endpoints = read_csv(table_file(evidence_dir, "service_endpoint"))
    vm_rows = read_csv(table_file(evidence_dir, "vm_finding"))
    if run_id is None:
        run_ids = {r.get("run_id") for r in endpoints if r.get("run_id")}
        run_id = sorted(run_ids)[0] if run_ids else "indirect-recon"
    if run_id != "indirect-recon":
        endpoints = [r for r in endpoints if r.get("run_id") == run_id]
        vm_rows = [r for r in vm_rows if r.get("run_id") == run_id]
    if limit:
        endpoints = endpoints[:limit]

    services = load_local_services()
    vm_ports = index_vm_ports(vm_rows)

    seen = set()
    receipts = []
    for row in endpoints:
        key = (row.get("ip"), row.get("port"), row.get("protocol"),
               (row.get("service_name") or "").strip().lower())
        if key in seen:
            continue
        seen.add(key)
        receipt = assess_endpoint(row, services, vm_ports)
        if receipt is not None:
            receipt["run_id"] = run_id
            receipts.append(receipt)

    label_tally = Counter(r["label_agreement"] for r in receipts)
    class_tally = Counter(r["port_class"] for r in receipts)
    corroboration = Counter(r["vm_corroboration"] for r in receipts)
    disagreements = Counter((r["port"], r["asm_service_name"]) for r in receipts
                            if r["label_agreement"] == "label_disagreement")
    control_plane = [r for r in receipts
                     if r["port_class"] in set(TELECOM_PORT_CLASS.values())]

    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, "indirect_recon_receipts.csv")
    if receipts:
        with open(csv_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(receipts[0].keys()))
            writer.writeheader()
            writer.writerows(receipts)
    else:
        with open(csv_path, "w", encoding="utf-8", newline="") as fh:
            fh.write("run_id,ip,port,protocol,no_endpoints\n")

    summary = {
        "recon_version": RECON_VERSION,
        "run_id": run_id,
        "evidence_dir": evidence_dir,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": ("ASM service_endpoint claims vs (a) the VM feed's own port "
                   "observations in the same pack, (b) this host's local "
                   "services file, (c) the pack's port classes"),
        "endpoints_examined": len(receipts),
        "distinct_ips": len({r["ip"] for r in receipts}),
        "label_agreement_tally": dict(label_tally),
        "port_class_tally": dict(class_tally),
        "vm_corroboration_tally": dict(corroboration),
        "control_plane_endpoints": len(control_plane),
        "top_label_disagreements": [
            {"port": p, "asm_service_name": n, "endpoints": c}
            for (p, n), c in disagreements.most_common(20)],
        "label_agreement_means": {
            "agree": "the claim names the service this port normally carries",
            "agree_by_equivalent_name": "the claim names an accepted equivalent "
                                        "(http on 443, rdp on 3389, winrm on 7680)",
            "label_disagreement": "the claim names one service and this port "
                                  "normally carries another - audit candidate",
            "claim_not_comparable": "the claim is banner prose that does not name "
                                    "a service we can compare against",
            "no_local_reference": "this host's services file does not know the "
                                  "port and it is not in the known-unregistered "
                                  "table",
            "no_claim": "the ASM row carries no service name at all",
        },
        "local_services_files": [p for p in services_file_paths()
                                 if os.path.exists(p)],
        "local_services_ports_known": len(services),
        "packets_sent": PACKETS_SENT,
        "evidence_class": EVIDENCE_CLASS,
        "does_not_satisfy": {
            "live_fire": "no observation of the endpoint was made; nothing was "
                         "sent to it",
            "independent_active_reproduction": "the second sensor is another "
                                               "dataset (the VM feed), not a new "
                                               "observation",
            "adversarial_reverify": "no new observation to re-verify",
        },
        "what_it_does_tell_you": "which ASM service claims another sensor in our "
                                 "own data agrees about, and where a service "
                                 "label does not match what the port normally "
                                 "carries - the mislabel and non-standard-"
                                 "listener candidates, at zero egress",
    }
    with open(os.path.join(out_dir, "indirect_recon_summary.json"), "w",
              encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args(argv)
    summary = run(args.evidence_dir, args.out_dir, args.run_id, args.limit)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
