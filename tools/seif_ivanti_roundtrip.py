#!/usr/bin/env python3
"""SEIF round-trip on the Ivanti Neurons export: DuckDB export -> SEIF -> pack table.

Question this answers (ASM/VM fit-test task 5): if the Ivanti VM/RBVM evidence
enters the pack *through SEIF* instead of the bespoke CSV the pack was built
against, what survives the trip? "Round-trip works" is only meaningful as a
per-column statement, so this measures it:

  1. EXPORT   read the Ivanti export (DuckDB) and write a vendor-shaped CSV whose
              headers are the aliases the SEIF Ivanti converter
              (seif/converters/ivanti_neurons.py) looks for. Columns the pack's
              own mapping spec (synthetic/mapping_spec.yaml) also accepts are
              carried too, so the same file can go both ways.
  2. CONVERT  run `seif-convert --format ivanti-neurons` (subprocess, the shipped
              CLI) and count what it dropped (map_row() returns None when
              finding_id or title is empty).
  3. VALIDATE run the shipped validator (seif.tools.validate_seif).
  4. PROJECT  project the SEIF findings back into the pack's
              ext_telecom_asmvm_vm_finding column set, using ONLY what SEIF
              carried. Two variants:
                A (faithful)  Tags column = the export's real Tags column, which
                              is what the converter actually sees. pluginFamily /
                              qid / port / protocol have no SEIF field and are
                              therefore empty in the projection - that is the
                              loss, measured, not argued.
                B (smuggled)  Tags column = pluginFamily, i.e. the vendor field
                              pushed through SEIF's free-form details.tags, and
                              recovered in the projection.
  5. DIFF     join the projection against the pack's own vm_finding table on
              finding_id and compare ip / title / severity / is_open /
              plugin_family / qid / port, plus CVE coverage
              (details.Vulnerabilities[].Id vs ext_telecom_asmvm_vm_cve_finding).

Sampling is deterministic (DuckDB USING SAMPLE ... REPEATABLE(seed)).

Usage:
  SEIF_SRC=/path/to/seif/src python tools/seif_ivanti_roundtrip.py \
      --export-db <ivanti export duckdb> --out-dir <outdir> \
      --sample 25000 --seed 42 --pack-evidence <pack evidence dir>
"""

import argparse
import csv
import importlib.util
import io
import json
import os
import subprocess
import sys
import time

import duckdb

def _raise_csv_cap():
    """Raise Python's CSV field cap (vendor exports carry >128 KB fields).

    sys.maxsize overflows the C long on Windows (32-bit long), so ladder down.
    """
    for cap in (sys.maxsize, 2 ** 31 - 1, 10 ** 9, 10 ** 7):
        try:
            csv.field_size_limit(cap)
            return cap
        except (OverflowError, ValueError):
            continue
    return None


_RAISED_CAP = _raise_csv_cap()

SEIF_SRC = os.environ.get("SEIF_SRC", "")    # seif source tree (src dir)
if SEIF_SRC not in sys.path:
    sys.path.insert(0, SEIF_SRC)

# Pack target columns (order = ext_telecom_asmvm_vm_finding DDL order).
VM_FINDING_COLUMNS = [
    "run_id", "engagement_id", "accept_event_id", "finding_id", "ip", "title",
    "qid", "plugin_family", "port", "protocol", "severity", "risk_rating",
    "status", "is_open", "last_found_ts", "resolved_ts", "scanner",
    "audit_year", "source_system", "source_file", "source_row_id",
    "record_hash", "lineage_batch_id", "mapping_version", "model_version",
]

# Vendor header names, chosen so BOTH the SEIF Ivanti converter's alias table and
# the pack mapping spec resolve them. "Severity" is the textual risk label the
# converter keeps only as details.original_severity; the score itself rides the
# "VRR" alias, which the converter turns into SEIF severity + details.vrr.
EXPORT_SQL = """
COPY (
    SELECT 'ivanti-finding-' || CAST(f.id AS VARCHAR)       AS "Finding ID",
           f.host_ip                                        AS "IP Address",
           CAST(f.host_id AS VARCHAR)                       AS "Asset ID",
           f.title                                          AS "Title",
           f.description                                    AS "Description",
           f.severity                                       AS "VRR",
           CASE WHEN f.scannerSeverity >= 9 THEN 'Critical'
                WHEN f.scannerSeverity >= 7 THEN 'High'
                WHEN f.scannerSeverity >= 4 THEN 'Medium'
                WHEN f.scannerSeverity >= 1 THEN 'Low'
                ELSE 'Informational' END                    AS "Severity",
           f.status                                         AS "Status",
           CASE WHEN COALESCE(f.manualExploitCount, 0) > 0
                THEN 'Yes' ELSE 'No' END                     AS "Exploit Available",
           {tags}                                           AS "Tags",
           f.pluginFamily                                   AS "pluginFamily",
           f.scannerName                                    AS "scannerName",
           f.source                                         AS "source",
           CAST(f.port AS VARCHAR)                          AS "port",
           f.protocol                                       AS "protocol",
           f.network                                        AS "network",
           CAST(f.sourceId AS VARCHAR)                      AS "Qualifier ID",
           CAST(f.discoveredOn AS VARCHAR)                   AS "discoveredOn",
           CAST(f.lastFoundOn AS VARCHAR)                    AS "lastFoundOn",
           f.sourceId                                       AS "_pack_source_row_id",
           f.vulnerabilities                                AS "_pack_vulnerabilities_json"
    FROM findings f {sample}
) TO '{path}' (HEADER, DELIMITER ',');
"""


def sh(cmd, cwd=None):
    print("$ " + " ".join(cmd), flush=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = (SEIF_SRC + os.pathsep + env.get("PYTHONPATH", "")).strip(os.pathsep)
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    return p


def step_export(db, path, sample, seed, tags_expr, out):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    sample_sql = ("" if not sample else
                  "USING SAMPLE RESERVOIR(%d ROWS) REPEATABLE(%d)"
                  % (sample, seed))
    sql = EXPORT_SQL.format(path=path.replace("\\", "/"), sample=sample_sql,
                            tags=tags_expr)
    con = duckdb.connect(db, read_only=True)
    t0 = time.time()
    full = con.execute("""SELECT count(*), count(DISTINCT host_ip),
                       count(*) FILTER (WHERE status = 'Open'),
                       count(*) FILTER (WHERE severity >= 9.0),
                       count(*) FILTER (WHERE findingType IS NOT NULL),
                       /* the export carries two severity axes: the vendor's
                          scannerSeverity label and the numeric VRR. SEIF keeps
                          the score-derived band (details.original_severity keeps
                          the label), so measure how often they disagree. */
                       count(*) FILTER (WHERE
                          (CASE WHEN scannerSeverity >= 9 THEN 'critical'
                                WHEN scannerSeverity >= 7 THEN 'high'
                                WHEN scannerSeverity >= 4 THEN 'medium'
                                WHEN scannerSeverity >= 1 THEN 'low'
                                ELSE 'info' END)
                          <> (CASE WHEN severity >= 9 THEN 'critical'
                                   WHEN severity >= 7 THEN 'high'
                                   WHEN severity >= 4 THEN 'medium'
                                   WHEN severity > 0 THEN 'low'
                                   ELSE 'info' END)),
                       count(*) FILTER (WHERE COALESCE(len(vulnerabilities), 0) > 0)
                       FROM findings""").fetchone()
    # Reservoir+seed is reproducible for a fixed file/version/thread count; say
    # so in the report instead of assuming it.
    digest_sql = ("SELECT count(*), md5(string_agg(CAST(id AS VARCHAR), ',' "
                  "ORDER BY CAST(id AS VARCHAR))) FROM (SELECT DISTINCT id "
                  "FROM findings " + sample_sql + ")")
    rep_a = con.execute(digest_sql).fetchone()
    rep_b = con.execute(digest_sql).fetchone()
    con.execute(sql)
    # count with the CSV reader, not line count: Ivanti descriptions and the
    # `vulnerabilities` JSON blob contain embedded newlines.
    with io.open(path, encoding="utf-8", newline="") as fh:
        rdr = csv.reader(fh)
        next(rdr, None)
        n = sum(1 for _ in rdr)
    blob = con.execute("SELECT max(len(vulnerabilities)), count(*) FILTER "
                       "(WHERE len(vulnerabilities) > 131072) FROM findings"
                       ).fetchone()
    con.close()
    out["source_field_sizes"] = {
        "vulnerabilities_max_len": blob[0],
        "rows_over_python_csv_default_field_limit_131072": blob[1],
        "note": ("seif's converter uses csv.DictReader with Python's default "
                 "131072-byte field limit, so the real Ivanti export cannot be "
                 "read without raising the limit; see convert_* fields")}
    out["export"] = {"db": db, "csv": path, "rows_written": n,
                     "export_full_rows": full[0], "export_full_ips": full[1],
                     "export_full_open": full[2], "export_full_critical": full[3],
                     "export_full_severity_axes_disagree": full[5],
                     "export_full_rows_with_vulnerabilities_json": full[6],
                     "seconds": round(time.time() - t0, 1),
                     "sample_rows": sample, "seed": seed,
                     "sample_id_digest_run1": rep_a[1],
                     "sample_id_digest_run2": rep_b[1],
                     "sample_reproducible": rep_a == rep_b}
    print("export: %d rows (full export has %d) in %.1fs"
          % (n, full[0], time.time() - t0), flush=True)
    return n


def _wrapper(path):
    """shim that raises Python's CSV field cap, then execs the shipped CLI.

    Needed because seif/converters/ivanti_neurons.py reads the export with
    csv.DictReader at the default 131072-byte field limit, and the real Ivanti
    export has `vulnerabilities` blobs up to ~485 KB. Without the shim the
    shipped CLI exits 1 with 'error: field larger than field limit (131072)' -
    recorded in the report as the as-shipped result.
    """
    with io.open(path, "w", encoding="utf-8") as fh:
        fh.write("import csv, sys\n"
                 "for _cap in (sys.maxsize, 2 ** 31 - 1, 10 ** 9, 10 ** 7):\n"
                 "    try:\n"
                 "        csv.field_size_limit(_cap)\n"
                 "        break\n"
                 "    except (OverflowError, ValueError):\n"
                 "        continue\n"
                 "from seif.cli import main\n"
                 "raise SystemExit(main())\n")
    return path


def step_convert(csv_path, seif_path, shim_path, label):
    """Run the shipped CLI as-is, then (if it failed on the field cap) again
    through the field-size shim, so the report shows both."""
    t0 = time.time()
    as_shipped = sh([sys.executable, "-m", "seif.cli", csv_path, seif_path,
                     "--format", "ivanti-neurons",
                     "--source", "ivanti_neurons_fit_test"])
    res = {"cmd": " ".join(as_shipped.args), "returncode": as_shipped.returncode,
           "stdout": as_shipped.stdout.strip(),
           "stderr": as_shipped.stderr.strip()[-800:],
           "seconds": round(time.time() - t0, 1)}
    if as_shipped.returncode != 0:
        _wrapper(shim_path)
        t1 = time.time()
        via_shim = sh([sys.executable, shim_path, csv_path, seif_path,
                       "--format", "ivanti-neurons",
                       "--source", "ivanti_neurons_fit_test"])
        res["shim"] = {"cmd": " ".join(via_shim.args),
                       "returncode": via_shim.returncode,
                       "stdout": via_shim.stdout.strip(),
                       "stderr": via_shim.stderr.strip()[-800:],
                       "seconds": round(time.time() - t1, 1)}
    return res


def step_validate(seif_path):
    p = sh([sys.executable, "-m", "seif.tools.validate_seif", seif_path])
    return {"returncode": p.returncode, "stdout": p.stdout.strip()[-1200:],
            "stderr": p.stderr.strip()[-800:]}


def project(seif_path, out_csv, variant, lineage_batch):
    """SEIF findings -> pack vm_finding CSV, using only fields SEIF carried."""
    env = json.load(io.open(seif_path, encoding="utf-8"))
    findings = env.get("findings", [])
    dropped_fields = {"qid": 0, "plugin_family": 0, "port": 0, "protocol": 0,
                      "last_found_ts": 0}
    with io.open(out_csv, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=VM_FINDING_COLUMNS)
        w.writeheader()
        for i, f in enumerate(findings):
            det = f.get("details") or {}
            tags = det.get("tags") or []
            plugin_family = ""
            if variant == "B":
                # variant B smuggled pluginFamily through details.tags
                plugin_family = tags[0] if tags else ""
            vrr = det.get("vrr")
            status = f.get("status") or ""
            if not f.get("last_observed_at"):
                dropped_fields["last_found_ts"] += 1
            dropped_fields["qid"] += 1
            dropped_fields["port"] += 1
            dropped_fields["protocol"] += 1
            w.writerow({
                "run_id": "gw-seif-roundtrip-20260909",
                "engagement_id": "asmvm-rehearsal-2026",
                "accept_event_id": "00000000-0000-0000-0000-000000000000",
                "finding_id": f.get("finding_id"),
                "ip": f.get("resource_uid") or "",
                "title": f.get("title"),
                "qid": "",                       # no SEIF field for it
                "plugin_family": plugin_family,  # '' in variant A - the loss
                "port": "",                      # no SEIF field for it
                "protocol": "",                  # no SEIF field for it
                "severity": "" if vrr is None else vrr,
                "risk_rating": "" if vrr is None else vrr,
                "status": "Open" if status == "active" else
                          ("Closed" if status == "resolved" else status),
                "is_open": "true" if status == "active" else "false",
                "last_found_ts": f.get("last_observed_at") or "",
                "resolved_ts": "",
                "scanner": "QUALYS",
                "audit_year": "2026",
                "source_system": "ivanti_neurons_via_seif",
                "source_file": os.path.basename(seif_path),
                "source_row_id": str(i),
                "record_hash": "",
                "lineage_batch_id": lineage_batch,
                "mapping_version": "seif-roundtrip-1",
                "model_version": "fit-1",
            })
    cves = 0
    for f in findings:
        for v in (f.get("details") or {}).get("Vulnerabilities") or []:
            if v.get("Id"):
                cves += 1
    return {"variant": variant, "rows": len(findings), "csv": out_csv,
            "cve_pairs_in_seif": cves,
            "fields_with_no_seif_home": dropped_fields,
            "findings_with_last_observed_at":
                sum(1 for f in findings if f.get("last_observed_at"))}


def diff_against_pack(baseline_csv, projected_csv, out):
    base = {}
    with io.open(baseline_csv, encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            base[row["finding_id"]] = row
    rows = list(csv.DictReader(io.open(projected_csv, encoding="utf-8", newline="")))
    # Observed, not assumed: the Ivanti converter does NOT prefix resource_uid
    # (no normalize_resource_uid exists) and its alias order is
    # ["Asset ID", "Resource Uid", "IP Address", ...], so with both columns in
    # the export the pack's join key is replaced by the scanner asset id. The
    # prefix strip below is defensive (0 rows needed it here); the real fix is
    # on the ingest side - see seif_variant_c.py.
    for r in rows:
        for pfx in ("ip:", "host:", "private-ip:"):
            if (r.get("ip") or "").startswith(pfx):
                r["ip"] = r["ip"][len(pfx):]
                r["_uid_prefix"] = pfx
                break
        else:
            r["_uid_prefix"] = ""
    ids = {r["finding_id"] for r in rows}
    matched = [r for r in rows if r["finding_id"] in base]
    res = {"baseline_rows": len(base), "projected_rows": len(rows),
           "projected_ids_present_in_baseline": len(matched),
           "projected_ids_missing_from_baseline": len(ids - set(base))}
    fields = ("ip", "title", "severity", "is_open", "plugin_family", "qid",
              "port", "protocol", "last_found_ts")
    agree = dict.fromkeys(fields, 0)
    # fields the pack has but the SEIF round trip did not carry (loss table)
    lost = dict.fromkeys(fields, 0)
    severity_delta = []
    for r in matched:
        b = base[r["finding_id"]]
        for fld in fields:
            pv, bv = (r.get(fld) or "").strip(), (b.get(fld) or "").strip()
            if bv and not pv:
                lost[fld] += 1
            if fld == "severity":
                try:
                    if abs(float(pv) - float(bv)) < 1e-9:
                        agree[fld] += 1
                    else:
                        severity_delta.append((r["finding_id"], pv, bv))
                except ValueError:
                    pass
                continue
            if pv == bv:
                agree[fld] += 1
    res["fields_equal_of_matched"] = agree
    res["fields_baseline_had_value_projection_empty"] = lost
    res["severity_mismatch_examples"] = severity_delta[:5]
    res["resource_uid_prefix_stripped_rows"] = sum(
        1 for r in rows if r["_uid_prefix"])
    res["baseline_ips_in_sample"] = len({base[i]["ip"] for i in ids if i in base})
    res["projected_ips"] = len({r["ip"] for r in rows if r["ip"]})
    # CVE coverage: pack table vs SEIF details.Vulnerabilities
    cve_csv = os.path.join(os.path.dirname(baseline_csv),
                           "ext_telecom_asmvm_vm_cve_finding.csv")
    if os.path.exists(cve_csv):
        keep, total = 0, 0
        with io.open(cve_csv, encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                total += 1
                if row["finding_id"] in ids:
                    keep += 1
        res["pack_cve_rows_total"] = total
        res["pack_cve_rows_for_sampled_findings"] = keep
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-db", required=True,
                    help="Ivanti export DuckDB (findings table)")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--pack-evidence", required=True,
                    help="pack evidence dir whose vm_finding CSV is the baseline")
    ap.add_argument("--sample", type=int, default=25000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--seif-src", default="",
                    help="seif source tree (or $SEIF_SRC); required to convert")
    ap.add_argument("--lineage-batch", default="gw-seif-20260909")
    args = ap.parse_args()
    global SEIF_SRC
    if args.seif_src:
        SEIF_SRC = args.seif_src
    if SEIF_SRC and SEIF_SRC not in sys.path:
        sys.path.insert(0, SEIF_SRC)
    if importlib.util.find_spec("seif") is None:
        raise SystemExit("the converter lives in the seif source tree; pass "
                         "--seif-src <path to seif/src> or set SEIF_SRC")

    out = {"tool": "seif_ivanti_roundtrip", "seif_src": SEIF_SRC}
    os.makedirs(args.out_dir, exist_ok=True)

    # variant A: Tags = the export's real Tags column (what the converter sees)
    csvA = os.path.join(args.out_dir, "ivanti_export_A_findings.csv")
    step_export(args.export_db, csvA, args.sample, args.seed,
                "COALESCE(f.tags, '')", out)
    seifA = os.path.join(args.out_dir, "ivanti_A.seif.json")
    out["convert_A"] = step_convert(
        csvA, seifA, os.path.join(args.out_dir, "seif_cli_shim.py"), "A")
    out["validate_A"] = step_validate(seifA)

    # variant B: Tags = pluginFamily, so a vendor field can ride details.tags
    csvB = os.path.join(args.out_dir, "ivanti_export_B_findings.csv")
    step_export(args.export_db, csvB, args.sample, args.seed,
                "COALESCE(f.pluginFamily, '')", out)
    seifB = os.path.join(args.out_dir, "ivanti_B.seif.json")
    out["convert_B"] = step_convert(
        csvB, seifB, os.path.join(args.out_dir, "seif_cli_shim.py"), "B")
    out["validate_B"] = step_validate(seifB)

    for variant, seif in (("A", seifA), ("B", seifB)):
        proj_csv = os.path.join(args.out_dir,
                                "seif_%s_ext_telecom_asmvm_vm_finding.csv" % variant)
        out["projection_" + variant] = project(seif, proj_csv, variant,
                                               args.lineage_batch)
        out["diff_" + variant] = diff_against_pack(
            os.path.join(args.pack_evidence,
                         "ext_telecom_asmvm_vm_finding.csv"), proj_csv, out)

    with io.open(os.path.join(args.out_dir, "seif_roundtrip_report.json"),
                 "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, default=str)
    print(json.dumps(out, indent=2, default=str)[:4000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
