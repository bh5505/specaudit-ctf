#!/usr/bin/env python3
"""SEIF round-trip variant C: the ingest-side mitigations, measured.

seif_ivanti_roundtrip.py measured what the shipped Ivanti converter does to a
real export when used as documented (variant A) and with pluginFamily smuggled
through details.tags (variant B). Two losses turned out to be fixable at the
ingest side, and this script measures the fix:

  * resource_uid alias order. seif/converters/ivanti_neurons.py prefers
    ["Asset ID", "Resource Uid", "IP Address", ...], so an export that carries
    both columns lands the scanner's internal asset id in SEIF's resource_uid
    and the IP address is gone - every ASM/VM check joins on the address.
    Mitigation: do not emit "Asset ID" (emit only "IP Address").
  * plugin_family has no SEIF field: emit it as the Tags value (variant B).

Variant C = export without "Asset ID" + pluginFamily in Tags. Same convert
(shipped CLI, field-cap shim), same projection, same diff as A/B, so the three
numbers are directly comparable.
"""

import argparse
import csv
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import seif_ivanti_roundtrip as rt           # noqa: E402

BASE = os.environ.get("SEIF_RT_DIR", os.getcwd())


def strip_asset_id(src, dst):
    """Re-write export A without the 'Asset ID' column."""
    with io.open(src, encoding="utf-8", newline="") as fh:
        rdr = csv.DictReader(fh)
        fields = [c for c in rdr.fieldnames if c != "Asset ID"]
        with io.open(dst, "w", encoding="utf-8", newline="") as ofh:
            w = csv.DictWriter(ofh, fieldnames=fields)
            w.writeheader()
            n = 0
            for row in rdr:
                w.writerow({k: row.get(k) for k in fields})
                n += 1
    return n


def main(base, out_dir):
    OUT = out_dir
    out = {"tool": "seif_variant_c", "why": (
        "no Asset ID (so resource_uid resolves to IP Address) + pluginFamily in "
        "Tags; everything else identical to variant B")}
    src = os.path.join(OUT, "ivanti_export_B_findings.csv")
    csvC = os.path.join(OUT, "ivanti_export_C_findings.csv")
    out["export_C_rows"] = strip_asset_id(src, csvC)
    seifC = os.path.join(OUT, "ivanti_C.seif.json")
    out["convert_C"] = rt.step_convert(csvC, seifC,
                                       os.path.join(OUT, "seif_cli_shim.py"), "C")
    out["validate_C"] = rt.step_validate(seifC)
    projC = os.path.join(OUT, "seif_C_ext_telecom_asmvm_vm_finding.csv")
    out["projection_C"] = rt.project(seifC, projC, "B", "gw-seif-20260909")
    out["diff_C"] = rt.diff_against_pack(
        os.path.join(base, "pack_evidence",
                     "ext_telecom_asmvm_vm_finding.csv"), projC, out)
    with io.open(os.path.join(OUT, "seif_variant_c_report.json"), "w",
                 encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, default=str)
    print(json.dumps({"convert_C": out["convert_C"].get(
        "shim", out["convert_C"]).get("stdout"),
        "validate_C": out["validate_C"]["stdout"][-80:],
        "projection_C": out["projection_C"],
        "diff_C": {k: out["diff_C"][k] for k in (
            "projected_ids_present_in_baseline", "fields_equal_of_matched",
            "fields_baseline_had_value_projection_empty", "projected_ips",
            "baseline_ips_in_sample")}}, indent=2))
    return 0


def _cli():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default=BASE,
                    help="directory holding pack_evidence/ (baseline table)")
    ap.add_argument("--out-dir", default=os.path.join(BASE, "seif_roundtrip"),
                    help="dir holding the variant A/B export from "
                         "seif_ivanti_roundtrip.py; variant C files land here")
    ap.add_argument("--seif-src", default="",
                    help="seif source tree (or $SEIF_SRC)")
    args = ap.parse_args()
    if args.seif_src:
        rt.SEIF_SRC = args.seif_src
    return main(args.base, args.out_dir)


if __name__ == "__main__":
    sys.exit(_cli())
