#!/usr/bin/env python3
"""Build an evidence dir where ext_telecom_asmvm_vm_finding.csv is replaced by a
SEIF round-tripped projection, everything else hard-linked from the baseline.

Used to run pack checks against SEIF-mediated evidence: same runner, same SQL,
only the VM-finding table's provenance changed
(export -> SEIF -> pack CSV instead of export -> pack CSV).

  python make_seif_evidence_dir.py --baseline pack_evidence \
      --projection seif_roundtrip_full/seif_A_ext_telecom_asmvm_vm_finding.csv \
      --out evidence_seif_A
"""

import argparse
import csv
import io
import os
import shutil
import sys

TABLE = "ext_telecom_asmvm_vm_finding.csv"


def rewrite_run_id(src, dst, run_id):
    """Stream src -> dst with the run_id column replaced by run_id."""
    with io.open(src, encoding="utf-8", newline="") as fin, \
            io.open(dst, "w", encoding="utf-8", newline="") as fout:
        rd = csv.reader(fin)
        wr = csv.writer(fout, lineterminator="\n")
        header = next(rd)
        wr.writerow(header)
        try:
            col = header.index("run_id")
        except ValueError:
            raise SystemExit("%s has no run_id column" % src)
        for row in rd:
            row[col] = run_id
            wr.writerow(row)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--projection", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--run-id", default=None,
                    help="stamp this run_id into the projection. SEIF carries no "
                         "run id (the real pipeline stamps it at load), so a "
                         "CSV-level round trip must stamp it too - otherwise every "
                         "check's run_id filter sees zero SEIF rows and the A/B "
                         "measures nothing")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    linked, copied = [], []
    for name in sorted(os.listdir(args.baseline)):
        if not name.endswith(".csv"):
            continue
        dst = os.path.join(args.out, name)
        if os.path.exists(dst):
            os.remove(dst)
        if name == TABLE:
            if args.run_id:
                rewrite_run_id(args.projection, dst, args.run_id)
            else:
                shutil.copyfile(args.projection, dst)
            copied.append(name)
            continue
        try:
            os.link(os.path.join(args.baseline, name), dst)
            linked.append(name)
        except OSError:
            shutil.copyfile(os.path.join(args.baseline, name), dst)
            copied.append(name)
    n = sum(1 for _ in io.open(os.path.join(args.out, TABLE),
                               encoding="utf-8", newline="")) - 1
    print("evidence dir %s: %d linked, %d copied, %s rows=%d"
          % (args.out, len(linked), len(copied), TABLE, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
