#!/usr/bin/env python3
"""Compare two pack report.json files finding-for-finding.

Usage: python compare_reports.py BASELINE CANDIDATE [CANDIDATE ...]

Parity = same check set, same per-check counts, and the same set of
finding_alias values per check (order-insensitive; ORDER BY is asserted
separately by the synthetic suite).
"""
import json
import sys
from collections import defaultdict


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    by_check = defaultdict(set)
    counts = defaultdict(int)
    for f in doc["findings"]:
        by_check[f["check_id"]].add(f["finding_alias"])
        counts[f["check_id"]] += 1
    return doc, counts, by_check


def main():
    base_path, rest = sys.argv[1], sys.argv[2:]
    base_doc, base_counts, base_by = load(base_path)
    print("baseline %s engine=%s run=%s total=%d checks=%d"
          % (base_path, base_doc["engine"], base_doc["run_id"],
             len(base_doc["findings"]), len(base_counts)))
    ok_all = True
    for path in rest:
        doc, counts, by = load(path)
        print("\n=== %s engine=%s run=%s total=%d checks=%d"
              % (path, doc["engine"], doc["run_id"], len(doc["findings"]),
                 len(counts)))
        problems = []
        for cid in sorted(set(base_counts) | set(counts)):
            b, c = base_counts.get(cid, 0), counts.get(cid, 0)
            mark = "OK " if b == c else "DIFF"
            if b != c:
                problems.append(cid)
            alias_same = base_by.get(cid, set()) == by.get(cid, set())
            print("  %s %-62s baseline=%-6d now=%-6d aliases=%s"
                  % (mark, cid.replace("ext_telecom_asmvm_", ""), b, c,
                     "same" if alias_same else "DIFFERENT"))
            if not alias_same:
                problems.append(cid + ":aliases")
        ok = not problems and len(base_doc["findings"]) == len(doc["findings"])
        ok_all = ok_all and ok
        print("  -> %s%s" % ("PARITY OK" if ok else "PARITY FAILED",
                             "" if ok else ": " + ", ".join(problems)))
    print("\nOVERALL: %s" % ("PARITY OK" if ok_all else "PARITY FAILED"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
