#!/usr/bin/env bash
# Measured armed osmedeus scan through the catalog arm against the
# spawned lab target. Records envelopes + engine outputs into
# /tmp/osm-measure on the lab host (caller copies into
# lab/records/lab-osmedeus-<date>/).
# Prereqs: lab/install-osmedeus.sh once; jq on PATH (do-scan-vuln
# depends on it); the spawned lab target IP in LAB_TARGET_IP
# (172.19.89.77).
#
# Honest residuals (2026-09-06): do-scan-vuln-thorough skips with
# 'required command not found: vigolium' — vigolium is NOT part of
# the engine's binaries registry and has no obvious first-party
# install path; the skip is the measured behavior, recorded verbatim.
set -euo pipefail
export MSYS_NO_PATHCONV=1

NAME="${LAB_KALI_NAME:-kali-linux}"
IP="${LAB_TARGET_IP:-172.19.89.77}"

wsl -d "$NAME" -u root -e bash -seu -- "$IP" <<'EOF'
set -euo pipefail
IP="$1"
cd /root/ctf
# measure at the current upstream main (this script carries no branch
# pin - the record directory names the date; the commit measured is
# whatever origin/main resolves to, printed for the record)
git fetch origin -q
git reset --hard -q origin/main
git log --oneline -1
export OSMEDEUS_BIN=/usr/local/bin/osmedeus
export OSMEDEUS_DISPATCH_SCOPE="$IP"
R=/tmp/osm-measure
mkdir -p "$R"
START=$(date +%s)
python3 -m extension invoke osmedeus scan "{\"target\": \"http://$IP:8000\"}" \
  > "$R/armed-scan.json" 2>"$R/armed-scan.err"
cp "$R/armed-scan.err" "$R/armed-scan-dispatch.err"
END=$(date +%s)
echo "elapsed: $((END-START))s"
python3 - "$R" <<'PY'
import json, sys
R = sys.argv[1]
d = json.load(open(f"{R}/armed-scan.json"))
print("status:", d.get("status"))
print("elapsed_ms:", d.get("budget", {}).get("spent", {}).get("elapsed_ms"))
PY
# engine-side record (direct run, same shape) - the exit status is
# RECORDED, never masked; a failed engine run fails this script after
# writing the log
export HOME=/root
set +e
timeout 900 /usr/local/bin/osmedeus scan -f url -t "http://$IP:8000" \
  > "$R/engine-run.log" 2>&1
ENGINE_EXIT=$?
set -e
echo "engine exit: $ENGINE_EXIT" >> "$R/engine-run.log"
[ "$ENGINE_EXIT" = "0" ] || { tail -8 "$R/engine-run.log"; exit 1; }
tail -12 "$R/engine-run.log"
EOF
