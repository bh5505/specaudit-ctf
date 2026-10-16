#!/usr/bin/env bash
# Multi-attempt variance sweep for one head instance on this host: N
# runner commands per cell, per-attempt report files, so per-cell
# stability stats can be computed from the reports alone.
#
# Usage (from the repo checkout on the lab host):
#   EXERCISE_HEAD_CLAUDE_CODE_CMD=/root/.local/bin/claude \
#   lab/matrix-variance.sh claude-code /tmp/variance/claude-kali 3 \
#     telecom-aws-06-chain-rehearsal lab-knowledge-01-attack-mapping
#
# Cell names in argv are a challenge id, optionally suffixed -hard to
# attempt it with the hard-mode canonical prompt (scaffolding
# withheld; the graded contract is unchanged). A cell that fails is
# RECORDED, not fatal: honest variance is the deliverable.
set -uo pipefail

HEAD="${1:?usage: matrix-variance.sh <head-id> <out-dir> <N> [cell ...]}"
OUT="${2:?usage: matrix-variance.sh <head-id> <out-dir> <N> [cell ...]}"
N="${3:?usage: matrix-variance.sh <head-id> <out-dir> <N> [cell ...]}"
shift 3
CELLS=("$@")
if [ ${#CELLS[@]} -eq 0 ] || ! [[ "$N" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: matrix-variance.sh <head-id> <out-dir> <N> [cell ...]" >&2
  exit 2
fi
PY="${PYTHON:-python3}"

# Same fixed graded list as lab/matrix-run.sh; a -hard suffix selects
# the hard-mode prompt for the same track/contract.
graded_cell() {
  case "$1" in
    telecom-aws-01-reachability|telecom-aws-02-iam-s3-misconfig|\
telecom-aws-03-iam-privesc|telecom-aws-04-network-exposure|\
telecom-aws-05-logging-gaps|telecom-aws-06-chain-rehearsal|\
lab-knowledge-01-attack-mapping) return 0 ;;
    *) return 1 ;;
  esac
}

prompt_for() { # <cell> -> prompt path (prints; empty means none)
  base="${1%-hard}"
  hard=""
  [ "$base" != "$1" ] && hard="-hard"
  case "$base" in
    telecom-aws-*) echo "lab/prompts/challenge-${base#telecom-aws-}${hard}.txt" ;;
    lab-knowledge-*) echo "lab/prompts/challenge-knowledge-${base#lab-knowledge-}${hard}.txt" ;;
    *) return 1 ;;
  esac
}

for cell in "${CELLS[@]}"; do
  base="${cell%-hard}"
  if ! graded_cell "$base" || ! prompt="$(prompt_for "$cell")" || [ ! -f "$prompt" ]; then
    echo "[variance] unknown cell or missing prompt: $cell" >&2
    exit 2
  fi
done

mkdir -p "$OUT"
failed=0
for cell in "${CELLS[@]}"; do
  base="${cell%-hard}"
  prompt="$(prompt_for "$cell")"
  expected="challenges/$base/artifacts/expected-findings.json"
  for i in $(seq 1 "$N"); do
    cell_dir="$OUT/$cell"
    mkdir -p "$cell_dir"
    echo "[variance] $HEAD x $cell x attempt-$i"
    if "$PY" -m exercise \
      --challenge "$base" \
      --head "$HEAD" --head-execute \
      --attempt-prompt "$prompt" \
      --attempt-dir "$cell_dir/attempt-$i" \
      --expected "$expected" \
      --out "$cell_dir/report-$i.json" \
      2> "$cell_dir/stderr-$i.log";
    then
      echo "[variance]   -> complete"
    else
      echo "[variance]   -> FAILED (recorded in $cell_dir/report-$i.json when gradable)"
      failed=$((failed + 1))
    fi
  done
done
echo "[variance] sweep done: $failed failed attempt(s) (recorded, not fatal)"
exit 0
