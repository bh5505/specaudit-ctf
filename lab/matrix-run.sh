#!/usr/bin/env bash
# Head-matrix cell sweep for one head instance on this host: one runner
# command per cell (challenge), reports + attempt dirs per cell.
#
# Usage (from the repo checkout on the lab host):
#   EXERCISE_HEAD_CLAUDE_CODE_CMD=/root/.local/bin/claude \
#   lab/matrix-run.sh claude-code /tmp/matrix/claude-kali
#
# The graded cell list is the five challenges that ship findings
# contracts (challenge 01 is not-gradable-by-design - see
# lab/prompts/README.md). A cell that fails is RECORDED, not fatal:
# the comparative matrix report reads every report.json.
set -uo pipefail

HEAD="${1:?usage: matrix-run.sh <head-id> <out-dir> [challenge ...]}"
OUT="${2:?usage: matrix-run.sh <head-id> <out-dir> [challenge ...]}"
shift 2
CHALLENGES=("$@")
if [ ${#CHALLENGES[@]} -eq 0 ]; then
  CHALLENGES=(
    telecom-aws-02-iam-s3-misconfig
    telecom-aws-03-iam-privesc
    telecom-aws-04-network-exposure
    telecom-aws-05-logging-gaps
    telecom-aws-06-chain-rehearsal
  )
fi
PY="${PYTHON:-python3}"

# The graded cell list is fixed; argv challenge names must be one of
# the shipped ids (no path games in cell/prompt/expected derivation).
for requested in "${CHALLENGES[@]}"; do
  case "$requested" in
    telecom-aws-02-iam-s3-misconfig|telecom-aws-03-iam-privesc|\
telecom-aws-04-network-exposure|telecom-aws-05-logging-gaps|\
telecom-aws-06-chain-rehearsal) ;;
    *) echo "[matrix] unknown challenge id: $requested" >&2; exit 2 ;;  # 2 = usage error
  esac
done

mkdir -p "$OUT"
failed=0
for CH in "${CHALLENGES[@]}"; do
  cell="$OUT/$CH"
  prompt="lab/prompts/challenge-${CH#telecom-aws-}.txt"
  expected="challenges/$CH/artifacts/expected-findings.json"
  mkdir -p "$cell"
  echo "[matrix] $HEAD x $CH"
  if "$PY" -m exercise \
    --challenge "$CH" \
    --head "$HEAD" --head-execute \
    --attempt-prompt "$prompt" \
    --attempt-dir "$cell/attempt" \
    --expected "$expected" \
    --out "$cell/report.json" \
    2> "$cell/stderr.log";
  then
    echo "[matrix]   -> complete"
  else
    echo "[matrix]   -> FAILED (recorded in $cell/report.json when gradable)"
    failed=$((failed + 1))
  fi
done
echo "[matrix] sweep done: $failed failed cell(s) (recorded, not fatal)"
exit 0
