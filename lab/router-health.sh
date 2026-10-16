#!/usr/bin/env bash
# Tier-router health gate for the claude-code graded lanes (2026-09-07).
#
# claude-code heads grade only through the LiteLLM tier router on their
# host (127.0.0.1:4000). A route that silently lands on a dead upstream
# key wastes a graded run, so every graded matrix/variance sweep is
# preceded by this gate on the same host. It asserts, in order:
#
#   1. the router answers GET /v1/models with the master key and serves
#      EXACTLY the three dated claude ids (no additions, no renames);
#   2. the live config's route table is structurally the re-armed one:
#      a YAML read (not a grep — comments and env-var names must not
#      count) must yield exactly the three dated route names, every
#      route must pin the exact muse model + api_base, and NO
#      litellm_params value on any route may reference openrouter;
#   3. a direct POST /v1/chat/completions per dated id returns HTTP 200
#      with non-whitespace-EMPTY content (budget >= 1024: muse is a
#      reasoning model and smaller budgets legitimately return empty
#      content);
#   4. a `claude -p` smoke per dated id returns output with no
#      unrecognized_model warning and no dead-credential signal (402,
#      credit/quota/unauthorized). The muse gateway's deprecation banner
#      for the dated opus id prints on stdout and is informational —
#      tolerated. A quota-exhausted muse returns "Model not found or
#      access denied" for every id — that fails the gate.
#
# Secret handling: the master key is read from a root-only key file
# (group/other bits asserted zero) and travels only inside a 0600 curl
# config file (cleaned up on exit) — never in argv, where /proc would
# publish it, and never on stdout.
#
# Usage (from the repo checkout on a router host):
#   lab/router-health.sh

set -uo pipefail

ROUTER="${ROUTER_BASE:-http://127.0.0.1:4000}"
CONFIG="${LITELLM_CONFIG:-/opt/litellm/config.yaml}"
KEYFILE="${LITELLM_MASTER_KEY_FILE:-/root/.claude/litellm-master-key}"
LITELLM_PY="${LITELLM_PYTHON:-/opt/litellm/bin/python3}"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
MUSE_MODEL="anthropic/muse-spark-1.3-contributor"
MUSE_BASE="https://api.meta.ai"
IDS=(
  claude-opus-4-1-20250805
  claude-sonnet-4-5-20250929
  claude-haiku-4-5-20251001
)

fail() { echo "[router-health] FAIL: $*" >&2; exit 1; }

[ -r "$KEYFILE" ] || fail "master key file unreadable: $KEYFILE"
keymode="$(stat -c '%a' "$KEYFILE" 2>/dev/null)" || fail "cannot stat $KEYFILE"
[ "${keymode: -2}" = "00" ] || fail "$KEYFILE is group/other-readable (mode $keymode)"
MASTER_KEY="$(cat "$KEYFILE")" || fail "cannot read $KEYFILE"
[ -x "$LITELLM_PY" ] || fail "litellm venv python not found: $LITELLM_PY"

# The key rides in a 0600 curl config file, never in argv.
HEADER_FILE="$(mktemp "${TMPDIR:-/tmp}/router-health.XXXXXX")" || fail "mktemp failed"
chmod 600 "$HEADER_FILE" || fail "cannot restrict $HEADER_FILE"
trap 'rm -f "$HEADER_FILE"' EXIT
printf 'header = "Authorization: Bearer %s"\n' "$MASTER_KEY" > "$HEADER_FILE"

# 1. served-name set is exactly the three dated ids (bounded retry:
# the gate may legitimately run right after a router restart)
models_json=""
for attempt in 1 2 3 4 5 6; do
  if models_json="$(curl -sf --max-time 30 -K "$HEADER_FILE" "$ROUTER/v1/models")"; then
    break
  fi
  if [ "$attempt" = 6 ]; then
    fail "GET /v1/models failed after 6 attempts (router down or key refused)"
  fi
  sleep 10
done
served="$(printf '%s' "$models_json" | "$LITELLM_PY" -c \
  'import json,sys; print("\n".join(sorted(m["id"] for m in json.load(sys.stdin)["data"])))')" \
  || fail "could not parse /v1/models response"
expected="$(printf '%s\n' "${IDS[@]}" | LC_ALL=C sort)"
if [ "$served" != "$expected" ]; then
  fail "served model set drift:
--- expected ---
$expected
--- served ---
$served"
fi
echo "[router-health] served names ok: 3 dated ids, unchanged"

# 2. the live route table is structurally the re-armed one
"$LITELLM_PY" - "$CONFIG" "${IDS[@]}" "$MUSE_MODEL" "$MUSE_BASE" <<'PY' || fail "route check failed: route names drift, a route is not pinned to the muse backend, or a param references openrouter"
import sys

import yaml

config_path = sys.argv[1]
expected_names = sorted(sys.argv[2:-2])
muse_model, muse_base = sys.argv[-2], sys.argv[-1]

with open(config_path, encoding="utf-8") as handle:
    config = yaml.safe_load(handle)
routes = config.get("model_list") or []
names = sorted(str(route.get("model_name")) for route in routes)
assert names == expected_names, (
    f"route names {names} != expected {expected_names}"
)
for route in routes:
    name = route.get("model_name")
    params = route.get("litellm_params") or {}
    for key, value in params.items():
        assert "openrouter" not in str(value).lower(), (
            f"route {name!r} param {key!r} references openrouter: {value!r}"
        )
    assert str(params.get("model")) == muse_model, (
        f"route {name!r} is not pinned to {muse_model}: {params.get('model')!r}"
    )
    assert str(params.get("api_base")) == muse_base, (
        f"route {name!r} api_base is not {muse_base}: {params.get('api_base')!r}"
    )
print(
    f"[router-health] config ok: {len(routes)} routes, exact muse pin, "
    "zero openrouter references"
)
PY

# 3. direct completion per dated id: HTTP 200, non-whitespace content
for id in "${IDS[@]}"; do
  body="$(printf '{"model":"%s","max_tokens":1024,"messages":[{"role":"user","content":"Reply with the single word: ok"}]}' "$id")"
  answer="$(curl -sf --max-time 120 -K "$HEADER_FILE" \
    -H "Content-Type: application/json" -d "$body" "$ROUTER/v1/chat/completions")" \
    || fail "POST /v1/chat/completions failed for $id (dead upstream?)"
  content="$(printf '%s' "$answer" | "$LITELLM_PY" -c \
    'import json,sys; d=json.load(sys.stdin); print(d["choices"][0]["message"].get("content") or "")')" \
    || fail "unparsable completion body for $id"
  [[ "$content" =~ [^[:space:]] ]] || fail "whitespace-only content for $id (token budget or backend problem)"
  echo "[router-health] route ok: $id"
done

# 4. claude -p smoke per dated id, warnings and dead-credential
# signals fail closed (the informational muse deprecation banner does not)
for id in "${IDS[@]}"; do
  smoke="$(cd /tmp && timeout 180 "$CLAUDE_BIN" -p "Reply with just: ok" --model "$id" 2>&1)" \
    || fail "claude -p smoke failed for $id"
  lower_smoke="$(printf '%s' "$smoke" | tr '[:upper:]' '[:lower:]')"
  case "$lower_smoke" in
    *unrecognized_model*|*"not found"*|*"access denied"*|*402*|*credit*|*quota*|*exceed*|*unauthorized*)
      fail "claude smoke for $id warns: $(printf '%s\n' "$smoke" | head -2)"
      ;;
  esac
  [[ "$smoke" =~ [^[:space:]] ]] || fail "claude smoke for $id produced no output"
  echo "[router-health] smoke ok: $id"
done

echo "[router-health] ALL GREEN on this host: 3 muse-backed routes, smokes clean"
