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
#   2. every configured route is muse-backed: a structural YAML read of
#      the live config (not a grep — comments and env-var names must not
#      count) finds no openrouter reference in any route's model /
#      api_base / api_key values, and every route's model is the
#      muse-backed anthropic/ target;
#   3. a direct POST /v1/chat/completions per dated id returns HTTP 200
#      with non-empty content (budget >= 1024: muse is a reasoning model
#      and smaller budgets legitimately return empty content);
#   4. a `claude -p` smoke per dated id returns output with no
#      unrecognized_model warning. The muse gateway's deprecation banner
#      for the dated opus id prints on stdout and is informational —
#      tolerated. A quota-exhausted muse returns "Model not found or
#      access denied" for every id — that fails the gate.
#
# No key material is ever printed: the master key stays in its 0600
# file and travels only in the Authorization header. Exits non-zero on
# the first failed assertion.
#
# Usage (from the repo checkout on a router host):
#   lab/router-health.sh

set -uo pipefail

ROUTER="${ROUTER_BASE:-http://127.0.0.1:4000}"
CONFIG="${LITELLM_CONFIG:-/opt/litellm/config.yaml}"
KEYFILE="${LITELLM_MASTER_KEY_FILE:-/root/.claude/litellm-master-key}"
LITELLM_PY="${LITELLM_PYTHON:-/opt/litellm/bin/python3}"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
IDS=(
  claude-opus-4-1-20250805
  claude-sonnet-4-5-20250929
  claude-haiku-4-5-20251001
)

fail() { echo "[router-health] FAIL: $*" >&2; exit 1; }

[ -r "$KEYFILE" ] || fail "master key file unreadable: $KEYFILE"
[ -x "$LITELLM_PY" ] || fail "litellm venv python not found: $LITELLM_PY"
MASTER_KEY="$(cat "$KEYFILE")"

# 1. served-name set is exactly the three dated ids
models_json="$(curl -sf "$ROUTER/v1/models" -H "Authorization: Bearer $MASTER_KEY")" \
  || fail "GET /v1/models failed (router down or key refused)"
served="$(printf '%s' "$models_json" | "$LITELLM_PY" -c \
  'import json,sys; print("\n".join(sorted(m["id"] for m in json.load(sys.stdin)["data"])))')" \
  || fail "could not parse /v1/models response"
expected="$(printf '%s\n' "${IDS[@]}" | sort)"
if [ "$served" != "$expected" ]; then
  fail "served model set drift:
--- expected ---
$expected
--- served ---
$served"
fi
echo "[router-health] served names ok: 3 dated ids, unchanged"

# 2. every configured route is muse-backed (structural read)
"$LITELLM_PY" - "$CONFIG" <<'PY' || fail "route check failed: a route is missing, openrouter-referencing, or not muse-backed"
import sys

import yaml

with open(sys.argv[1], encoding="utf-8") as handle:
    config = yaml.safe_load(handle)
routes = config.get("model_list") or []
assert routes, "model_list is empty"
for route in routes:
    name = route.get("model_name")
    params = route.get("litellm_params") or {}
    targets = " ".join(
        str(params.get(key) or "") for key in ("model", "api_base", "api_key")
    ).lower()
    assert "openrouter" not in targets, f"route {name!r} references openrouter"
    assert str(params.get("model") or "").startswith("anthropic/"), (
        f"route {name!r} is not muse-backed: {params.get('model')!r}"
    )
print(f"config ok: {len(routes)} routes, all muse-backed, zero openrouter references")
PY

# 3. direct completion per dated id: HTTP 200, non-empty content
for id in "${IDS[@]}"; do
  body="$(printf '{"model":"%s","max_tokens":1024,"messages":[{"role":"user","content":"Reply with the single word: ok"}]}' "$id")"
  answer="$(curl -sf "$ROUTER/v1/chat/completions" \
    -H "Authorization: Bearer $MASTER_KEY" -H "Content-Type: application/json" \
    -d "$body")" || fail "POST /v1/chat/completions failed for $id (dead upstream?)"
  content="$(printf '%s' "$answer" | "$LITELLM_PY" -c \
    'import json,sys; d=json.load(sys.stdin); print(d["choices"][0]["message"].get("content") or "")')" \
    || fail "unparsable completion body for $id"
  [ -n "${content// /}" ] || fail "empty content for $id (token budget or backend problem)"
  echo "[router-health] route ok: $id"
done

# 4. claude -p smoke per dated id, warnings fail closed
for id in "${IDS[@]}"; do
  smoke="$(cd /tmp && timeout 180 "$CLAUDE_BIN" -p "Reply with just: ok" --model "$id" 2>&1)" \
    || fail "claude -p smoke failed for $id"
  case "$smoke" in
    *unrecognized_model*|*"not found"*|*"access denied"*)
      fail "claude smoke for $id warns: $(printf '%s\n' "$smoke" | head -2)"
      ;;
  esac
  [ -n "${smoke// /}" ] || fail "claude smoke for $id produced no output"
  echo "[router-health] smoke ok: $id"
done

echo "[router-health] ALL GREEN on this host: 3 muse-backed routes, smokes clean"
