# OpenAI subscription provider — probed, blocked on a live operator session (2026-09-07)

Directive: add the operator's OpenAI ChatGPT-subscription (OAuth) as a
provider for the codex CLI and for claude-code through the LiteLLM
tier router. The supplied credential material turned out to be
expired; the provider is NOT activated, nothing dead was wired, and a
one-command installer is staged on both hosts for fresh material.

## What was probed (facts, measured 2026-09-07)

- The supplied access JWT is expired: `exp` 1786478571 (about ten
  days after its `iat`), which precedes the probe date.
- The refresh grant against `https://auth.openai.com/oauth/token`
  with the client_id **parsed from the JWT itself**
  (`app_EMoamEEZ73f0CkXaXp7hrann`) — JSON and form-encoded bodies,
  with and without `scope` — returns 401 `"Your session has expired.
  Please log in again."` The request shape is right (a deliberately
  wrong client_id produces a different error, `invalid_client`); the
  refresh session itself is dead server-side.
- No live alternative exists on the machine: no `auth.json` for a
  Windows codex install, no OpenAI OAuth cache.
- codex 0.153.4's `~/.codex/auth.json` schema **requires a string
  `id_token`**: installing the stale material with
  `"id_token": null` makes `codex login status` fail with
  ``invalid type: null, expected a string``. Only a live refresh or
  login produces an id_token, so the stale material cannot populate a
  valid auth.json either. The invalid file was removed; the
  abliteration default provider was verified unaffected (`codex exec`
  smoke still answers).

Nothing here was simulated or worked around: a provider route served
by a dead token would be a dead route, and the tier router's
guarantee (every route live at gate time) is worth more than the
placeholder.

## What is staged for activation (both WSL hosts)

`/root/.claude/install-openai-auth.py` (0600) accepts either the
normalized blob `{refresh, access, expires, accountId}` (it runs the
refresh grant, parsing client_id from the JWT) or a full codex
`auth.json` export (it enforces the non-null `id_token` rule), then
installs `/root/.codex/auth.json` (0600) and
`/root/.claude/openai-access-token` (0600) for the gateway route.

Activation once fresh material exists (from an interactive
`codex login` on a host, or a live export):

```text
python3 /root/.claude/install-openai-auth.py <credential.json>
codex login status                                    # expect: logged in
```

then add the gateway route (new `model_name`, the three dated claude
names untouched):

```yaml
  - model_name: <subscription-served name>
    litellm_params:
      model: openai/<model>
      api_base: https://api.openai.com/v1
      api_key: os.environ/OPENAI_SUBSCRIPTION_ACCESS
```

and extend `lab/router-health.sh`'s invariants: the three dated ids
stay muse-pinned, the additional route pins the subscription backend,
and `openrouter` stays banned everywhere. The access token's ~10-day
lifetime needs a refresh hook at that point (same refresh grant) —
wired when the live material lands, never before.
