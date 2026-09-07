# OpenAI subscription provider — codex lane ACTIVATED 2026-09-07; gateway lane measured-blocked

Directive: add the operator's OpenAI ChatGPT-subscription (OAuth) as a
provider for the codex CLI and for claude-code through the LiteLLM
tier router.

**Outcome: the codex lane is live on both hosts** (ChatGPT login
accepted, `codex exec --profile chatgpt` verified end-to-end, default
model Daybreak Blue low per operator). The gateway lane for
claude-code is measured-blocked: the subscription token is refused by
the platform API (403 on `/v1/models`) — it serves only the Codex
backend — so no LiteLLM chat-completions route can sit in front of
it, and none was added.

## Activation (evening 2026-09-07, fresh operator material)

The operator supplied a fresh OAuth blob (access issued the same day,
plan type `pro`, MFA in `amr`). The staged installer consumed it:
refresh grant minted the id_token (the schema's required field),
`~/.codex/auth.json` installed 0600, `codex login status` → "Logged
in using ChatGPT". Ubuntu received kali's INSTALLED token set by
byte-copy (not a second refresh — OAuth refresh rotation could have
invalidated the first host's stored refresh token; both hosts share
one session and refresh it independently thereafter).

Served-model discovery (server-side 400s name the account's real
catalog): the legacy `-codex`-suffixed slugs (`gpt-5.1-codex`,
`gpt-5.2-codex`, `gpt-5.1-codex-max`, `gpt-5.3-codex`) and bare
`gpt-5.6` / `gpt-6` are all refused for ChatGPT accounts. Verified
working: **`gpt-5.6-luna`**, **`gpt-6-astra`**, and — the operator
directive — **Daybreak Blue**: stable alias
`gpt-daybreak-blue-latest`, model id `gpt-5.6-sol`. (Daybreak Red =
`gpt-daybreak-red-latest` / `gpt-5.6-cyber`, per the operator's
identifier table; not probed.)

Default wiring on both hosts — `/root/.codex/chatgpt.config.toml`
(0600), selected with `codex exec --profile chatgpt`; the global
default provider stays `abliteration` so the matrix baseline lanes
are unchanged:

```toml
model_provider = "openai"
model = "gpt-daybreak-blue-latest"
model_reasoning_effort = "low"
```

Both hosts smoke green through `--profile chatgpt`. Caveats on
record: (1) the access token lives ~10 days and the two hosts share
ONE OAuth session, so refresh must be single-writer: rerun
`/root/.claude/install-openai-auth.py` with fresh (or still-live)
material on ONE host, then byte-copy the installed `auth.json` to the
other — the codex CLI also refreshes tokens on use, so two hosts
refreshing the shared session independently can stale each other's
stored refresh token. (2) A server-side revocation or a login
elsewhere lands on both hosts at once.

## Why the gateway lane stayed closed (measured, not assumed)

- `GET https://api.openai.com/v1/models` with the subscription
  bearer → **403, zero models**: the token does not authorize the
  platform API, so an `openai/`-provider LiteLLM route has nothing to
  serve and no chat-completions-shaped endpoint exists on the Codex
  backend (`https://chatgpt.com/backend-api/codex`, responses wire
  only).
- Adding a dead route would violate the router's own guarantee (every
  route live at gate time), so `lab/router-health.sh` keeps its
  exact-three-muse-routes invariant. Revisit only if OpenAI ships a
  platform-compatible endpoint for subscription tokens.

## Earlier the same day: the first credential drop was dead

The first supplied blob (access expired, refresh session revoked,
plan `prolite`) could not be activated: the refresh grant returned
401 `"Your session has expired. Please log in again."` once the
client_id was parsed from the JWT (a hand-transcribed client_id
produced a misleading `invalid_client` first), and codex 0.153.4's
auth.json schema requires a string `id_token` — `"id_token": null`
breaks `codex login status`. Nothing was fabricated; the installer
was staged and the blocker recorded until fresh material arrived.
