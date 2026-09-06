# Lab Emu 02 — walkthrough

## 1. Stand up both halves

`lab/install-msf-mcp.sh` clones GH05TCREW/MetasploitMCP at `afc792d`
(2026-02-05), installs its requirements into a venv, then pins
`mcp<2` — the bridge imports `mcp.server.fastmcp`, which mcp 2.x
renamed to `MCPServer` (observed verbatim on the kali lane
2026-09-06), so the current mcp release breaks the bridge at import.
The script starts `msfrpcd -P <lab-pass> -S -a 127.0.0.1 -p 55553`
(no SSL, loopback only) and the bridge with
`MSF_PASSWORD`/`MSF_SERVER`/`MSF_PORT`/`MSF_SSL=false` +
`--transport http --host 127.0.0.1 --port 8085` (SSE at `/sse`).

## 2. Read through the arm

With `METASPLOIT_MCP_ENDPOINT=http://127.0.0.1:8085/sse`:

- `list_tools` confirms the bridge surface.
- `list_exploits` returns the module catalog (the body lands in the
  artifact dir under custody; the envelope carries the status).
  `list_payloads` with a platform filter did not return within five
  minutes on the lab bridge (full-catalog RPC enumeration) — observed
  2026-09-06, left as an operator-side read.
- `list_active_sessions` / `list_listeners` return empty on the fresh
  bridge.

## 3. The three rows

1. **demo-emu-msf-module-catalog-enumerable (low).** One credential,
   full catalog — the enumeration surface.
2. **demo-emu-msf-no-active-sessions (none).** Empty listing, absence
   phrased explicitly.
3. **demo-emu-msf-no-listeners (none).** Same shape.

## 4. Grade and run

Grade, then the runner cell with the four listing reads as the arms
lane. Grading 1.0 with arms 4/4 complete is the full cell.
