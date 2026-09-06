# Lab Emu 02 — exploitation-framework listing rehearsal

## Scenario

You are rehearsing the **exploitation-framework listing lane**: the
Metasploit Framework's RPC daemon plus its first-party community MCP
bridge (GH05TCREW/MetasploitMCP) running loopback on the kali lab
host, with the catalog arm reading the listings the way an operator
does. This is a **live-service lane** challenge: the planted content
is the framework's own shipped module catalog (the Kali
metasploit-framework package), declared in the contract's fixtures.

## What you need

The kali lab host (metasploit-framework installed — `msfrpcd` on
PATH), python3, and the helper `lab/install-msf-mcp.sh`, which clones
the bridge pinned to commit `afc792d` (2026-02-05), installs into a
venv, and starts both halves loopback — `msfrpcd` on 127.0.0.1:55553
with a lab-only password and the bridge speaking legacy HTTP+SSE on
127.0.0.1:8085. One distribution fact the script encodes: the bridge's
current requirements pull `mcp` 2.x, where `mcp.server.fastmcp` was
renamed and the bridge fails at import — the script pins `mcp<2`
after install (upstream error observed verbatim 2026-09-06).

## Objectives

1. **Start both halves and arm the reads.**
   `lab/install-msf-mcp.sh`, then
   `export METASPLOIT_MCP_ENDPOINT=http://127.0.0.1:8085/sse` and:
   - `python -m extension invoke metasploit-mcp list_tools`
   - `python -m extension invoke metasploit-mcp list_exploits '{"search_term": ""}'`
   - `python -m extension invoke metasploit-mcp list_active_sessions '{}'`
   - `python -m extension invoke metasploit-mcp list_listeners '{}'`

   Listing bodies land in the invoke artifact dir (digest-named) when
   `--attempt-id`/`--artifact-dir` custody is armed — the module
   catalog is large; the envelope carries the statuses.

   Live observation (2026-09-06): `list_payloads` with a platform
   filter enumerates the full payload catalog over RPC and did not
   return within five minutes on the lab bridge — the exercise uses
   the exploit-catalog listing as its enumeration evidence and leaves
   the payload listing as an operator-side read.

2. **Read the populations.**
   Fresh lab bridge: sessions empty, listeners empty — the two
   absence-shaped verdicts. The exploit/payload listings are the
   enumeration-surface evidence.

3. **Ship the found-findings document.**
   Three rows — module-catalog enumeration, no-sessions, no-listeners
   — each with `finding_key`, `control`, `severity`, a one-sentence
   `rationale`, and a `traces_to` naming the shipped module catalog.
   Track: `lab-emu-02-msf-listings`.

4. **Grade, and run the runner cell.**
   Grade:
   `python -m score --grade found-findings.json --expected challenges/lab-emu-02-msf-listings/artifacts/expected-findings.json`
   Then compose the runner cell:
   `python -m exercise --challenge lab-emu-02-msf-listings --found found-findings.json --expected challenges/lab-emu-02-msf-listings/artifacts/expected-findings.json --arms '[{"arm_id":"metasploit-mcp","action":"list_tools","args":{}},{"arm_id":"metasploit-mcp","action":"list_exploits","args":{"search_term":""}},{"arm_id":"metasploit-mcp","action":"list_active_sessions","args":{}},{"arm_id":"metasploit-mcp","action":"list_listeners","args":{}}]'`

## Notes

- The lab password is throwaway by construction; the framework itself
  carries an isolated-labs-only posture — this lane never leaves
  loopback and never touches anything outside the lab host.
- Determinism: module counts drift with the Kali package; findings
  grade the enumeration shape, never a count.
