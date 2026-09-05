## Addendum 4 — stdin class-sweep + expansion admissions + content anchors (2026-09-05)

The 2026-09-05 campaign (launcher: five items, expansion-first
posture) landed:

**Stdin-preference class-sweep (PR #51, merged):** every arm that
spawns a subprocess with an argv-passed target was audited against
primary source (muse-researcher lanes; every load-bearing upstream
fact re-verified by direct fetch where it changed code). Fixes:
`stdin=DEVNULL` on every argv-driven spawn (19 arm sites + the
generic CLI transport); **page-fetch rewritten to the zgrab2
stdin-feed pattern** — detectify/page-fetch reads URLs from stdin
ONLY (no URL flag; positional argv silently ignored; all error paths
exit 0), so the old bare-positional argv could never fetch and DEVNULL
alone would have been a guaranteed silent no-fetch; mitreattack-python
argv corrected to upstream v6.2.0's Typer shape (`from-stix
--stix-file`). New `tests/test_stdin_hygiene.py`: AST invariant
(every subprocess spawn in extension/ sets stdin= or input=, incl.
from-import and module-alias bypasses) + per-arm behavioral tests.
Commix fix verified held upstream. Tri-host: Windows 899/0/13 ·
Ubuntu 912/0 · Kali 908/0/4.

**vuls.scan admitted (PR #52, merged; doc-20 amendment recorded):**
51st invoke profile, normal recipe; lab install-from-source
(v0.40.1 + GOEXPERIMENT=jsonv2) and measured LOCAL-mode scan recorded.

**stratus-red-team warmup/detonate/revert admitted (PR #54):**
52nd-54th profiles (technique-lifecycle set; cloud-side spend truth
carried); operator-gated demo notes in lab/README.md. Doc-20
amendment follows the merge.

**Content anchors (PR #53, merged):** docs/track-d-dogfood.md — the
doc-11 §212 supplement. The named donor file was never authored
(verified in no branch of either internal repo); the worksheet is
written from the adopted Track D doctrine, retargeted at the public
data plane (this repo's CLI + stdio MCP server), graded-on-process
discipline preserved, score/ pairing explicit, teaching path
checkout+Python 3.11 only. lab/validation-results.md — fillable
awaiting-operator record for burp/GTI/prowler, linked bidirectionally
with the lab runbooks.

**Survey-pages item — verified absorbed, zero rows:** the ~26
per-tool donor pages under resources/external-tools/ were extracted
(glm-researcher lane) and every one maps to an EXISTING public
catalog row (arms or methodology rows); the public catalog is a
superset of the donor set. No entry-count change, no PR — the
contract stayed 46/27. The only donor page naming tools absent from
the catalog (community-mcp-servers) self-declares "no registry entry".

**Automatic reviews:** #50 bot (zdns record "exactly"+placeholders)
and #51 bot (AST predicate/naming residuals) applied in PR #52;
#52's bot review is an approval (wording-only residue); #53's bot
findings (score/README coinage — already fixed in-PR; schema-name
precision; full-command elisions) applied in sweep 8. Sweeps 7 (#50)
and 8 recorded.

Catalog at close: 46 entries / 27 curated arms / **54 invoke
profiles** (11 static + 16 dispatch + 9 burp + 12 GTI + 1 prowler +
5 metasploit) / zero held rows / agent-wiz sole maintained.
