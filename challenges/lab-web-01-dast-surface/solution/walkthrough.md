# Walkthrough — lab-web-01-dast-surface (worked pass, 2026-09-06)

Recorded against a freshly built golden rootfs (with the planted
`notes/` directory) spawned as instance `ctf-target` at
`172.19.89.77` — WSL-internal NAT only. Every read below was taken
under armed scopes; the arming env authorizes, it never names the
target.

## 1. The reads

- `wapiti scan` against `http://172.19.89.77:8080/` under
  `WAPITI_DISPATCH_SCOPE` — envelope `complete`, policy-report
  artifact recorded. The report surfaces the listener's honest
  response shape (missing hardening headers, cleartext channel) and
  the crawled pages.
- `page-fetch fetch` against `http://172.19.89.77:8080/notes/` under
  `PAGE_FETCH_DISPATCH_SCOPE` — envelope `complete`.
- Plain observation reads (for the walkthrough's evidence only):
  `curl -sI http://172.19.89.77:8080/` shows
  `Server: SimpleHTTP/0.6 Python/3.13.5`;
  `curl -s http://172.19.89.77:8080/notes/` returns the auto-index
  page `Directory listing for /notes/` linking
  `redeploy-checklist.txt`.

## 2. The planted findings (exactly the contract's three)

1. `demo-web-dir-listing` — `/notes/` renders the server's
   auto-generated directory index (the directory ships no
   `index.html`).
2. `demo-web-stale-file-exposed` — the listing links and serves
   `redeploy-checklist.txt`, a superseded (inert) ops note.
3. `demo-web-server-header` — every response carries the default
   implementation identification header.

Scope rule: the contract counts exactly the planted items. Wapiti's
generic hardening observations (missing CSP/X-Frame-Options/
X-Content-Type-Options, no HTTPS redirect) are true of any stock
python http.server and are NOT planted fixture items here — reporting
them as findings produces contract extras, which fail the grade, and
that is the correspondence contract working.

## 3. The graded pass

`python -m score --grade web-found.json --expected
challenges/lab-web-01-dast-surface/artifacts/expected-findings.json`
→ `passed: true, score: 1.0` (`web-found.json` in
`lab/records/lab-live-lanes-2026-09-06/` is the found document this
walkthrough shipped).

## 4. The runner cell

One runner command composed grading + arms lanes
(`web-report.json` in the same records directory):

```
python -m exercise --challenge lab-web-01-dast-surface \
  --found lab/records/lab-live-lanes-2026-09-06/web-found.json \
  --expected challenges/lab-web-01-dast-surface/artifacts/expected-findings.json \
  --arms '[{"arm_id":"wapiti","action":"scan","args":{"url":"http://172.19.89.77:8080/"}},{"arm_id":"page-fetch","action":"fetch","args":{"url":"http://172.19.89.77:8080/notes/"}}]'
```

Result: `complete`; grading 1.00; arms 2/2 (`wapiti`, `page-fetch`
both `complete`). The head-attempt lane is not part of this run and
must not be: the runner refuses live-service contracts for that lane
by design.
