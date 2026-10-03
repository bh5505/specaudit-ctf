# Synthetic Kubernetes RBAC path review — learner packet

**ID:** `lab-k8s-01-rbac-path` · **status:** design-ready · **domains:** CYB-03/CYB-07, T08 · **audience:** intermediate analyst · **version:** 0.1. The fixture contains no credentials, live cluster address, real secret contents, model call, or executable target. Do not run k8scout or kubectl. Use the bundled report and capture only.

The original `report.json` is shaped to the k8scout **offensive-mode JSON Report** at source revision `031c8bc4fc6579aab9d1df2e781697968028a427`; it was independently authored, not obtained from a real cluster. `capture.json` pins the report SHA-256, subject and synthetic scope. The declared `test_cases` ask about BLUE secret read, RED role-binding creation and a RED secret-read check that is missing. This teaching packet's reporter version is `0.0.0-synthetic`; the source revision identifies the schema, not a claim that the upstream tool generated the bytes.

Run from the repository root:

```sh
python -m k8s_path_evidence --report k8s_path_evidence/fixture/report.json --capture k8s_path_evidence/fixture/capture.json
```

The CLI emits JSON `{ok, result}` and exits 0 on a validated capture; on refusal it emits `{ok:false,error}` and exits 1. `python -m learning k8s` delegates to the same interface when installed with the learning dispatcher. Work from `case_evaluations`, raw SSAR records, graph edges and the explicit limitations. Submit a human workpaper stating which branch is a *candidate*, which is blocked by a reported check, which is unknown, and the exact evidence and retest needed to establish effective access. Explain why `risk_findings` is a tool hypothesis and why an inferred graph edge does not prove a secret was read. Review changes in namespace, binding, identity and SSRR/SSAR coverage before transferring any conclusion beyond this fixture.

The importer keeps only a closed subset: report metadata, subject, SSAR checks, node identities, directed edges, finding IDs/path references, and selected capture provenance. It drops descriptions, risk scores, free-text evidence, cluster object details beyond namespace names, SSRR rule contents, and audit footprint from the normalized output. It rejects `ai_narrative` entirely. Missing/partial data must be retained as unknown, never filled from dropped fields. Limits: 1 MiB report/capture, 500 rows per imported array. Hash validation does not make a mutable file immutable after the read; distribute a read-only packet and preserve the raw bytes for independent review.

Environment E0, local-only. No network, cloud, cluster, model, egress, or cost is authorized; one learner copy, no runtime reset, stop on a request to inspect real assets. Accessible equivalent: read the two JSON files and complete the same workpaper by hand. The instructor key is outside this distributable packet. Hints: first compare check decisions; then inspect whether the edge is marked inferred. Hints count as assisted completion in human review.
