# Challenge packet and grading API reference

Start new operations with the [unified operator console](operations-console.md).
This page documents the underlying compatibility API and its data contracts.

The installed package exposes an operator-only command for the 13 shipped
exact-coverage challenges. It is not an extension arm or MCP tool. Run it in
an operator-controlled E1 environment; export only the prepared packet to
learners. Exporting files is not operating-system isolation. Use separate
identities, filesystem access and custody controls before delivery.

Run from a checkout or installed wheel, with Python 3.11+:

    python -m exercise_operator inventory
    python -m exercise_operator prepare telecom-aws-01-reachability --out /tmp/learner-01
    python -m exercise_operator rehearse --out /tmp/operator-range-01
    cp /tmp/learner-01/findings-template.json /tmp/submitted-01.json
    # Fill submitted-01.json with evidence-supported rows, then:
    python -m exercise_operator grade telecom-aws-01-reachability \
      --packet /tmp/learner-01 --found /tmp/submitted-01.json \
      --out /tmp/operator-grade-01

Use fresh output directories. Enforce access to operator range and grade
directories outside the learner process. Inventory distinguishes seven
fixture-backed offline packet tracks, five live-service tracks and one
planted-code track. It shows original contract fixture notes and the reviewed
input roster, including challenge 02's cross fixture. Live-service and
planted-code tracks can use standalone exact comparison of separately
captured submissions, but prepare refuses them. This CLI does not provision
targets, launch framework catalogs, run scans or attest target contact. The
four additional learning pilots are separate from these exact contracts.

Prepare exports a short brief, empty findings template, shared public
key/control vocabulary across all fixture-backed tracks (including
nonapplicable candidates), and only four inputs per selected synthetic
fixture. It never exports challenge READMEs (which can contain answers),
expected.json mirrors, expected-findings contracts, solutions, instructor
keys or range-derived results. Choose only evidence-supported candidates;
supply your own severity, rationale and precise traces_to. Copy the template
outside the packet before editing. The public vocabulary is not a selection
of correct answers for a particular challenge.

Rehearse dispatches the entire shipped synthetic range at seed 123 with an
explicit empty arm list. It never auto-discovers installed scanners or
contacts a target. Its operator directory retains the execution-result
envelope and a Mode A digest-named, verified range-report artifact, with
hashes in the manifest. The full range includes fixtures outside the
selected challenge. Keep its answer-bearing report on the operator side.
A failed or incomplete dispatch remains failed. Mode A requires Unix
descriptor-relative artifact custody; an unsupported host refuses.

Grade captures at most 1 MiB from a regular nofollow submission file,
rejects duplicate JSON keys, non-finite numbers and excessive nesting, then
uses the existing score.grading comparison unchanged. Optional --packet
recomputes canonical packet bytes from the packaged contracts, vocabulary
and fixtures, verifies the manifest and files, and records the manifest
hash. Submission and grade output must be outside that packet. The grader
reads fixed private snapshots, records exact submission and contract SHA-256
hashes, and retains submission.json, grade.json (when structurally gradable)
and manifest.json on the operator side. Preserve the matching operator
package version/corpus for replay. Without --packet, grading remains
available for independently controlled submissions, including live-service
and planted-code lanes, but no packet binding is claimed. Canonical byte
comparison detects edits including a rewritten manifest. It is not
producer authentication or access control; a learner with operator
installation access can read packaged contracts.

Exit 0 means preparation/rehearsal completed or exact grade passed; exit 1
means comparison or rehearsal failed; exit 2 means refusal/malformed input.
Exact grading checks track match, finding keys and non-empty owned
fields against a non-empty contract. It does not verify seed, fixture identity, evidence
truth, provenance, actual testing, workpaper quality or live-service
effectiveness. Severity differences are advisory. Retain negative, partial
and refused reports with attempt records; never export operator reports as
learner packets.
