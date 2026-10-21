# CTF learning path

The shipped challenges practice finding planted issues, explaining the evidence, and reporting what a test did and did not show. Work through the challenge briefs in this order or select one exercise directly.

| Stage | Challenges | Practice |
|---|---|---|
| Cloud basics | [AWS 01–02](challenges/README.md) | Reachability, IAM, and S3 configuration. |
| Paths and near misses | [AWS 03–05](challenges/README.md) | Privilege paths, network exposure, and logging gaps. |
| Combined challenge | [AWS 06](challenges/telecom-aws-06-chain-rehearsal/README.md) | Connect discovery, exposure, and impact in one findings set. |
| Local services and code | [Lab web, network, edge, and code](challenges/README.md) | Observe planted services or source and explain results. |
| Tool and evidence reasoning | [Knowledge and emulation labs](challenges/README.md) | Map techniques and interpret tool output. |

Each challenge README states its inputs and deliverable. Fixture-based tasks use a local synthetic range. Live-service tasks use the services the operator starts for the lab. The [challenge index](challenges/README.md) identifies each lane and its fixtures.

For exact-grading challenges, submit a JSON findings document matching the challenge's contract shape and run `python -m score --grade FOUND.json --expected CONTRACT.json`. A pass means the submission matches that contract; it does not certify a real-world assessment. The [instructor guide](INSTRUCTOR_GUIDE.md) covers sharing a brief, running the exercise, reviewing results, and resetting local state.
