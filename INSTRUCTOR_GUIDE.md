# Instructor guide

Choose a challenge from the [index](challenges/README.md) and read its README and expected-findings contract. Give participants the learner brief and the inputs needed for that exercise. Keep the expected findings and walkthrough aside until review so the exercise remains useful.

For a fixture challenge, run `python -m extension.range` to check the synthetic range. For a live-service challenge, start the local service using that challenge's instructions and confirm that the service responds before the attempt. The operator selects the host, network, and any external tool configuration; the CTF does not decide whether those choices are authorized.

Ask participants to explain each finding with the observed input and expected behavior. Grade the submitted JSON with:

```sh
python -m score --grade FOUND.json --expected CONTRACT.json
```

The exact grader reports misses and extra findings. Review the reasoning and tool output separately, including cases where the grader passes but the explanation is weak. Share the solution and walkthrough after the attempt. Stop local services and remove disposable outputs before the next participant. Use [operations](OPERATIONS.md) for command setup and exercise composition.
