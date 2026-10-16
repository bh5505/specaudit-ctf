# specaudit-ctf agent guidance

Start with [README.md](README.md) for the public runtime/package map,
[OPERATIONS.md](OPERATIONS.md) for operational authorization and containment,
[extension/README.md](extension/README.md) for adapter contracts, and
[tests/](tests/) for executable expectations. This is a standalone public repo;
keep private host paths, credentials, and internal artifacts out of commits.

## Package constraints and validation

- Preserve fail-closed scope/dispatch admission and synthetic-range containment.
  Do not target live engagements, cloud accounts, networks, or third-party
  systems without the explicit scope required by the operational contract.
- Survey/catalog presence is not a shipping, support, installation, or capability
  claim. Preserve distinctions among research, experimental, maintained, and
  held support tiers; use the current catalog and tests as authority.
- Runtime head profiles and extension skills are product integration surfaces,
  separate from development-agent workflow. Verify their contracts before editing.
- Use the existing Python environment and commands from the README/pyproject.
  Run targeted `python -m pytest tests/<relevant-test>.py` for behavior changes,
  and broader tests when affected contracts warrant it. For docs-only changes,
  check links, command accuracy, consistency, and whitespace.
- Keep generated results, local builds, credentials, and unrelated in-progress
  changes out of the deliverable. Review scope includes added files.

