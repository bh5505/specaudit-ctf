# specaudit-ctf agent guidance

SpecAudit-CTF is a lab CTF tool. Its job is to run the supported arms and
exercises, return their results, and grade participant findings. The competent
human operator is responsible for choosing targets and for how the tool is used.

Do not build operator-permission systems into the tool: no scope-grant environment
variables, approval or rules-of-engagement references, admission tiers,
qualification gates, promotion records, or checkers that claim to transfer
accountability to the software. A warning or confirmation may inform an operator
about an action and let them continue; keep it simple and independent of any
approval registry.

Read [README.md](README.md) and the relevant arm or exercise code before editing.
Keep input validation, result reporting, tool authentication, and ordinary error
handling tied to the operation they serve. Test the affected CLI, MCP, exercise,
and grading paths. Keep private host paths, credentials, generated artifacts,
and unrelated work out of commits.
