"""Offline learning workflows; deliberately separate from extension.invoke."""

from __future__ import annotations

import importlib
import sys


COMMANDS = {
    "graph": "graph_evidence.importer",
    "review": "review_workpaper.__main__",
    "agent": "learning.agent_security_harness",
    "detection": "learning.detection_validation",
    "triage": "extension.triage.siftrank",
    "k8s": "k8s_path_evidence.__main__",
}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        print("usage: python -m learning {graph|k8s|review|agent|detection|triage} ...")
        return 0 if args else 2
    command = args.pop(0)
    if command not in COMMANDS:
        print(f"unknown learning workflow: {command}", file=sys.stderr)
        return 2
    module = importlib.import_module(COMMANDS[command])
    return int(module.main(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
