#!/usr/bin/env python3
"""Convenience entry point with the naming used in the project brief.

  python scripts/evaluate_gate.py --variant baseline --repo .
  python scripts/evaluate_gate.py --variant proposed --repo . --base origin/main

`baseline` -> full scan + zero tolerance + raw log      (policy/baseline.yml)
`proposed` -> differential + risk triage + feedback .md (policy/adaptive.yml)
Must run where the scanners exist (the security-gate container or CI).
Extra arguments are forwarded to gate/cli.py.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
args = sys.argv[1:]
if "--variant" not in args:
    sys.exit(__doc__)
i = args.index("--variant")
variant = args[i + 1]
mode = {"baseline": "baseline", "proposed": "adaptive", "adaptive": "adaptive"}.get(variant)
if not mode:
    sys.exit(f"unknown variant {variant!r}: use baseline | proposed")
rest = args[:i] + args[i + 2:]
cli = str(ROOT / "gate" / "cli.py")
os.execv(sys.executable, [sys.executable, cli, "--mode", mode, *rest])
