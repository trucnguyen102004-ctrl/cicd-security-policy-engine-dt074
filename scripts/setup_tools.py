#!/usr/bin/env python3
"""Build and verify the pinned scanner toolchain (Semgrep, Gitleaks, Trivy, Syft).

Why one pinned image instead of `:latest` tags: `latest` moves whenever a vendor
releases, so three runs a few days apart could use three different scanners and
CVE databases. The Dockerfile pins every version and checks the vendor SHA-256;
the Semgrep rule snapshot and Trivy DB are frozen at build time.

  python scripts/setup_tools.py            # build image security-gate:1.0 and verify
  python scripts/setup_tools.py --verify   # only print versions from an existing image
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("GATE_IMAGE", "security-gate:1.0")
EXPECTED = {"semgrep": "1.178.0", "gitleaks": "8.30.1", "trivy": "0.74.0", "syft": "1.52.0"}


def docker() -> str:
    exe = shutil.which("docker")
    if not exe and os.name == "nt":  # Docker Desktop per-user install is not always on PATH
        cand = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe"
        exe = str(cand) if cand.exists() else None
    if not exe:
        sys.exit("docker not found — install Docker Desktop (WSL2 backend) first")
    return exe


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--no-cache", action="store_true")
    args = ap.parse_args()
    d = docker()
    if not args.verify:
        cmd = [d, "build", "-t", IMAGE, str(ROOT)] + (["--no-cache"] if args.no_cache else [])
        print("[tools] " + " ".join(cmd))
        subprocess.run(cmd, check=True)
    out = subprocess.run([d, "run", "--rm", "--entrypoint", "cat", IMAGE, "/opt/gate/TOOL_VERSIONS.txt",
                          "/opt/gate/rules/registry/SNAPSHOT.sha256"], check=True,
                         capture_output=True, text=True).stdout
    print(out)
    missing = [f"{t} {v}" for t, v in EXPECTED.items() if v not in out]
    if missing:
        sys.exit(f"[tools] version mismatch: {missing}")
    print(f"[tools] OK — {IMAGE} contains " + ", ".join(f"{t} {v}" for t, v in EXPECTED.items()))


if __name__ == "__main__":
    main()
