#!/usr/bin/env python3
"""Security Gate orchestrator: select targets, run scanners, then evaluate.

  python gate/cli.py --mode adaptive --repo . --base origin/main --head HEAD --out .gate-out
  python gate/cli.py --mode baseline --repo . --out .gate-out

Modes map to policy/<mode>.yml unless --policy is given.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yaml  # noqa: E402
from evaluate_gate import GATE_ROOT, evaluate, in_scope, matches_any  # noqa: E402

LANG_BY_EXT = {".java": "java", ".py": "python",
               ".c": "c", ".h": "c", ".cpp": "c", ".cc": "c", ".hpp": "c"}   # Semgrep "c" rules also parse C++
TIME_BIN = shutil.which("time") if os.path.exists("/usr/bin/time") else None


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout


def run_tool(name: str, cmd: list[str], out: Path, cwd: Path, tools: dict) -> bool:
    """Run one scanner, recording wall time, CPU time and peak memory."""
    tfile = out / f".{name}.time"
    full = ([TIME_BIN, "-f", "%e %U %S %M", "-o", str(tfile)] if TIME_BIN else []) + cmd
    t0 = time.perf_counter()
    proc = subprocess.run(full, cwd=cwd, capture_output=True, text=True)
    wall = time.perf_counter() - t0
    (out / f"{name}.stderr.log").write_text(proc.stderr[-20000:], encoding="utf-8")
    rec = {"status": "ok" if proc.returncode == 0 else "error", "exit_code": proc.returncode,
           "wall": round(wall, 3), "cmd": " ".join(cmd)}
    if tfile.exists():
        # GNU time prepends "Command exited with non-zero status N" on failure
        lines = tfile.read_text().strip().splitlines()
        parts = lines[-1].split() if lines else []
        if len(parts) >= 4:
            rec.update(cpu=round(float(parts[1]) + float(parts[2]), 3), max_rss_kb=int(parts[3]))
        tfile.unlink()
    tools[name] = rec
    if proc.returncode != 0:
        print(f"[gate] {name} failed (exit {proc.returncode}): {proc.stderr[-400:]}", file=sys.stderr)
    return proc.returncode == 0


def skip(name: str, why: str, tools: dict) -> None:
    tools[name] = {"status": "skipped", "reason": why, "wall": 0.0}


def export_manifests(repo: Path, ref: str, paths: list[str], dest: Path) -> list[str]:
    """Materialise the given manifest files as they exist at `ref` into dest/."""
    written = []
    for rel in paths:
        try:
            blob = subprocess.run(["git", "-C", str(repo), "show", f"{ref}:{rel}"],
                                  check=True, capture_output=True).stdout
        except subprocess.CalledProcessError:
            continue  # file did not exist at ref
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        written.append(rel)
    return written


def components(sbom_path: Path) -> list[str]:
    if not sbom_path.exists():
        return []
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    return sorted({f"{c.get('name')}@{c.get('version')}" for c in sbom.get("components", []) or []})


def main() -> None:
    ap = argparse.ArgumentParser(description="DT074 CI/CD Security Gate")
    ap.add_argument("--mode", choices=["baseline", "adaptive"], required=True)
    ap.add_argument("--repo", type=Path, default=Path("."))
    ap.add_argument("--base", help="base ref for differential scanning (adaptive)")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--out", type=Path, default=Path(".gate-out"))
    ap.add_argument("--policy", type=Path)
    ap.add_argument("--registry", type=Path, default=GATE_ROOT / "rules" / "registry")
    args = ap.parse_args()

    t_start = time.perf_counter()
    repo = args.repo.resolve()
    out = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    policy_path = args.policy or GATE_ROOT / "policy" / f"{args.mode}.yml"
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    scope = policy.get("scope", {})
    differential = scope.get("differential", False)

    head = git(repo, "rev-parse", args.head).strip()
    base = None
    if differential:
        if not args.base:
            sys.exit("[gate] adaptive mode needs --base")
        base = git(repo, "merge-base", args.base, head).strip()
        changed = git(repo, "diff", "--name-only", "--diff-filter=ACMR", base, head).split()
    else:
        changed = git(repo, "ls-files").split()
    repo_files = [p for p in git(repo, "ls-files").split() if in_scope(p, policy)]
    scanned = [p for p in changed if in_scope(p, policy) and (repo / p).is_file()]
    manifests_changed = [p for p in scanned if matches_any(p, scope.get("dependency_manifests", []))]

    tools: dict = {}
    meta = {"mode": args.mode, "repo": str(repo), "base": base or "", "head": head,
            "scope": {"changed_files": changed, "scanned_files": scanned,
                      "manifests_changed": manifests_changed},
            "repo_files": repo_files, "tools": tools}

    # ---- SAST: Semgrep -----------------------------------------------------
    entries = [c if isinstance(c, dict) else {"path": c} for c in policy["sast"]["configs"]]
    if differential and policy["sast"].get("language_aware"):
        langs = {LANG_BY_EXT.get(Path(p).suffix) for p in scanned} - {None}
        entries = [e for e in entries if not e.get("languages") or langs & set(e["languages"])]
    config_paths = [e["path"].format(registry=args.registry, gate=GATE_ROOT) for e in entries]
    meta["semgrep_configs"] = config_paths
    configs = [arg for c in config_paths for arg in ("--config", c)]
    semgrep = ["semgrep", "scan", "--metrics=off", "--disable-version-check", "--json",
               "--dataflow-traces", "--timeout", "30", "-q", "-o", str(out / "semgrep.json"), *configs]
    if differential:
        if scanned:
            run_tool("semgrep", semgrep + scanned, out, repo, tools)
        else:
            skip("semgrep", "no in-scope changed files", tools)
    else:
        run_tool("semgrep", semgrep + ["."], out, repo, tools)

    # ---- Secrets: Gitleaks ---------------------------------------------------
    gl = ["gitleaks", "git", ".", "--report-format", "json", "--report-path", str(out / "gitleaks.json"),
          "--exit-code", "0", "--no-banner", "--log-level", "error"]
    if differential:
        if base != head:
            run_tool("gitleaks", gl + ["--log-opts", f"{base}..{head}"], out, repo, tools)
        else:
            skip("gitleaks", "no new commits", tools)
    else:
        run_tool("gitleaks", gl, out, repo, tools)

    # ---- SBOM (Syft) -> SCA (Trivy) -------------------------------------------
    sbom = out / "sbom.cdx.json"
    syft = ["syft", "-q", "-o", f"cyclonedx-json={sbom}"]
    trivy = ["trivy", "sbom", "-q", "--skip-db-update", "--offline-scan", "--format", "json",
             "--output", str(out / "trivy.json"), str(sbom)]
    if not differential:
        if run_tool("syft", syft + ["dir:."], out, repo, tools):
            run_tool("trivy", trivy, out, repo, tools)
    elif manifests_changed or not policy.get("sbom", {}).get("only_on_manifest_change", True):
        with tempfile.TemporaryDirectory() as tmp:
            head_dir, base_dir = Path(tmp, "head"), Path(tmp, "base")
            export_manifests(repo, head, manifests_changed, head_dir)
            if export_manifests(repo, base, manifests_changed, base_dir):
                run_tool("syft_base", ["syft", "-q", "-o", f"cyclonedx-json={out / 'sbom_base.cdx.json'}",
                                       f"dir:{base_dir}"], out, repo, tools)
            if run_tool("syft", syft + [f"dir:{head_dir}"], out, repo, tools):
                run_tool("trivy", trivy, out, repo, tools)
        meta["base_components"] = components(out / "sbom_base.cdx.json")
    else:
        skip("syft", "no dependency manifest changed", tools)
        skip("trivy", "no dependency manifest changed", tools)

    meta["total_seconds"] = round(time.perf_counter() - t_start, 3)
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    result = evaluate(out, policy_path, repo)
    result["total_seconds"] = round(time.perf_counter() - t_start, 3)
    (out / "decision.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[gate] {args.mode}: {result['decision']} — {result['counts']['blocking']} blocking / "
          f"{result['counts']['total']} findings in {result['total_seconds']:.1f}s "
          f"({len(scanned)} file(s) in scope)")
    if policy.get("feedback", {}).get("markdown"):
        print(f"[gate] feedback: {out / policy['feedback']['markdown']}")
    else:
        sys.stdout.write((out / "baseline_raw.log").read_text(encoding="utf-8"))
    sys.exit(result["exit_code"])


def fail_closed(out: Path, exc: BaseException) -> None:
    """Any unexpected gate error must still produce a BLOCK decision (never fail open)."""
    out.mkdir(parents=True, exist_ok=True)
    result = {"mode": "unknown", "decision": "BLOCK", "exit_code": 1, "failed_tools": ["gate"],
              "error": f"{type(exc).__name__}: {exc}", "counts": {"total": 0, "blocking": 0, "advisory": 0},
              "total_seconds": 0.0, "tools": {}}
    (out / "decision.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "findings.json").write_text("[]", encoding="utf-8")
    print(f"[gate] internal error -> BLOCK (fail-closed): {result['error']}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        out_arg = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else ".gate-out"
        fail_closed(Path(out_arg).resolve(), exc)
        sys.exit(1)
