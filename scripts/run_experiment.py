#!/usr/bin/env python3
"""Controlled experiment: Baseline vs Proposed (adaptive) gate on the SARD subset.

Every labelled case is replayed as one simulated pull request:
  commit 1 (base) = host repository for the chosen profile
  commit 2 (head) = base + the case file(s)
and each gate variant decides PASS/BLOCK on that commit.

Profiles
  isolated   host repo is empty -> measures each gate's detection logic alone
  realistic  host repo is the demo app in app/ (with its pre-existing advisory
             findings and a known-vulnerable pinned dependency) -> measures
             what a developer actually experiences in CI
Variants
  baseline, adaptive, and (with --ablation) adaptive minus one mechanism.

Usage (inside the gate container):
  python scripts/run_experiment.py --runs 3 --seed 42 --out results/exp1
  python scripts/run_experiment.py --runs 1 --ablation --profiles isolated --out results/ablation
  python scripts/run_experiment.py --runs 3 --scale 0,5,20 --cases J01-bad,J01-good --out results/scale
"""
from __future__ import annotations

import argparse
import copy
import csv
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
WORK = Path(os.environ.get("EXP_WORKDIR", "/tmp/dt074-exp"))

ABLATIONS = {
    # name: (description, mutation of the adaptive policy)
    "no_differential": ("scan the whole repository instead of the diff",
                        lambda p: p["scope"].update(differential=False)),
    "no_language_aware": ("load every rule pack regardless of changed languages",
                          lambda p: p["sast"].update(language_aware=False)),
    "no_custom_rules": ("registry rules only (drop dt074.* custom rules)",
                        lambda p: p["sast"].update(configs=[c for c in p["sast"]["configs"]
                                                            if "custom" not in c["path"]])),
    "no_risk_threshold": ("block every SAST finding (no OWASP risk / confidence / audit filter)",
                          lambda p: p["sast"].update(block_at="INFO", min_confidence="LOW", audit_blocks=True)),
    "no_sanitizer_triage": ("do not downgrade findings on sanitised lines",
                            lambda p: p["sast"].update(sanitizer_triage=False)),
    "no_sca_triage": ("block every CVE (no severity / fix / reachability / new-only filter)",
                      lambda p: p["sca"].update(only_new_components=False, always_block=[
                          "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])),
}


def sh(*cmd, cwd=None, check=True):
    return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)


def load_cases(splits: list[str], only: set[str] | None, labels: str = "labels.csv") -> list[dict]:
    with (DATASET / labels).open(encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r["split"] in splits]
    return [r for r in rows if not only or r["case_id"] in only]


def place_case(case: dict, ws: Path) -> list[str]:
    """Copy the case into the host repo where a developer would put it."""
    src = DATASET / case["path"]
    if case["kind"] == "sca":
        dest = ws / "app" / "modules" / src.name
        shutil.copytree(src, dest)
        return [p.relative_to(ws).as_posix() for p in dest.rglob("*") if p.is_file()]
    sub = {"java": "java/src/main/java/edu/demo", "python": "python", "c": "c/src"}[case["lang"]]
    dest = ws / "app" / sub / src.name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return [dest.relative_to(ws).as_posix()]


def build_workspace(case: dict, profile: str, scale: int) -> Path:
    ws = WORK / "ws"
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    sh("git", "init", "-q", "-b", "main", cwd=ws)
    (ws / "README.md").write_text("# demo service\n", encoding="utf-8")
    if profile == "realistic":
        shutil.copytree(ROOT / "app", ws / "app")
        for i in range(scale):  # scalability study: grow the repo with extra modules
            shutil.copytree(ROOT / "app", ws / "legacy" / f"module_{i:03d}")
    sh("git", "add", "-A", cwd=ws)
    sh("git", "commit", "-qm", "base", cwd=ws)
    place_case(case, ws)
    sh("git", "add", "-A", cwd=ws)
    sh("git", "commit", "-qm", f"PR: {case['case_id']}", cwd=ws)
    return ws


def write_policies(out: Path, ablation: bool, policy_dir: Path) -> dict[str, Path]:
    pol_dir = out / "policies"
    pol_dir.mkdir(parents=True, exist_ok=True)
    variants = {"baseline": policy_dir / "baseline.yml", "adaptive": policy_dir / "adaptive.yml"}
    if ablation:
        base = yaml.safe_load(variants["adaptive"].read_text(encoding="utf-8"))
        for name, (desc, mutate) in ABLATIONS.items():
            p = copy.deepcopy(base)
            mutate(p)
            p["name"], p["description"] = f"adaptive-{name}", desc
            path = pol_dir / f"adaptive-{name}.yml"
            path.write_text(yaml.safe_dump(p, sort_keys=False), encoding="utf-8")
            variants[f"adaptive-{name}"] = path
    for name, path in variants.items():
        if path.parent != pol_dir:
            shutil.copy2(path, pol_dir / f"{name}.yml")
    return variants


def run_gate(ws: Path, variant: str, policy: Path, dest: Path) -> dict:
    mode = "baseline" if variant == "baseline" else "adaptive"
    cmd = [sys.executable, str(ROOT / "gate" / "cli.py"), "--mode", mode, "--repo", str(ws),
           "--out", str(dest), "--policy", str(policy)]
    if os.environ.get("GATE_REGISTRY"):
        cmd += ["--registry", os.environ["GATE_REGISTRY"]]
    if mode == "adaptive":
        cmd += ["--base", "HEAD~1"]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    wall = time.perf_counter() - t0
    (dest / "gate.stdout.log").write_text(proc.stdout, encoding="utf-8")
    (dest / "gate.stderr.log").write_text(proc.stderr, encoding="utf-8")
    decision = json.loads((dest / "decision.json").read_text(encoding="utf-8"))
    findings = json.loads((dest / "findings.json").read_text(encoding="utf-8"))
    tools = decision.get("tools", {})
    return {
        "decision": decision["decision"], "blocked": int(decision["decision"] == "BLOCK"),
        "exit_code": proc.returncode, "wall_s": round(wall, 3),
        "cpu_s": round(sum(t.get("cpu", 0) for t in tools.values()), 3),
        "max_rss_mb": round(max([t.get("max_rss_kb", 0) for t in tools.values()] or [0]) / 1024, 1),
        **{f"t_{n}": t.get("wall", 0) for n, t in tools.items()},
        "n_findings": decision["counts"]["total"], "n_blocking": decision["counts"]["blocking"],
        "n_issues": decision["counts"].get("blocking_issues", 0),
        "failed_tools": ";".join(decision.get("failed_tools", [])),
        "blocking_rules": ";".join(sorted({f["rule_id"].rsplit(".", 1)[-1] for f in findings if f["blocking"]})),
    }


def environment_info(out: Path) -> dict:
    info = {"started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "platform": platform.platform(), "python": platform.python_version(),
            "cpu_count": os.cpu_count()}
    try:
        info["cpu_model"] = next(l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo")
                                 if l.startswith("model name"))
        info["mem_total_kb"] = int(next(l.split()[1] for l in open("/proc/meminfo") if l.startswith("MemTotal")))
    except (OSError, StopIteration):
        pass
    for f in (ROOT / "TOOL_VERSIONS.txt", Path("/opt/gate/TOOL_VERSIONS.txt")):
        if f.exists():
            info["tool_versions"] = f.read_text(encoding="utf-8")
            break
    reg = Path(os.environ.get("GATE_REGISTRY", ROOT / "rules" / "registry"))
    if (reg / "SNAPSHOT.sha256").exists():
        info["semgrep_registry_snapshot"] = (reg / "SNAPSHOT.sha256").read_text()
        info["semgrep_registry_date"] = (reg / "SNAPSHOT_DATE").read_text().strip()
    meta = Path(os.environ.get("TRIVY_CACHE_DIR", "/opt/trivy-cache")) / "db" / "metadata.json"
    if meta.exists():
        info["trivy_db"] = json.loads(meta.read_text())
    info["dataset_manifest_sha256"] = sh("sha256sum", str(DATASET / "manifest.sha256"), check=False).stdout.split(" ")[0]
    info["gate_commit"] = sh("git", "-C", str(ROOT), "rev-parse", "HEAD", check=False).stdout.strip() or "n/a"
    return info


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--profiles", default="isolated,realistic")
    ap.add_argument("--splits", default="main,holdout")
    ap.add_argument("--variants", default="", help="comma list; default baseline,adaptive(+ablations)")
    ap.add_argument("--ablation", action="store_true")
    ap.add_argument("--scale", default="0", help="comma list of extra legacy modules (realistic profile)")
    ap.add_argument("--cases", default="", help="comma list of case_ids to restrict to")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--labels", default="labels.csv", help="labels file under dataset/ (labels_cpp.csv for SARD #112)")
    ap.add_argument("--policy-dir", type=Path, default=ROOT / "policy", help="directory with baseline.yml / adaptive.yml")
    ap.add_argument("--keep-raw", action="store_true", default=True)
    args = ap.parse_args()

    if sh(sys.executable, str(ROOT / "scripts" / "setup_fixtures.py"), "--verify-only", check=False).returncode:
        sys.exit("[exp] dataset manifest verification failed — run scripts/setup_fixtures.py")

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    variants = write_policies(out, args.ablation, args.policy_dir.resolve())
    if args.variants:
        variants = {k: v for k, v in variants.items() if k in args.variants.split(",")}
    cases = load_cases(args.splits.split(","), set(filter(None, args.cases.split(","))), args.labels)
    scales = [int(s) for s in args.scale.split(",")]
    config = {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()}
    config["variants"] = {k: str(v) for k, v in variants.items()}
    config["n_cases"] = len(cases)
    (out / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    (out / "environment.json").write_text(json.dumps(environment_info(out), indent=2), encoding="utf-8")

    fields = None
    total = args.runs * len(args.profiles.split(",")) * len(scales) * len(cases) * len(variants)
    done = 0
    t_all = time.perf_counter()
    with (out / "runs.csv").open("w", newline="", encoding="utf-8") as fh:
        for run in range(1, args.runs + 1):
            rng = random.Random(args.seed + run)       # fixed, per-run case order
            for profile in args.profiles.split(","):
                for scale in scales if profile == "realistic" else [0]:
                    order = cases[:]
                    rng.shuffle(order)
                    for idx, case in enumerate(order):
                        ws = build_workspace(case, profile, scale)
                        names = list(variants)
                        if (run + idx) % 2:                 # alternate execution order
                            names.reverse()
                        for variant in names:
                            dest = out / "raw" / profile / f"scale{scale}" / f"run{run}" / case["case_id"] / variant
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            res = run_gate(ws, variant, variants[variant], dest)
                            row = {"run": run, "profile": profile, "scale": scale, "variant": variant,
                                   "order": idx, **{k: case[k] for k in
                                                    ("case_id", "pair", "label", "cwe", "lang", "kind", "split")},
                                   **res}
                            if fields is None:
                                fields = list(row) + ["t_syft_base"]
                                for t in ("t_semgrep", "t_gitleaks", "t_syft", "t_trivy"):
                                    if t not in fields:
                                        fields.append(t)
                                writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore",
                                                        lineterminator="\n")
                                writer.writeheader()
                            writer.writerow(row)
                            fh.flush()
                            done += 1
                            print(f"[exp] {done}/{total} run{run} {profile} s{scale} {case['case_id']:<9} "
                                  f"{variant:<32} {res['decision']:<10} {res['wall_s']:.1f}s", flush=True)
    print(f"[exp] finished {done} gate executions in {time.perf_counter() - t_all:.0f}s -> {out}/runs.csv")


if __name__ == "__main__":
    main()
