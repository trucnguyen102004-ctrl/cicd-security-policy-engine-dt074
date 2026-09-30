#!/usr/bin/env python3
"""Compute metrics, statistical tests and charts from results/<exp>/runs.csv.

Metrics per (profile, split, variant):
  Detection coverage  = recall on bad cases          (Wilson 95% CI)
  False Block Rate    = blocked good / all good      (Wilson 95% CI)
  Precision, F1, MCC, balanced accuracy (not accuracy alone)
  CI duration         = gate wall time per commit, mean ± sd, p50/p95,
                        stability = sd of the per-run means, CV
Paired comparisons vs baseline:
  decisions -> exact McNemar test on per-case majority decisions
  durations -> mean difference with seeded paired-bootstrap 95% CI
Also: decision stability across runs, per-CWE breakdown, error list.

Usage: python scripts/analyze.py results/exp1 [--charts]
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value for discordant counts b, c."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def bootstrap_diff(a: list[float], b: list[float], seed: int = 42, n: int = 5000) -> tuple[float, float, float]:
    """Paired bootstrap CI of mean(b - a)."""
    diffs = [y - x for x, y in zip(a, b)]
    rng = random.Random(seed)
    means = sorted(st.fmean(rng.choices(diffs, k=len(diffs))) for _ in range(n))
    return st.fmean(diffs), means[int(0.025 * n)], means[int(0.975 * n)]


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]


def fmt_ci(p: float, ci: tuple[float, float]) -> str:
    return f"{100 * p:.1f}% [{100 * ci[0]:.1f}–{100 * ci[1]:.1f}]"


# CWE families used for "CWE-matched" detection: a block only counts as a correct
# detection if at least one *blocking* finding belongs to the labelled weakness.
CWE_FAMILY = {
    "CWE-89": {"CWE-89", "CWE-564", "CWE-943"},
    "CWE-79": {"CWE-79", "CWE-80", "CWE-81", "CWE-83"},
    "CWE-22": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    "CWE-798": {"CWE-798", "CWE-259", "CWE-321", "CWE-522", "CWE-547"},
    "CWE-78": {"CWE-78", "CWE-77"},
}


def matched_block(exp: Path, r: dict) -> int | None:
    """1 if a blocking finding matches the case's CWE family, 0 if not, None if raw log missing."""
    f = exp / "raw" / r["profile"] / f"scale{r.get('scale') or 0}" / f"run{r['run']}" / r["case_id"] / r["variant"] / "findings.json"
    if not f.exists():
        return None
    blocking = [x for x in json.loads(f.read_text(encoding="utf-8")) if x["blocking"]]
    if r["kind"] == "sca":
        return int(any(x["tool"] == "trivy" for x in blocking))
    fam = CWE_FAMILY.get(r["cwe"], {r["cwe"]})
    return int(any(set(x["cwe"]) & fam for x in blocking))


def load(exp: Path) -> list[dict]:
    with (exp / "runs.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        r["matched"] = matched_block(exp, r) if r["label"] == "bad" else None
        r["blocked"] = int(r["blocked"])
        r["wall_s"] = float(r["wall_s"])
        r["cpu_s"] = float(r["cpu_s"] or 0)
        r["max_rss_mb"] = float(r["max_rss_mb"] or 0)
        r["run"] = int(r["run"])
        r["scale"] = int(r.get("scale") or 0)
    return rows


def majority(rows: list[dict]) -> dict[str, int]:
    """case_id -> blocked decision agreed by the majority of runs."""
    votes = defaultdict(list)
    for r in rows:
        votes[r["case_id"]].append(r["blocked"])
    return {k: int(sum(v) * 2 > len(v)) for k, v in votes.items()}


def confusion(dec: dict[str, int], labels: dict[str, str]) -> dict:
    tp = sum(1 for c, b in dec.items() if labels[c] == "bad" and b)
    fn = sum(1 for c, b in dec.items() if labels[c] == "bad" and not b)
    fp = sum(1 for c, b in dec.items() if labels[c] == "good" and b)
    tn = sum(1 for c, b in dec.items() if labels[c] == "good" and not b)
    recall = tp / (tp + fn) if tp + fn else float("nan")
    fbr = fp / (fp + tn) if fp + tn else float("nan")
    prec = tp / (tp + fp) if tp + fp else float("nan")
    f1 = 2 * prec * recall / (prec + recall) if tp else 0.0
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom else 0.0
    return dict(tp=tp, fn=fn, fp=fp, tn=tn, recall=recall, recall_ci=wilson(tp, tp + fn),
                fbr=fbr, fbr_ci=wilson(fp, fp + tn), precision=prec, f1=f1, mcc=mcc,
                balanced_acc=(recall + (1 - fbr)) / 2)


def analyze(rows: list[dict]) -> dict:
    labels = {r["case_id"]: r["label"] for r in rows}
    meta = {r["case_id"]: r for r in rows}
    groups = defaultdict(list)
    for r in rows:
        groups[(r["profile"], r["scale"], r["split"], r["variant"])].append(r)
    for r in rows:  # also the pooled main+holdout view
        groups[(r["profile"], r["scale"], "all", r["variant"])].append(r)

    report = {}
    for key, g in sorted(groups.items()):
        dec = majority(g)
        cm = confusion(dec, labels)
        walls = [r["wall_s"] for r in g]
        per_run = defaultdict(list)
        for r in g:
            per_run[r["run"]].append(r["wall_s"])
        run_means = [st.fmean(v) for v in per_run.values()]
        per_case = defaultdict(set)
        for r in g:
            per_case[r["case_id"]].add(r["blocked"])
        stable = sum(1 for v in per_case.values() if len(v) == 1) / len(per_case)
        by_cwe = defaultdict(lambda: [0, 0, 0, 0])  # bad_blocked, bad, good_blocked, good
        for c, b in dec.items():
            idx = 0 if labels[c] == "bad" else 2
            by_cwe[meta[c]["cwe"]][idx] += b
            by_cwe[meta[c]["cwe"]][idx + 1] += 1
        mvotes = defaultdict(list)
        for r in g:
            if r["matched"] is not None:
                mvotes[r["case_id"]].append(r["matched"])
        mdec = {c: int(sum(v) * 2 > len(v)) for c, v in mvotes.items()}
        mk, mn = sum(mdec.values()), len(mdec)
        report["|".join(map(str, key))] = {
            **cm, "matched_recall": mk / mn if mn else float("nan"), "matched_ci": wilson(mk, mn),
            "matched_k": mk, "matched_n": mn, "n_cases": len(dec), "n_exec": len(g), "runs": len(per_run),
            "wall_mean": st.fmean(walls), "wall_sd": st.stdev(walls) if len(walls) > 1 else 0.0,
            "wall_p50": pct(walls, 0.5), "wall_p95": pct(walls, 0.95),
            "run_mean_sd": st.stdev(run_means) if len(run_means) > 1 else 0.0,
            "wall_cv": (st.stdev(walls) / st.fmean(walls)) if len(walls) > 1 else 0.0,
            "cpu_mean": st.fmean(r["cpu_s"] for r in g),
            "rss_max": max(r["max_rss_mb"] for r in g),
            "rss_mean": st.fmean(r["max_rss_mb"] for r in g),
            "decision_stability": stable,
            "by_cwe": dict(by_cwe),
            "errors": sorted(
                [{"case": c, "type": "FN" if labels[c] == "bad" else "FP",
                  "rules": sorted({r["blocking_rules"] for r in g if r["case_id"] == c} - {""})}
                 for c, b in dec.items() if (labels[c] == "bad") != bool(b)], key=lambda e: e["case"]),
        }
    # paired comparisons against the baseline in the same profile/scale/split
    for key, res in report.items():
        profile, scale, split, variant = key.split("|")
        base_key = f"{profile}|{scale}|{split}|baseline"
        if variant == "baseline" or base_key not in report:
            continue
        g_b = [r for r in groups[(profile, int(scale), split, "baseline")]]
        g_v = [r for r in groups[(profile, int(scale), split, variant)]]
        d_b, d_v = majority(g_b), majority(g_v)
        correct = lambda c, d: int((labels[c] == "bad") == bool(d[c]))  # noqa: E731
        common = sorted(set(d_b) & set(d_v))            # paired cases only
        b = sum(1 for c in common if correct(c, d_b) and not correct(c, d_v))
        c_ = sum(1 for c in common if not correct(c, d_b) and correct(c, d_v))
        pair_b = {(r["run"], r["case_id"]): r["wall_s"] for r in g_b}
        pair_v = {(r["run"], r["case_id"]): r["wall_s"] for r in g_v}
        keys = sorted(set(pair_b) & set(pair_v))
        mean_d, lo, hi = bootstrap_diff([pair_b[k] for k in keys], [pair_v[k] for k in keys])
        res["vs_baseline"] = {
            "mcnemar_b_only_baseline_correct": b, "mcnemar_c_only_variant_correct": c_,
            "mcnemar_p": mcnemar_exact(b, c_),
            "wall_diff_mean": mean_d, "wall_diff_ci": [lo, hi],
            "speedup": report[base_key]["wall_mean"] / res["wall_mean"],
        }
    return report


def markdown(report: dict, exp: Path) -> str:
    env = json.loads((exp / "environment.json").read_text()) if (exp / "environment.json").exists() else {}
    md = [f"# Experiment results — `{exp.name}`", "",
          f"- Host: {env.get('cpu_model', '?')} · {env.get('cpu_count', '?')} vCPU · "
          f"{int(env.get('mem_total_kb', 0)) // 1024} MB RAM (container)",
          f"- Started: {env.get('started_utc', '?')} · dataset manifest `{env.get('dataset_manifest_sha256', '?')[:16]}`",
          f"- Trivy DB: {env.get('trivy_db', {}).get('UpdatedAt', '?')} · Semgrep registry snapshot {env.get('semgrep_registry_date', '?')}",
          "", "Decisions use the per-case majority over runs; 95% CIs are Wilson intervals; "
          "p-values are exact McNemar vs baseline; Δt is the paired-bootstrap mean difference (s).", ""]
    md += ["| Profile | Split | Variant | Detection coverage (recall) | CWE-matched coverage | False Block Rate | Precision | F1 | MCC |"
           " CI duration μ±σ (s) | p95 (s) | Speed-up | Δt [95% CI] | McNemar p | Stable |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for key, r in report.items():
        profile, scale, split, variant = key.split("|")
        vs = r.get("vs_baseline", {})
        prof = profile + (f" (+{scale} modules)" if scale != "0" else "")
        md.append(
            f"| {prof} | {split} | {variant} | {fmt_ci(r['recall'], r['recall_ci'])} ({r['tp']}/{r['tp'] + r['fn']}) | "
            f"{fmt_ci(r['matched_recall'], r['matched_ci'])} ({r['matched_k']}/{r['matched_n']}) | "
            f"{fmt_ci(r['fbr'], r['fbr_ci'])} ({r['fp']}/{r['fp'] + r['tn']}) | "
            f"{r['precision']:.2f} | {r['f1']:.2f} | {r['mcc']:.2f} | "
            f"{r['wall_mean']:.2f} ± {r['wall_sd']:.2f} | {r['wall_p95']:.2f} | "
            f"{('%.2f×' % vs['speedup']) if vs else '—'} | "
            f"{('%+.2f [%+.2f, %+.2f]' % (vs['wall_diff_mean'], *vs['wall_diff_ci'])) if vs else '—'} | "
            f"{('%.4f' % vs['mcnemar_p']) if vs else '—'} | {100 * r['decision_stability']:.0f}% |")
    md += ["", "## Resource cost", "", "| Profile | Split | Variant | CPU s / commit | Peak RSS mean (MB) | Peak RSS max (MB) | Run-mean σ (s) | CV |",
           "|---|---|---|---|---|---|---|---|"]
    for key, r in report.items():
        profile, scale, split, variant = key.split("|")
        md.append(f"| {profile}{'+' + scale if scale != '0' else ''} | {split} | {variant} | {r['cpu_mean']:.2f} | "
                  f"{r['rss_mean']:.0f} | {r['rss_max']:.0f} | {r['run_mean_sd']:.3f} | {r['wall_cv']:.3f} |")
    md += ["", "## Per-CWE (blocked bad / bad · blocked good / good)", ""]
    for key, r in report.items():
        if key.split("|")[2] != "all":
            continue
        cells = " · ".join(f"{cwe}: {v[0]}/{v[1]} · {v[2]}/{v[3]}" for cwe, v in sorted(r["by_cwe"].items()))
        md.append(f"- **{key.replace('|', ' / ')}** — {cells}")
    md += ["", "## Error analysis (FN = missed bad case, FP = false block of good case)", ""]
    for key, r in report.items():
        if key.split("|")[2] == "all" or not r["errors"]:
            continue
        md.append(f"- **{key.replace('|', ' / ')}**: " + ", ".join(
            f"{e['case']} ({e['type']}{': ' + ';'.join(e['rules']) if e['rules'] else ''})" for e in r["errors"]))
    return "\n".join(md) + "\n"


def charts(report: dict, rows: list[dict], exp: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out = exp / "charts"
    out.mkdir(exist_ok=True)
    colors = {"baseline": "#9aa0a6", "adaptive": "#1a73e8"}
    for profile in sorted({k.split("|")[0] for k in report}):
        keys = [k for k in report if k.startswith(profile + "|0|all|")]
        if not keys:
            continue
        variants = [k.split("|")[3] for k in keys]
        fig, axes = plt.subplots(1, 3, figsize=(12, 3.6))
        for ax, metric, title in ((axes[0], "recall", "Detection coverage (↑)"),
                                  (axes[1], "fbr", "False Block Rate (↓)")):
            vals = [100 * report[k][metric] for k in keys]
            lo = [100 * (report[k][metric] - report[k][metric + "_ci"][0]) for k in keys]
            hi = [100 * (report[k][metric + "_ci"][1] - report[k][metric]) for k in keys]
            ax.bar(variants, vals, yerr=[lo, hi], capsize=4,
                   color=[colors.get(v, "#fbbc04") for v in variants])
            ax.set_title(title), ax.set_ylim(0, 105), ax.set_ylabel("%")
            ax.tick_params(axis="x", rotation=30)
        walls = [[r["wall_s"] for r in rows if r["profile"] == profile and r["scale"] == 0
                  and r["variant"] == v] for v in variants]
        axes[2].boxplot(walls, tick_labels=variants)
        axes[2].set_title("CI duration per commit (s, ↓)")
        axes[2].tick_params(axis="x", rotation=30)
        fig.suptitle(f"Profile: {profile} (main + holdout, 95% CI)")
        fig.tight_layout()
        fig.savefig(out / f"metrics_{profile}.png", dpi=160)
        plt.close(fig)
    scales = sorted({r["scale"] for r in rows})
    if len(scales) > 1:
        fig, ax = plt.subplots(figsize=(6, 3.6))
        for v in ("baseline", "adaptive"):
            ys = [st.fmean(r["wall_s"] for r in rows if r["scale"] == s and r["variant"] == v) for s in scales]
            ax.plot(scales, ys, marker="o", label=v, color=colors[v])
        ax.set_xlabel("extra legacy modules in repository"), ax.set_ylabel("gate wall time (s)")
        ax.set_title("Scalability: full scan vs differential"), ax.legend()
        fig.tight_layout()
        fig.savefig(out / "scalability.png", dpi=160)
        plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("exp", type=Path)
    ap.add_argument("--charts", action="store_true")
    args = ap.parse_args()
    rows = load(args.exp)
    report = analyze(rows)
    (args.exp / "summary.json").write_text(json.dumps(report, indent=2, default=list), encoding="utf-8")
    md = markdown(report, args.exp)
    (args.exp / "summary.md").write_text(md, encoding="utf-8")
    if args.charts:
        charts(report, rows, args.exp)
    sys.stdout.reconfigure(encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
