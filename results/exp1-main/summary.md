# Experiment results — `exp1-main`

- Host: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz · 12 vCPU · 7861 MB RAM (container)
- Started: 2026-09-30T14:43:52+00:00 · dataset manifest `e50c0bf0d8eb9d18`
- Trivy DB: 2026-09-30T13:11:13.714761705Z · Semgrep registry snapshot 2026-09-30T14:13:08Z

Decisions use the per-case majority over runs; 95% CIs are Wilson intervals; p-values are exact McNemar vs baseline; Δt is the paired-bootstrap mean difference (s).

| Profile | Split | Variant | Detection coverage (recall) | CWE-matched coverage | False Block Rate | Precision | F1 | MCC | CI duration μ±σ (s) | p95 (s) | Speed-up | Δt [95% CI] | McNemar p | Stable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| isolated | all | adaptive | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 0.0% [0.0–12.1] (0/28) | 1.00 | 0.94 | 0.90 | 6.60 ± 1.29 | 8.84 | 1.87× | -5.72 [-6.26, -5.20] | 0.0039 | 100% |
| isolated | all | baseline | 71.4% [52.9–84.7] (20/28) | 64.3% [45.8–79.3] (18/28) | 14.3% [5.7–31.5] (4/28) | 0.83 | 0.77 | 0.58 | 12.32 ± 1.70 | 14.45 | — | — | — | 100% |
| isolated | holdout | adaptive | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 6.08 ± 0.53 | 6.75 | 2.01× | -6.14 [-6.55, -5.79] | 1.0000 | 100% |
| isolated | holdout | baseline | 63.6% [35.4–84.8] (7/11) | 63.6% [35.4–84.8] (7/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.78 | 0.68 | 12.22 ± 1.06 | 13.53 | — | — | — | 100% |
| isolated | main | adaptive | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 0.0% [0.0–18.4] (0/17) | 1.00 | 1.00 | 1.00 | 6.93 ± 1.51 | 9.10 | 1.79× | -5.45 [-6.35, -4.64] | 0.0078 | 100% |
| isolated | main | baseline | 76.5% [52.7–90.4] (13/17) | 64.7% [41.3–82.7] (11/17) | 23.5% [9.6–47.3] (4/17) | 0.76 | 0.76 | 0.53 | 12.38 ± 2.02 | 14.45 | — | — | — | 100% |
| realistic | all | adaptive | 66.7% [20.8–93.9] (2/3) | 66.7% [20.8–93.9] (2/3) | nan% [nan–nan] (0/0) | 1.00 | 0.80 | 0.00 | 6.02 ± 0.23 | 6.27 | 1.90× | -5.30 [-5.33, -5.27] | 1.0000 | 100% |
| realistic | all | baseline | 100.0% [34.2–100.0] (2/2) | 50.0% [9.5–90.5] (1/2) | nan% [nan–nan] (0/0) | 1.00 | 1.00 | 0.00 | 11.41 ± 0.28 | 11.60 | — | — | — | 100% |
| realistic | holdout | adaptive | 0.0% [0.0–79.3] (0/1) | 0.0% [0.0–79.3] (0/1) | nan% [nan–nan] (0/0) | nan | 0.00 | 0.00 | 5.84 ± 0.00 | 5.84 | — | — | — | 100% |
| realistic | main | adaptive | 100.0% [34.2–100.0] (2/2) | 100.0% [34.2–100.0] (2/2) | nan% [nan–nan] (0/0) | 1.00 | 1.00 | 0.00 | 6.11 ± 0.23 | 6.27 | 1.87× | -5.30 [-5.33, -5.27] | 1.0000 | 100% |
| realistic | main | baseline | 100.0% [34.2–100.0] (2/2) | 50.0% [9.5–90.5] (1/2) | nan% [nan–nan] (0/0) | 1.00 | 1.00 | 0.00 | 11.41 ± 0.28 | 11.60 | — | — | — | 100% |

## Resource cost

| Profile | Split | Variant | CPU s / commit | Peak RSS mean (MB) | Peak RSS max (MB) | Run-mean σ (s) | CV |
|---|---|---|---|---|---|---|---|
| isolated | all | adaptive | 6.02 | 199 | 255 | 0.000 | 0.195 |
| isolated | all | baseline | 10.36 | 249 | 265 | 0.000 | 0.138 |
| isolated | holdout | adaptive | 5.52 | 188 | 190 | 0.000 | 0.086 |
| isolated | holdout | baseline | 10.43 | 249 | 257 | 0.000 | 0.087 |
| isolated | main | adaptive | 6.34 | 206 | 255 | 0.000 | 0.218 |
| isolated | main | baseline | 10.32 | 250 | 265 | 0.000 | 0.163 |
| realistic | all | adaptive | 5.49 | 188 | 189 | 0.000 | 0.038 |
| realistic | all | baseline | 10.46 | 269 | 283 | 0.000 | 0.024 |
| realistic | holdout | adaptive | 5.26 | 188 | 188 | 0.000 | 0.000 |
| realistic | main | adaptive | 5.61 | 188 | 189 | 0.000 | 0.037 |
| realistic | main | baseline | 10.46 | 269 | 283 | 0.000 | 0.024 |

## Per-CWE (blocked bad / bad · blocked good / good)

- **isolated / 0 / all / adaptive** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8
- **isolated / 0 / all / baseline** — CWE-1395: 2/2 · 1/2 · CWE-22: 5/7 · 1/7 · CWE-79: 5/6 · 1/6 · CWE-798: 2/5 · 1/5 · CWE-89: 6/8 · 0/8
- **realistic / 0 / all / adaptive** — CWE-22: 1/2 · 0/0 · CWE-798: 1/1 · 0/0
- **realistic / 0 / all / baseline** — CWE-22: 1/1 · 0/0 · CWE-798: 1/1 · 0/0

## Error analysis (FN = missed bad case, FP = false block of good case)

- **isolated / 0 / holdout / adaptive**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **isolated / 0 / holdout / baseline**: H02-bad (FN), H06-bad (FN), H09-bad (FN), H11-bad (FN)
- **isolated / 0 / main / baseline**: J03-bad (FN), J07-bad (FN), J09-bad (FN), J10-bad (FN), J11-good (FP: use-of-default-aes), P02-good (FP: raw-html-format), P03-good (FP: path-traversal-open), S04-good (FP: CVE-2026-34477;CVE-2026-34478;CVE-2026-34480)
- **realistic / 0 / holdout / adaptive**: H09-bad (FN)
