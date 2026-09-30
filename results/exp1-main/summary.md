# Experiment results — `exp1-main`

- Host: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz · 12 vCPU · 7861 MB RAM (container)
- Started: 2026-09-30T14:43:52+00:00 · dataset manifest `e50c0bf0d8eb9d18`
- Trivy DB: 2026-09-30T13:11:13.714761705Z · Semgrep registry snapshot 2026-09-30T14:13:08Z

Decisions use the per-case majority over runs; 95% CIs are Wilson intervals; p-values are exact McNemar vs baseline; Δt is the paired-bootstrap mean difference (s).

| Profile | Split | Variant | Detection coverage (recall) | CWE-matched coverage | False Block Rate | Precision | F1 | MCC | CI duration μ±σ (s) | p95 (s) | Speed-up | Δt [95% CI] | McNemar p | Stable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| isolated | all | adaptive | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 0.0% [0.0–12.1] (0/28) | 1.00 | 0.94 | 0.90 | 6.35 ± 1.19 | 8.24 | 1.79× | -5.03 [-5.27, -4.78] | 0.0039 | 100% |
| isolated | all | baseline | 71.4% [52.9–84.7] (20/28) | 64.3% [45.8–79.3] (18/28) | 14.3% [5.7–31.5] (4/28) | 0.83 | 0.77 | 0.58 | 11.38 ± 1.24 | 13.05 | — | — | — | 100% |
| isolated | holdout | adaptive | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 5.81 ± 0.39 | 6.59 | 1.96× | -5.57 [-5.77, -5.39] | 1.0000 | 100% |
| isolated | holdout | baseline | 63.6% [35.4–84.8] (7/11) | 63.6% [35.4–84.8] (7/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.78 | 0.68 | 11.38 ± 0.96 | 12.91 | — | — | — | 100% |
| isolated | main | adaptive | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 0.0% [0.0–18.4] (0/17) | 1.00 | 1.00 | 1.00 | 6.70 ± 1.39 | 9.64 | 1.70× | -4.68 [-5.05, -4.31] | 0.0078 | 100% |
| isolated | main | baseline | 76.5% [52.7–90.4] (13/17) | 64.7% [41.3–82.7] (11/17) | 23.5% [9.6–47.3] (4/17) | 0.76 | 0.76 | 0.53 | 11.38 ± 1.40 | 13.54 | — | — | — | 100% |
| realistic | all | adaptive | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 0.0% [0.0–12.1] (0/28) | 1.00 | 0.94 | 0.90 | 6.23 ± 1.10 | 8.10 | 1.78× | -4.86 [-5.05, -4.66] | 0.0000 | 100% |
| realistic | all | baseline | 100.0% [87.9–100.0] (28/28) | 67.9% [49.3–82.1] (19/28) | 100.0% [87.9–100.0] (28/28) | 0.50 | 0.67 | 0.00 | 11.09 ± 0.72 | 12.37 | — | — | — | 100% |
| realistic | holdout | adaptive | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 5.70 ± 0.18 | 5.98 | 1.95× | -5.41 [-5.58, -5.28] | 0.0574 | 100% |
| realistic | holdout | baseline | 100.0% [74.1–100.0] (11/11) | 72.7% [43.4–90.3] (8/11) | 100.0% [74.1–100.0] (11/11) | 0.50 | 0.67 | 0.00 | 11.12 ± 0.70 | 12.42 | — | — | — | 100% |
| realistic | main | adaptive | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 0.0% [0.0–18.4] (0/17) | 1.00 | 1.00 | 1.00 | 6.57 ± 1.30 | 9.69 | 1.69× | -4.50 [-4.79, -4.21] | 0.0000 | 100% |
| realistic | main | baseline | 100.0% [81.6–100.0] (17/17) | 64.7% [41.3–82.7] (11/17) | 100.0% [81.6–100.0] (17/17) | 0.50 | 0.67 | 0.00 | 11.08 ± 0.74 | 12.33 | — | — | — | 100% |

## Resource cost

| Profile | Split | Variant | CPU s / commit | Peak RSS mean (MB) | Peak RSS max (MB) | Run-mean σ (s) | CV |
|---|---|---|---|---|---|---|---|
| isolated | all | adaptive | 5.81 | 199 | 257 | 0.245 | 0.187 |
| isolated | all | baseline | 10.05 | 250 | 268 | 0.835 | 0.109 |
| isolated | holdout | adaptive | 5.28 | 188 | 190 | 0.247 | 0.067 |
| isolated | holdout | baseline | 10.10 | 249 | 258 | 0.759 | 0.084 |
| isolated | main | adaptive | 6.16 | 207 | 257 | 0.249 | 0.207 |
| isolated | main | baseline | 10.03 | 251 | 268 | 0.886 | 0.123 |
| realistic | all | adaptive | 5.70 | 199 | 257 | 0.159 | 0.176 |
| realistic | all | baseline | 10.15 | 267 | 284 | 0.453 | 0.065 |
| realistic | holdout | adaptive | 5.20 | 188 | 190 | 0.096 | 0.032 |
| realistic | holdout | baseline | 10.21 | 265 | 282 | 0.404 | 0.063 |
| realistic | main | adaptive | 6.03 | 206 | 257 | 0.200 | 0.197 |
| realistic | main | baseline | 10.12 | 268 | 284 | 0.488 | 0.067 |

## Per-CWE (blocked bad / bad · blocked good / good)

- **isolated / 0 / all / adaptive** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8
- **isolated / 0 / all / baseline** — CWE-1395: 2/2 · 1/2 · CWE-22: 5/7 · 1/7 · CWE-79: 5/6 · 1/6 · CWE-798: 2/5 · 1/5 · CWE-89: 6/8 · 0/8
- **realistic / 0 / all / adaptive** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8
- **realistic / 0 / all / baseline** — CWE-1395: 2/2 · 2/2 · CWE-22: 7/7 · 7/7 · CWE-79: 6/6 · 6/6 · CWE-798: 5/5 · 5/5 · CWE-89: 8/8 · 8/8

## Error analysis (FN = missed bad case, FP = false block of good case)

- **isolated / 0 / holdout / adaptive**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **isolated / 0 / holdout / baseline**: H02-bad (FN), H06-bad (FN), H09-bad (FN), H11-bad (FN)
- **isolated / 0 / main / baseline**: J03-bad (FN), J07-bad (FN), J09-bad (FN), J10-bad (FN), J11-good (FP: use-of-default-aes), P02-good (FP: raw-html-format), P03-good (FP: path-traversal-open), S04-good (FP: CVE-2026-34477;CVE-2026-34478;CVE-2026-34480)
- **realistic / 0 / holdout / adaptive**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **realistic / 0 / holdout / baseline**: H01-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), H02-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), H03-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), H04-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), H05-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), H06-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), H07-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), H08-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), H09-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), H10-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), H11-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format)
- **realistic / 0 / main / baseline**: J01-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), J02-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), J03-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), J04-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), J05-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), J06-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), J07-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), J08-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), J09-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), J10-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), J11-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format;use-of-default-aes), P01-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), P02-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), P03-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;path-traversal-open;raw-html-format), P04-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), S03-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), S04-good (FP: CVE-2026-27205;CVE-2026-34477;CVE-2026-34478;CVE-2026-34480;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format)
