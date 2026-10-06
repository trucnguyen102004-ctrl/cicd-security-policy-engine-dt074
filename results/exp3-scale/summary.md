# Experiment results — `exp3-scale`

- Host: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz · 12 vCPU · 7861 MB RAM (container)
- Started: 2026-10-03T17:10:58+00:00 · dataset manifest `e50c0bf0d8eb9d18`
- Trivy DB: 2026-09-30T13:11:13.714761705Z · Semgrep registry snapshot 2026-09-30T14:13:08Z

Decisions use the per-case majority over runs; 95% CIs are Wilson intervals; p-values are exact McNemar vs baseline; Δt is the paired-bootstrap mean difference (s).

| Profile | Split | Variant | Detection coverage (recall) | CWE-matched coverage | False Block Rate | Precision | F1 | MCC | CI duration μ±σ (s) | p95 (s) | Speed-up | Δt [95% CI] | McNemar p | Stable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| realistic | all | adaptive | 100.0% [43.9–100.0] (3/3) | 100.0% [43.9–100.0] (3/3) | 0.0% [0.0–56.1] (0/3) | 1.00 | 1.00 | 1.00 | 7.96 ± 1.60 | 9.84 | 1.38× | -3.03 [-3.72, -2.35] | 0.2500 | 100% |
| realistic | all | baseline | 100.0% [43.9–100.0] (3/3) | 66.7% [20.8–93.9] (2/3) | 100.0% [43.9–100.0] (3/3) | 0.50 | 0.67 | 0.00 | 10.99 ± 0.83 | 12.42 | — | — | — | 100% |
| realistic | main | adaptive | 100.0% [43.9–100.0] (3/3) | 100.0% [43.9–100.0] (3/3) | 0.0% [0.0–56.1] (0/3) | 1.00 | 1.00 | 1.00 | 7.96 ± 1.60 | 9.84 | 1.38× | -3.03 [-3.72, -2.35] | 0.2500 | 100% |
| realistic | main | baseline | 100.0% [43.9–100.0] (3/3) | 66.7% [20.8–93.9] (2/3) | 100.0% [43.9–100.0] (3/3) | 0.50 | 0.67 | 0.00 | 10.99 ± 0.83 | 12.42 | — | — | — | 100% |
| realistic (+10 modules) | all | adaptive | 100.0% [43.9–100.0] (3/3) | 100.0% [43.9–100.0] (3/3) | 0.0% [0.0–56.1] (0/3) | 1.00 | 1.00 | 1.00 | 8.14 ± 1.84 | 10.29 | 1.39× | -3.16 [-3.96, -2.30] | 0.2500 | 100% |
| realistic (+10 modules) | all | baseline | 100.0% [43.9–100.0] (3/3) | 66.7% [20.8–93.9] (2/3) | 100.0% [43.9–100.0] (3/3) | 0.50 | 0.67 | 0.00 | 11.30 ± 0.69 | 12.63 | — | — | — | 100% |
| realistic (+10 modules) | main | adaptive | 100.0% [43.9–100.0] (3/3) | 100.0% [43.9–100.0] (3/3) | 0.0% [0.0–56.1] (0/3) | 1.00 | 1.00 | 1.00 | 8.14 ± 1.84 | 10.29 | 1.39× | -3.16 [-3.96, -2.30] | 0.2500 | 100% |
| realistic (+10 modules) | main | baseline | 100.0% [43.9–100.0] (3/3) | 66.7% [20.8–93.9] (2/3) | 100.0% [43.9–100.0] (3/3) | 0.50 | 0.67 | 0.00 | 11.30 ± 0.69 | 12.63 | — | — | — | 100% |
| realistic (+40 modules) | all | adaptive | 100.0% [43.9–100.0] (3/3) | 100.0% [43.9–100.0] (3/3) | 0.0% [0.0–56.1] (0/3) | 1.00 | 1.00 | 1.00 | 7.95 ± 1.75 | 10.04 | 1.50× | -3.96 [-4.77, -3.13] | 0.2500 | 100% |
| realistic (+40 modules) | all | baseline | 100.0% [43.9–100.0] (3/3) | 66.7% [20.8–93.9] (2/3) | 100.0% [43.9–100.0] (3/3) | 0.50 | 0.67 | 0.00 | 11.91 ± 0.72 | 12.60 | — | — | — | 100% |
| realistic (+40 modules) | main | adaptive | 100.0% [43.9–100.0] (3/3) | 100.0% [43.9–100.0] (3/3) | 0.0% [0.0–56.1] (0/3) | 1.00 | 1.00 | 1.00 | 7.95 ± 1.75 | 10.04 | 1.50× | -3.96 [-4.77, -3.13] | 0.2500 | 100% |
| realistic (+40 modules) | main | baseline | 100.0% [43.9–100.0] (3/3) | 66.7% [20.8–93.9] (2/3) | 100.0% [43.9–100.0] (3/3) | 0.50 | 0.67 | 0.00 | 11.91 ± 0.72 | 12.60 | — | — | — | 100% |

## Resource cost

| Profile | Split | Variant | CPU s / commit | Peak RSS mean (MB) | Peak RSS max (MB) | Run-mean σ (s) | CV |
|---|---|---|---|---|---|---|---|
| realistic | all | adaptive | 7.65 | 231 | 257 | 0.415 | 0.201 |
| realistic | all | baseline | 11.04 | 259 | 281 | 0.710 | 0.076 |
| realistic | main | adaptive | 7.65 | 231 | 257 | 0.415 | 0.201 |
| realistic | main | baseline | 11.04 | 259 | 281 | 0.710 | 0.076 |
| realistic+10 | all | adaptive | 7.85 | 229 | 257 | 0.451 | 0.226 |
| realistic+10 | all | baseline | 12.56 | 271 | 293 | 0.527 | 0.061 |
| realistic+10 | main | adaptive | 7.85 | 229 | 257 | 0.451 | 0.226 |
| realistic+10 | main | baseline | 12.56 | 271 | 293 | 0.527 | 0.061 |
| realistic+40 | all | adaptive | 7.57 | 232 | 257 | 0.317 | 0.220 |
| realistic+40 | all | baseline | 16.11 | 277 | 298 | 0.554 | 0.060 |
| realistic+40 | main | adaptive | 7.57 | 232 | 257 | 0.317 | 0.220 |
| realistic+40 | main | baseline | 16.11 | 277 | 298 | 0.554 | 0.060 |

## Per-CWE (blocked bad / bad · blocked good / good)

- **realistic / 0 / all / adaptive** — CWE-1395: 1/1 · 0/1 · CWE-89: 2/2 · 0/2
- **realistic / 0 / all / baseline** — CWE-1395: 1/1 · 1/1 · CWE-89: 2/2 · 2/2
- **realistic / 10 / all / adaptive** — CWE-1395: 1/1 · 0/1 · CWE-89: 2/2 · 0/2
- **realistic / 10 / all / baseline** — CWE-1395: 1/1 · 1/1 · CWE-89: 2/2 · 2/2
- **realistic / 40 / all / adaptive** — CWE-1395: 1/1 · 0/1 · CWE-89: 2/2 · 0/2
- **realistic / 40 / all / baseline** — CWE-1395: 1/1 · 1/1 · CWE-89: 2/2 · 2/2

## Error analysis (FN = missed bad case, FP = false block of good case)

- **realistic / 0 / main / baseline**: J01-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), P01-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), S03-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format)
- **realistic / 10 / main / baseline**: J01-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), P01-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), S03-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format)
- **realistic / 40 / main / baseline**: J01-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), P01-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), S03-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format)
