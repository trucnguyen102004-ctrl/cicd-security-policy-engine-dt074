# Experiment results — `exp4-cpp112`

- Host: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz · 12 vCPU · 7861 MB RAM (container)
- Started: 2026-10-03T15:00:41+00:00 · dataset manifest `e50c0bf0d8eb9d18`
- Trivy DB: 2026-09-30T13:11:13.714761705Z · Semgrep registry snapshot 2026-09-30T14:13:08Z

Decisions use the per-case majority over runs; 95% CIs are Wilson intervals; p-values are exact McNemar vs baseline; Δt is the paired-bootstrap mean difference (s).

| Profile | Split | Variant | Detection coverage (recall) | CWE-matched coverage | False Block Rate | Precision | F1 | MCC | CI duration μ±σ (s) | p95 (s) | Speed-up | Δt [95% CI] | McNemar p | Stable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| isolated | all | adaptive | 0.0% [0.0–24.2] (0/12) | 0.0% [0.0–24.2] (0/12) | 0.0% [0.0–24.2] (0/12) | nan | 0.00 | 0.00 | 4.87 ± 0.29 | 5.46 | 2.30× | -6.34 [-6.46, -6.22] | 1.0000 | 100% |
| isolated | all | baseline | 41.7% [19.3–68.0] (5/12) | 0.0% [0.0–24.2] (0/12) | 33.3% [13.8–60.9] (4/12) | 0.56 | 0.48 | 0.09 | 11.21 ± 0.63 | 12.20 | — | — | — | 100% |
| isolated | cpp112 | adaptive | 0.0% [0.0–24.2] (0/12) | 0.0% [0.0–24.2] (0/12) | 0.0% [0.0–24.2] (0/12) | nan | 0.00 | 0.00 | 4.87 ± 0.29 | 5.46 | 2.30× | -6.34 [-6.46, -6.22] | 1.0000 | 100% |
| isolated | cpp112 | baseline | 41.7% [19.3–68.0] (5/12) | 0.0% [0.0–24.2] (0/12) | 33.3% [13.8–60.9] (4/12) | 0.56 | 0.48 | 0.09 | 11.21 ± 0.63 | 12.20 | — | — | — | 100% |
| realistic | all | adaptive | 0.0% [0.0–24.2] (0/12) | 0.0% [0.0–24.2] (0/12) | 0.0% [0.0–24.2] (0/12) | nan | 0.00 | 0.00 | 4.91 ± 0.55 | 5.50 | 2.30× | -6.38 [-6.58, -6.19] | 1.0000 | 100% |
| realistic | all | baseline | 100.0% [75.8–100.0] (12/12) | 0.0% [0.0–24.2] (0/12) | 100.0% [75.8–100.0] (12/12) | 0.50 | 0.67 | 0.00 | 11.29 ± 0.83 | 13.04 | — | — | — | 100% |
| realistic | cpp112 | adaptive | 0.0% [0.0–24.2] (0/12) | 0.0% [0.0–24.2] (0/12) | 0.0% [0.0–24.2] (0/12) | nan | 0.00 | 0.00 | 4.91 ± 0.55 | 5.50 | 2.30× | -6.38 [-6.58, -6.19] | 1.0000 | 100% |
| realistic | cpp112 | baseline | 100.0% [75.8–100.0] (12/12) | 0.0% [0.0–24.2] (0/12) | 100.0% [75.8–100.0] (12/12) | 0.50 | 0.67 | 0.00 | 11.29 ± 0.83 | 13.04 | — | — | — | 100% |

## Resource cost

| Profile | Split | Variant | CPU s / commit | Peak RSS mean (MB) | Peak RSS max (MB) | Run-mean σ (s) | CV |
|---|---|---|---|---|---|---|---|
| isolated | all | adaptive | 4.30 | 177 | 182 | 0.183 | 0.060 |
| isolated | all | baseline | 10.86 | 248 | 259 | 0.443 | 0.056 |
| isolated | cpp112 | adaptive | 4.30 | 177 | 182 | 0.183 | 0.060 |
| isolated | cpp112 | baseline | 10.86 | 248 | 259 | 0.443 | 0.056 |
| realistic | all | adaptive | 4.35 | 177 | 182 | 0.179 | 0.112 |
| realistic | all | baseline | 11.14 | 271 | 284 | 0.417 | 0.074 |
| realistic | cpp112 | adaptive | 4.35 | 177 | 182 | 0.179 | 0.112 |
| realistic | cpp112 | baseline | 11.14 | 271 | 284 | 0.417 | 0.074 |

## Per-CWE (blocked bad / bad · blocked good / good)

- **isolated / 0 / all / adaptive** — CWE-22: 0/4 · 0/4 · CWE-78: 0/4 · 0/4 · CWE-798: 0/4 · 0/4
- **isolated / 0 / all / baseline** — CWE-22: 0/4 · 0/4 · CWE-78: 3/4 · 4/4 · CWE-798: 2/4 · 0/4
- **realistic / 0 / all / adaptive** — CWE-22: 0/4 · 0/4 · CWE-78: 0/4 · 0/4 · CWE-798: 0/4 · 0/4
- **realistic / 0 / all / baseline** — CWE-22: 4/4 · 4/4 · CWE-78: 4/4 · 4/4 · CWE-798: 4/4 · 4/4

## Error analysis (FN = missed bad case, FP = false block of good case)

- **isolated / 0 / cpp112 / adaptive**: C01-bad (FN), C02-bad (FN), C03-bad (FN), C04-bad (FN), C05-bad (FN), C06-bad (FN), C07-bad (FN), C08-bad (FN), C09-bad (FN), C10-bad (FN), C11-bad (FN), C12-bad (FN)
- **isolated / 0 / cpp112 / baseline**: C01-good (FP: insecure-use-strcat-fn), C02-bad (FN), C02-good (FP: insecure-use-strcat-fn), C03-good (FP: insecure-use-strcat-fn), C04-good (FP: insecure-use-strcat-fn), C05-bad (FN), C06-bad (FN), C07-bad (FN), C08-bad (FN), C10-bad (FN), C12-bad (FN)
- **realistic / 0 / cpp112 / adaptive**: C01-bad (FN), C02-bad (FN), C03-bad (FN), C04-bad (FN), C05-bad (FN), C06-bad (FN), C07-bad (FN), C08-bad (FN), C09-bad (FN), C10-bad (FN), C11-bad (FN), C12-bad (FN)
- **realistic / 0 / cpp112 / baseline**: C01-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;insecure-use-strcat-fn;raw-html-format), C02-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;insecure-use-strcat-fn;raw-html-format), C03-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;insecure-use-strcat-fn;raw-html-format), C04-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;insecure-use-strcat-fn;raw-html-format), C05-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), C06-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), C07-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), C08-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), C09-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), C10-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), C11-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format), C12-good (FP: CVE-2026-27205;CVE-2026-42198;CVE-2026-54291;directly-returned-format-string;raw-html-format)
