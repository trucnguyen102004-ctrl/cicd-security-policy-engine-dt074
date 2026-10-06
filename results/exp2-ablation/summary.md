# Experiment results — `exp2-ablation`

- Host: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz · 12 vCPU · 7861 MB RAM (container)
- Started: 2026-10-03T15:39:47+00:00 · dataset manifest `e50c0bf0d8eb9d18`
- Trivy DB: 2026-09-30T13:11:13.714761705Z · Semgrep registry snapshot 2026-09-30T14:13:08Z

Decisions use the per-case majority over runs; 95% CIs are Wilson intervals; p-values are exact McNemar vs baseline; Δt is the paired-bootstrap mean difference (s).

| Profile | Split | Variant | Detection coverage (recall) | CWE-matched coverage | False Block Rate | Precision | F1 | MCC | CI duration μ±σ (s) | p95 (s) | Speed-up | Δt [95% CI] | McNemar p | Stable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| isolated | all | adaptive-no_custom_rules | 60.7% [42.4–76.4] (17/28) | 60.7% [42.4–76.4] (17/28) | 0.0% [0.0–12.1] (0/28) | 1.00 | 0.76 | 0.66 | 6.34 ± 1.14 | 8.23 | — | — | — | 100% |
| isolated | all | adaptive-no_differential | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 0.0% [0.0–12.1] (0/28) | 1.00 | 0.94 | 0.90 | 11.46 ± 0.65 | 12.53 | — | — | — | 100% |
| isolated | all | adaptive-no_language_aware | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 0.0% [0.0–12.1] (0/28) | 1.00 | 0.94 | 0.90 | 9.94 ± 0.76 | 11.32 | — | — | — | 100% |
| isolated | all | adaptive-no_risk_threshold | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 3.6% [0.6–17.7] (1/28) | 0.96 | 0.93 | 0.86 | 6.67 ± 1.09 | 8.29 | — | — | — | 100% |
| isolated | all | adaptive-no_sanitizer_triage | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 3.6% [0.6–17.7] (1/28) | 0.96 | 0.93 | 0.86 | 6.68 ± 1.10 | 8.24 | — | — | — | 100% |
| isolated | all | adaptive-no_sca_triage | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 3.6% [0.6–17.7] (1/28) | 0.96 | 0.93 | 0.86 | 6.71 ± 1.05 | 8.51 | — | — | — | 100% |
| isolated | holdout | adaptive-no_custom_rules | 63.6% [35.4–84.8] (7/11) | 63.6% [35.4–84.8] (7/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.78 | 0.68 | 5.90 ± 0.49 | 6.59 | — | — | — | 100% |
| isolated | holdout | adaptive-no_differential | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 11.59 ± 0.55 | 12.53 | — | — | — | 100% |
| isolated | holdout | adaptive-no_language_aware | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 10.08 ± 0.89 | 11.48 | — | — | — | 100% |
| isolated | holdout | adaptive-no_risk_threshold | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 6.26 ± 0.39 | 7.01 | — | — | — | 100% |
| isolated | holdout | adaptive-no_sanitizer_triage | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 6.18 ± 0.36 | 6.86 | — | — | — | 100% |
| isolated | holdout | adaptive-no_sca_triage | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 6.30 ± 0.40 | 6.94 | — | — | — | 100% |
| isolated | main | adaptive-no_custom_rules | 58.8% [36.0–78.4] (10/17) | 58.8% [36.0–78.4] (10/17) | 0.0% [0.0–18.4] (0/17) | 1.00 | 0.74 | 0.65 | 6.62 ± 1.34 | 8.30 | — | — | — | 100% |
| isolated | main | adaptive-no_differential | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 0.0% [0.0–18.4] (0/17) | 1.00 | 1.00 | 1.00 | 11.38 ± 0.70 | 12.40 | — | — | — | 100% |
| isolated | main | adaptive-no_language_aware | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 0.0% [0.0–18.4] (0/17) | 1.00 | 1.00 | 1.00 | 9.84 ± 0.66 | 10.96 | — | — | — | 100% |
| isolated | main | adaptive-no_risk_threshold | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 5.9% [1.0–27.0] (1/17) | 0.94 | 0.97 | 0.94 | 6.93 ± 1.31 | 9.07 | — | — | — | 100% |
| isolated | main | adaptive-no_sanitizer_triage | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 5.9% [1.0–27.0] (1/17) | 0.94 | 0.97 | 0.94 | 6.99 ± 1.30 | 8.85 | — | — | — | 100% |
| isolated | main | adaptive-no_sca_triage | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 5.9% [1.0–27.0] (1/17) | 0.94 | 0.97 | 0.94 | 6.98 ± 1.24 | 9.31 | — | — | — | 100% |
| realistic | all | adaptive-no_custom_rules | 60.7% [42.4–76.4] (17/28) | 60.7% [42.4–76.4] (17/28) | 0.0% [0.0–12.1] (0/28) | 1.00 | 0.76 | 0.66 | 6.52 ± 1.05 | 8.73 | — | — | — | 100% |
| realistic | all | adaptive-no_differential | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 0.0% [0.0–12.1] (0/28) | 1.00 | 0.94 | 0.90 | 12.03 ± 0.71 | 13.01 | — | — | — | 100% |
| realistic | all | adaptive-no_language_aware | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 0.0% [0.0–12.1] (0/28) | 1.00 | 0.94 | 0.90 | 10.30 ± 0.80 | 11.70 | — | — | — | 100% |
| realistic | all | adaptive-no_risk_threshold | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 3.6% [0.6–17.7] (1/28) | 0.96 | 0.93 | 0.86 | 6.89 ± 1.12 | 9.15 | — | — | — | 100% |
| realistic | all | adaptive-no_sanitizer_triage | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 3.6% [0.6–17.7] (1/28) | 0.96 | 0.93 | 0.86 | 6.87 ± 1.32 | 8.77 | — | — | — | 100% |
| realistic | all | adaptive-no_sca_triage | 89.3% [72.8–96.3] (25/28) | 89.3% [72.8–96.3] (25/28) | 3.6% [0.6–17.7] (1/28) | 0.96 | 0.93 | 0.86 | 6.76 ± 1.05 | 8.69 | — | — | — | 100% |
| realistic | holdout | adaptive-no_custom_rules | 63.6% [35.4–84.8] (7/11) | 63.6% [35.4–84.8] (7/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.78 | 0.68 | 6.02 ± 0.55 | 6.86 | — | — | — | 100% |
| realistic | holdout | adaptive-no_differential | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 12.12 ± 0.88 | 13.17 | — | — | — | 100% |
| realistic | holdout | adaptive-no_language_aware | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 9.98 ± 0.66 | 11.13 | — | — | — | 100% |
| realistic | holdout | adaptive-no_risk_threshold | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 6.40 ± 0.76 | 8.23 | — | — | — | 100% |
| realistic | holdout | adaptive-no_sanitizer_triage | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 6.32 ± 0.54 | 7.23 | — | — | — | 100% |
| realistic | holdout | adaptive-no_sca_triage | 72.7% [43.4–90.3] (8/11) | 72.7% [43.4–90.3] (8/11) | 0.0% [0.0–25.9] (0/11) | 1.00 | 0.84 | 0.76 | 6.36 ± 0.61 | 7.63 | — | — | — | 100% |
| realistic | main | adaptive-no_custom_rules | 58.8% [36.0–78.4] (10/17) | 58.8% [36.0–78.4] (10/17) | 0.0% [0.0–18.4] (0/17) | 1.00 | 0.74 | 0.65 | 6.84 ± 1.17 | 9.02 | — | — | — | 100% |
| realistic | main | adaptive-no_differential | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 0.0% [0.0–18.4] (0/17) | 1.00 | 1.00 | 1.00 | 11.96 ± 0.59 | 12.93 | — | — | — | 100% |
| realistic | main | adaptive-no_language_aware | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 0.0% [0.0–18.4] (0/17) | 1.00 | 1.00 | 1.00 | 10.50 ± 0.82 | 11.70 | — | — | — | 100% |
| realistic | main | adaptive-no_risk_threshold | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 5.9% [1.0–27.0] (1/17) | 0.94 | 0.97 | 0.94 | 7.20 ± 1.21 | 9.17 | — | — | — | 100% |
| realistic | main | adaptive-no_sanitizer_triage | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 5.9% [1.0–27.0] (1/17) | 0.94 | 0.97 | 0.94 | 7.22 ± 1.54 | 9.61 | — | — | — | 100% |
| realistic | main | adaptive-no_sca_triage | 100.0% [81.6–100.0] (17/17) | 100.0% [81.6–100.0] (17/17) | 5.9% [1.0–27.0] (1/17) | 0.94 | 0.97 | 0.94 | 7.01 ± 1.19 | 9.11 | — | — | — | 100% |

## Resource cost

| Profile | Split | Variant | CPU s / commit | Peak RSS mean (MB) | Peak RSS max (MB) | Run-mean σ (s) | CV |
|---|---|---|---|---|---|---|---|
| isolated | all | adaptive-no_custom_rules | 5.86 | 199 | 255 | 0.000 | 0.180 |
| isolated | all | adaptive-no_differential | 11.14 | 251 | 268 | 0.000 | 0.057 |
| isolated | all | adaptive-no_language_aware | 9.70 | 245 | 264 | 0.000 | 0.077 |
| isolated | all | adaptive-no_risk_threshold | 6.19 | 199 | 256 | 0.000 | 0.164 |
| isolated | all | adaptive-no_sanitizer_triage | 6.18 | 199 | 256 | 0.000 | 0.165 |
| isolated | all | adaptive-no_sca_triage | 6.22 | 199 | 257 | 0.000 | 0.156 |
| isolated | holdout | adaptive-no_custom_rules | 5.35 | 187 | 189 | 0.000 | 0.083 |
| isolated | holdout | adaptive-no_differential | 11.27 | 253 | 259 | 0.000 | 0.047 |
| isolated | holdout | adaptive-no_language_aware | 9.86 | 244 | 254 | 0.000 | 0.088 |
| isolated | holdout | adaptive-no_risk_threshold | 5.71 | 188 | 190 | 0.000 | 0.063 |
| isolated | holdout | adaptive-no_sanitizer_triage | 5.63 | 188 | 190 | 0.000 | 0.058 |
| isolated | holdout | adaptive-no_sca_triage | 5.74 | 188 | 191 | 0.000 | 0.063 |
| isolated | main | adaptive-no_custom_rules | 6.18 | 207 | 255 | 0.000 | 0.203 |
| isolated | main | adaptive-no_differential | 11.06 | 250 | 268 | 0.000 | 0.062 |
| isolated | main | adaptive-no_language_aware | 9.60 | 246 | 264 | 0.000 | 0.067 |
| isolated | main | adaptive-no_risk_threshold | 6.49 | 205 | 256 | 0.000 | 0.189 |
| isolated | main | adaptive-no_sanitizer_triage | 6.54 | 206 | 256 | 0.000 | 0.185 |
| isolated | main | adaptive-no_sca_triage | 6.53 | 206 | 257 | 0.000 | 0.178 |
| realistic | all | adaptive-no_custom_rules | 6.03 | 198 | 256 | 0.000 | 0.161 |
| realistic | all | adaptive-no_differential | 11.95 | 266 | 282 | 0.000 | 0.059 |
| realistic | all | adaptive-no_language_aware | 10.07 | 247 | 262 | 0.000 | 0.077 |
| realistic | all | adaptive-no_risk_threshold | 6.38 | 199 | 256 | 0.000 | 0.163 |
| realistic | all | adaptive-no_sanitizer_triage | 6.35 | 199 | 258 | 0.000 | 0.192 |
| realistic | all | adaptive-no_sca_triage | 6.25 | 199 | 257 | 0.000 | 0.155 |
| realistic | holdout | adaptive-no_custom_rules | 5.45 | 187 | 188 | 0.000 | 0.091 |
| realistic | holdout | adaptive-no_differential | 12.09 | 267 | 282 | 0.000 | 0.073 |
| realistic | holdout | adaptive-no_language_aware | 9.74 | 250 | 252 | 0.000 | 0.066 |
| realistic | holdout | adaptive-no_risk_threshold | 5.82 | 188 | 190 | 0.000 | 0.119 |
| realistic | holdout | adaptive-no_sanitizer_triage | 5.77 | 188 | 190 | 0.000 | 0.086 |
| realistic | holdout | adaptive-no_sca_triage | 5.82 | 188 | 190 | 0.000 | 0.096 |
| realistic | main | adaptive-no_custom_rules | 6.40 | 205 | 256 | 0.000 | 0.171 |
| realistic | main | adaptive-no_differential | 11.86 | 265 | 282 | 0.000 | 0.049 |
| realistic | main | adaptive-no_language_aware | 10.28 | 246 | 262 | 0.000 | 0.078 |
| realistic | main | adaptive-no_risk_threshold | 6.75 | 206 | 256 | 0.000 | 0.168 |
| realistic | main | adaptive-no_sanitizer_triage | 6.73 | 207 | 258 | 0.000 | 0.213 |
| realistic | main | adaptive-no_sca_triage | 6.54 | 206 | 257 | 0.000 | 0.170 |

## Per-CWE (blocked bad / bad · blocked good / good)

- **isolated / 0 / all / adaptive-no_custom_rules** — CWE-1395: 2/2 · 0/2 · CWE-22: 4/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 1/5 · 0/5 · CWE-89: 5/8 · 0/8
- **isolated / 0 / all / adaptive-no_differential** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8
- **isolated / 0 / all / adaptive-no_language_aware** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8
- **isolated / 0 / all / adaptive-no_risk_threshold** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 1/5 · CWE-89: 7/8 · 0/8
- **isolated / 0 / all / adaptive-no_sanitizer_triage** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 1/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8
- **isolated / 0 / all / adaptive-no_sca_triage** — CWE-1395: 2/2 · 1/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8
- **realistic / 0 / all / adaptive-no_custom_rules** — CWE-1395: 2/2 · 0/2 · CWE-22: 4/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 1/5 · 0/5 · CWE-89: 5/8 · 0/8
- **realistic / 0 / all / adaptive-no_differential** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8
- **realistic / 0 / all / adaptive-no_language_aware** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8
- **realistic / 0 / all / adaptive-no_risk_threshold** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 1/5 · CWE-89: 7/8 · 0/8
- **realistic / 0 / all / adaptive-no_sanitizer_triage** — CWE-1395: 2/2 · 0/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 1/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8
- **realistic / 0 / all / adaptive-no_sca_triage** — CWE-1395: 2/2 · 1/2 · CWE-22: 6/7 · 0/7 · CWE-79: 5/6 · 0/6 · CWE-798: 5/5 · 0/5 · CWE-89: 7/8 · 0/8

## Error analysis (FN = missed bad case, FP = false block of good case)

- **isolated / 0 / holdout / adaptive-no_custom_rules**: H02-bad (FN), H06-bad (FN), H09-bad (FN), H11-bad (FN)
- **isolated / 0 / holdout / adaptive-no_differential**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **isolated / 0 / holdout / adaptive-no_language_aware**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **isolated / 0 / holdout / adaptive-no_risk_threshold**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **isolated / 0 / holdout / adaptive-no_sanitizer_triage**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **isolated / 0 / holdout / adaptive-no_sca_triage**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **isolated / 0 / main / adaptive-no_custom_rules**: J03-bad (FN), J07-bad (FN), J09-bad (FN), J10-bad (FN), J11-bad (FN), P01-bad (FN), P03-bad (FN)
- **isolated / 0 / main / adaptive-no_risk_threshold**: J11-good (FP: use-of-default-aes)
- **isolated / 0 / main / adaptive-no_sanitizer_triage**: P02-good (FP: raw-html-format)
- **isolated / 0 / main / adaptive-no_sca_triage**: S04-good (FP: CVE-2026-34477;CVE-2026-34478;CVE-2026-34480)
- **realistic / 0 / holdout / adaptive-no_custom_rules**: H02-bad (FN), H06-bad (FN), H09-bad (FN), H11-bad (FN)
- **realistic / 0 / holdout / adaptive-no_differential**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **realistic / 0 / holdout / adaptive-no_language_aware**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **realistic / 0 / holdout / adaptive-no_risk_threshold**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **realistic / 0 / holdout / adaptive-no_sanitizer_triage**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **realistic / 0 / holdout / adaptive-no_sca_triage**: H02-bad (FN), H06-bad (FN), H09-bad (FN)
- **realistic / 0 / main / adaptive-no_custom_rules**: J03-bad (FN), J07-bad (FN), J09-bad (FN), J10-bad (FN), J11-bad (FN), P01-bad (FN), P03-bad (FN)
- **realistic / 0 / main / adaptive-no_risk_threshold**: J11-good (FP: use-of-default-aes)
- **realistic / 0 / main / adaptive-no_sanitizer_triage**: P02-good (FP: raw-html-format)
- **realistic / 0 / main / adaptive-no_sca_triage**: S04-good (FP: CVE-2026-34477;CVE-2026-34478;CVE-2026-34480)
