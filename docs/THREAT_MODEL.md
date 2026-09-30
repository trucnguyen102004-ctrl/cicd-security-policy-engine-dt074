# Threat model, data risks and success criteria (fixed before the experiments)

## 1. System and trust boundaries

```
 Developer ──push/PR──▶ GitHub repo ──event──▶ Actions runner (ephemeral VM)
                                                 │
                                   docker run ▶ security-gate image (pinned tools,
                                                 │  frozen rules + CVE DB, no network needed)
                                                 ▼
                          decision.json / feedback.md / SARIF ──▶ PR comment, check status,
                                                                 code scanning, chat webhook
```

| Boundary | Crosses | Main threats | Mitigation in DT074 |
|---|---|---|---|
| TB1 PR author → CI | untrusted code, untrusted PR text/labels | vulnerable code merged; gate bypass through excluded paths; forged override | Gate is a required check; `scope.exclude` lives in the repo policy (protect with CODEOWNERS); override needs a label (write access) **and** a written reason, and is logged in `audit.jsonl` |
| TB2 CI → scanner supply chain | third-party binaries, rules, CVE feed | tampered or changed tools; `latest` drift changes results | Exact versions + vendor SHA-256 in `Dockerfile`; rules/DB frozen at build; hashes logged per experiment |
| TB3 Gate → reporting | findings that contain code and secrets | a secret leaks into PR comments, logs or webhooks | Secret values are masked in feedback/snippets; webhooks send rule id + path only |
| TB4 Gate failure | scanner crash / timeout | fail-open lets vulnerable code through | **Fail-closed**: any scanner error → BLOCK (tested) |

STRIDE summary: Spoofing (override actor from `github.actor`); Tampering (pinned
image, manifest hashes); Repudiation (audit log for overrides); Information
disclosure (secret masking); Denial of service (timeouts, cancel-in-progress
concurrency); Elevation of privilege (minimal `permissions:` in the workflow).

## 2. Data risks (EDA → see docs/DATASET.md)

| Risk | Status | Handling |
|---|---|---|
| Train/test leakage | Rules were written while looking at *main* output | Separate **holdout** split fixed in code before rule writing; rule changes logged in `rules/RULE_CHANGELOG.md`; pairs never split; near-duplicate check across splits = 0 |
| Duplicates | 4 near-duplicate pairs inside a split (Juliet G2B bodies are identical across sources) | Reported; effective sample size is smaller than the nominal one → wide Wilson CIs are shown |
| Class imbalance | bad:good = 1:1 in every split by construction | Metrics use recall, FBR, MCC and balanced accuracy, not accuracy alone |
| Label noise | Juliet labels are function-level; our split is file-level. C headers keep macros such as `#define PASSWORD` in the good half | Discussed in error analysis; a CWE-matched metric counts only blocks caused by the labelled weakness |
| Representativeness | Juliet is synthetic and short (median 22–169 LOC) | Stated as a limitation; the realistic profile adds a host application |
| Privacy | No personal data; fabricated secrets only | Secret strings are provider-neutral (no push-protection patterns) |

## 3. Success criteria (defined a priori)

| Id | Criterion | Threshold |
|---|---|---|
| S1 | Detection coverage of adaptive ≥ baseline on each split | recall(adaptive) ≥ recall(baseline) |
| S2 | False Block Rate of adaptive on `good()` | ≤ 10 % (Sadowski et al. effective-FP target) and ≤ baseline |
| S3 | CI duration per commit | adaptive mean < baseline mean, bootstrap 95 % CI of the difference excludes 0 |
| S4 | Stability | identical decisions in all runs (determinism); run-mean σ < 10 % of mean |
| S5 | Realistic repo | 0 blocks of adaptive on good cases caused by pre-existing debt |
| S6 | Actionability | 100 % of blocking issues have file:line + CWE + fix snippet |
| S7 | Honesty rule | improvements with McNemar p ≥ 0.05 are reported as "not significant" |
