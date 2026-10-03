# DT074 — Adaptive Security Gate for Java/Python CI/CD

A CI/CD security gate that combines **SAST (Semgrep)**, **secret scanning
(Gitleaks)**, **SBOM generation (Syft)**, **dependency scanning (Trivy)** and a
**policy threshold engine** written for this project. It is evaluated against a
traditional zero-tolerance gate on **NIST SARD / Juliet** test cases.

Course project DT074 — *Xây security gate trong CI/CD cho dự án Java/Python*
Course: An toàn và bảo mật hệ thống thông tin — Lecturer: ThS. Phạm Trọng Huynh
Student: Nguyễn Lê Anh Trúc — MSSV 1150080078 — Lớp 11ĐHCNPM1
Reference paper: Assal et al., *Software security in practice: knowledge and
motivation*, Journal of Cybersecurity 11(1), 2025, [10.1093/cybsec/tyaf005](https://doi.org/10.1093/cybsec/tyaf005)
(Vietnamese section-by-section summary: [docs/PAPER_SUMMARY_VI.md](docs/PAPER_SUMMARY_VI.md);
reproduction sheet: [docs/PAPER_MAPPING.md](docs/PAPER_MAPPING.md)).

## What is compared

| | Baseline gate | Proposed adaptive gate |
|---|---|---|
| Scope | Whole repository, every commit | `git diff base..head` only, plus language-aware rule selection |
| Secrets | Full git history | Commits in the PR range |
| SCA / SBOM | Always | Only when a dependency manifest changes. Only vulnerabilities **introduced** by the change can block |
| Decision | Any finding → `exit 1` | OWASP risk (likelihood × impact) ≥ HIGH, confidence ≥ MEDIUM, not an audit-grade rule, not sanitised. SCA: CRITICAL, or HIGH with a fix available and the package imported |
| Output | Raw log | `SECURITY_GATE_FEEDBACK.md` (line, CWE, fix snippet, references), SARIF, PR comment, chat webhook |
| Emergency | — | Audited override (`security-override` label + `Override-Reason:`) |

## Repository layout

```
Dockerfile               pinned toolchain (versions + vendor SHA-256), frozen rules + CVE DB
action.yml               reusable GitHub Action (composite)
.github/workflows/       CI for this repo (dogfoods action.yml) + weekly debt scan
gate/cli.py              orchestrator: targets, scanners, timing / CPU / RAM
gate/evaluate_gate.py    policy threshold engine: normalise → triage → decide → feedback
gate/notify.py           Discord / Slack / Telegram webhook on BLOCK
policy/                  baseline.yml, adaptive.yml (every mechanism can be toggled)
rules/custom/            DT074 Semgrep taint / credential rules (Java, Python)
rules/remediation.yml    CWE → explanation + fix snippets
rules/RULE_CHANGELOG.md  audit trail of rule tuning (main split only)
app/                     demo service (Flask + Java) used as the host repository
dataset/                 SARD subsets, labels.csv, manifest.sha256 (generated)
scripts/                 setup_tools, setup_fixtures(_cpp), run_experiment, analyze, demo
tests/                   unit, negative and integration tests
results/                 experiment outputs (runs.csv, summary.md, charts, raw logs)
docs/                    paper mapping, results, report material
```

## Quick start (from zero)

Requirements: Docker (Docker Desktop with the WSL2 backend on Windows), Python ≥ 3.10, git.

### Windows (PowerShell)

```powershell
git clone https://github.com/trucnguyen102004-ctrl/cicd-security-policy-engine-dt074.git
cd cicd-security-policy-engine-dt074
Set-ExecutionPolicy -Scope Process Bypass
pip install -r requirements-dev.txt     # host-side analysis only
.\run_local.ps1 setup                   # build image, download Juliet, build dataset
.\run_local.ps1 test                    # 32 unit + 9 integration tests
.\run_local.ps1 demo                    # Demo 1 (blocked) / Demo 2 (passes)
.\run_local.ps1 experiment              # main experiment (~2-3 h)
.\run_local.ps1 analyze exp1-main       # tables + charts
```

### Linux / macOS

```bash
python3 scripts/setup_tools.py          # docker build -t security-gate:1.0 . + version check
python3 scripts/setup_fixtures.py       # Juliet Java 1.3 (SARD #111) -> dataset/
python3 scripts/setup_fixtures_cpp.py   # Juliet C/C++ 1.3 (SARD #112) -> dataset/sard112_cpp/
RUN="docker run --rm -e GATE_REGISTRY=/opt/gate/rules/registry -v $PWD:/src -w /src --entrypoint"
$RUN bash security-gate:1.0 scripts/demo.sh
$RUN python security-gate:1.0 scripts/run_experiment.py --runs 3 --seed 42 --out /src/results/exp1-main
python3 scripts/analyze.py results/exp1-main --charts
```

### Use the gate in another repository

```yaml
# .github/workflows/security.yml
on: [pull_request]
permissions: { contents: read, pull-requests: write }
jobs:
  gate:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: trucnguyen102004-ctrl/cicd-security-policy-engine-dt074@main
        with:
          mode: adaptive          # or baseline
          # policy: .security/policy.yml
```

Or run it by hand: `python scripts/evaluate_gate.py --variant proposed --repo . --base origin/main`
(inside the container), or `--variant baseline` for the zero-tolerance gate.

## Data

| Split | Source | Content | Role |
|---|---|---|---|
| main | SARD #111 Juliet Java 1.3 (flow variant 01) + SARD-derived Python + 4 SCA cases | 17 bad / 17 good | Rule development ("tuning") |
| holdout | SARD #111, flow variants 02/03 and other sources/sinks | 11 bad / 11 good | Generalisation. Fixed before any rule was written and never used for tuning |
| cpp112 | SARD #112 Juliet C/C++ 1.3 (flow variant 01) | 12 bad / 12 good | External validity. No custom rules, no tuning |

- Juliet Java 1.3: `2017-10-01-juliet-test-suite-for-java-v1-3.zip`, SHA-256
  `d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60`.
  Juliet C/C++ 1.3: SHA-256 `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb`.
  Both are public domain (17 USC 105) / CC0 1.0. They are downloaded by the setup
  scripts and not redistributed, except for the derived samples in `dataset/`.
- Each Juliet file is split into a `bad()`-only and a `good()`-only unit. Method
  bodies are kept verbatim and normalised to LF. `labels.csv` holds the ground truth.
  `manifest.sha256` hashes every sample, and `tests/` check the hashes, duplicates and
  main/holdout leakage.
- Selection rules and the CWE mapping are documented in `scripts/setup_fixtures*.py`.

## Reproducibility

- Scanner versions: Semgrep 1.178.0, Gitleaks 8.30.1, Trivy 0.74.0, Syft 1.52.0.
  Each is pinned in the `Dockerfile` and checked against the vendor SHA-256.
- The Semgrep Registry rules and the Trivy vulnerability DB are frozen at image
  build time. Their hashes and dates are written to `results/<exp>/environment.json`.
  Registry rules are not committed (Semgrep Rules License).
- The experiment uses a fixed seed (`--seed 42`, case order per run), alternates
  the variant execution order, runs ≥ 3 times, and keeps every raw scanner output
  under `results/<exp>/raw/` (published as `raw.tar.gz`).
- `results/<exp>/config.json` + `policies/` record every parameter of a run.

## Metrics

Detection coverage (recall on `bad()`), **CWE-matched coverage** (a block only
counts if a blocking finding has the labelled CWE), False Block Rate (on `good()`),
precision / F1 / MCC, CI duration (μ ± σ, p95, per-run stability), CPU time and
peak RSS. 95 % Wilson CIs, exact McNemar tests, and paired-bootstrap CIs for time
differences are computed by `scripts/analyze.py`. See `docs/RESULTS.md`.

## Ethics and safety

Only public test suites (NIST SARD) and synthetic code are scanned, inside local
containers and repositories owned by the author. No real system is scanned or
attacked. The secrets in `dataset/` are fabricated, provider-neutral strings
created for testing. The feedback, PR comments and webhooks never print a secret
value (it is masked).

## License

Code: MIT. Juliet-derived samples: public domain / CC0 (NIST).
