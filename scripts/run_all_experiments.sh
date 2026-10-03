#!/usr/bin/env bash
# Runs the secondary experiments in sequence (inside the gate container, repo at /src).
# exp1 (main) is run separately: scripts/run_experiment.py --runs 3 --out results/exp1-main
set -euo pipefail
cd /src
python scripts/setup_fixtures_cpp.py --verify-only
# exp4: external validity on SARD #112 (C/C++), registry rules only, no custom rules / tuning
GATE_REGISTRY=/src/.cache/registry-merged python scripts/run_experiment.py --runs 3 --seed 42 \
  --profiles isolated,realistic --splits cpp112 --labels labels_cpp.csv --policy-dir policy/cpp \
  --out results/exp4-cpp112
# exp2: ablation (decisions were 100% stable across runs in exp1 -> 1 run per variant)
python scripts/run_experiment.py --runs 1 --seed 42 --ablation --profiles isolated,realistic \
  --splits main,holdout \
  --variants adaptive-no_differential,adaptive-no_language_aware,adaptive-no_custom_rules,adaptive-no_risk_threshold,adaptive-no_sanitizer_triage,adaptive-no_sca_triage \
  --out results/exp2-ablation
# exp3: scalability with repository size
python scripts/run_experiment.py --runs 3 --seed 42 --profiles realistic --scale 0,10,40 \
  --variants baseline,adaptive --cases J01-bad,J01-good,P01-bad,P01-good,S01-bad,S03-good \
  --out results/exp3-scale
echo "ALL EXPERIMENTS DONE"
