# Custom rule development log

Rules were developed **only** against the *main* split (`dataset/sard_samples`).
The *holdout* split (`dataset/holdout_samples`) was fixed in
`scripts/setup_fixtures.py` before the first rule was written and is only
scanned by `scripts/run_experiment.py`. Every change made after looking at
scanner output is recorded here so the tuning effort is auditable.

| # | Date | Rule | Change | Trigger (main split only) |
|---|------|------|--------|---------------------------|
| 1 | 2026-09-30 | all `dt074.*` | Initial version from OWASP / find-sec-bugs source–sink–sanitiser catalogues | — |
| 2 | 2026-09-30 | `dt074.python.xss.tainted-flask-response` | Added `open(...)` / `io.open(...)` as sanitisers | P03-good: file *contents* read via a sanitised path were treated as reflected request data (rule design flaw, not a sample-specific tweak) |
