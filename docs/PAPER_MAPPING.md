# Reproduction sheet — Assal et al. (2025)

**Paper.** H. Assal, S. G. Morkonda, M. Z. Arif, S. Chiasson. *Software security in
practice: knowledge and motivation.* Journal of Cybersecurity 11(1), tyaf005, 2025.
DOI [10.1093/cybsec/tyaf005](https://doi.org/10.1093/cybsec/tyaf005).

## 1. What the paper does

| Item | Paper |
|---|---|
| Problem | Why developers do / do not adopt software-security practices |
| RQ1 | How do developers acquire software-security knowledge? |
| RQ2 | What motivates developers to adopt software-security practices? |
| Design | Qualitative, semi-structured interviews (~1 h each), 3 waves until saturation |
| Participants | 13 professional developers, 15 companies, North America, all with university degrees, mean 9.35 years of experience |
| Analysis | Grounded Theory (Strauss & Corbin): open coding (170 codes / 600 excerpts, Atlas.ti), axial and selective coding; Self-Determination Theory (SDT) continuum for motivation |
| Output | Taxonomy of learning activities (formal / semi-formal / informal); motivation continuum (amotivation → external → internal); model of *internalising* security through perceived competence + relatedness |
| Metrics | None quantitative (self-rated knowledge 1–5, demographics only) |

## 2. Why a literal reproduction is impossible, and what we reproduce

The paper publishes no quantitative dataset and no tool measurements, so its
numbers cannot be "re-run". Interviews are also out of scope for a course project
(ethics approval, recruitment). We therefore do a **selective, operational
reproduction**:

1. Extract the paper's findings that concern tooling and workflow (§3).
2. Turn each into a **design requirement** for a CI security gate.
3. Pair each with a **measurable proxy** and test it against a baseline gate on
   NIST SARD / Juliet.

The results support or refute *our design hypotheses*. They do not confirm or
refute the paper's qualitative claims about developers. We state this in the
report and do **not** claim to "outperform" the paper.

## 3. Findings / limitations extracted (≥ 5) → design requirement → metric

| # | Source | Finding (verbatim where quoted) | Design requirement in DT074 | Proxy metric (this project) |
|---|---|---|---|---|
| F1 | Paper, amotivation | Static-analysis warnings trigger amotivation when "developers perceive the security warnings from these tools as unuseful", i.e. incompatible with their workflow | Show findings **inside the PR**. Group duplicates into issues. Block only on high-risk evidence and keep the rest as advisories | False Block Rate on `good()`; findings→issues ratio; advisories per PR |
| F2 | Paper (citing Danilova et al.) | Developers are "more receptive when the security warnings include code examples" | `SECURITY_GATE_FEEDBACK.md` gives exact line, CWE link, and a language-specific **fix snippet** | Actionability coverage: % of blocking issues that have location + CWE + fix snippet |
| F3 | Paper, perceived lack of competence | "teams do not have the necessary budget, time, people-power, or expertise"; "security tools are nonexistent or lacking" | A zero-install, pinned, reusable GitHub Action. Cheap per-commit cost: differential scanning, language-aware rules | CI duration (μ ± σ), CPU s, peak RSS |
| F4 | Paper, defiance / resistance | Developers ignore security when it "conflicts with their perception of the proper way of coding" (inflexible rules) | Risk-based policy (OWASP likelihood × impact), sanitiser-aware triage, per-path scope, **audited emergency override** instead of all-or-nothing | FBR; blocks caused by pre-existing debt (realistic profile) |
| F5 | Paper, priorities | Pressure leads "developers to sacrifice security for other functional requirements"; low-value tasks are dropped | Do not charge the developer for old debt (new-code-only SCA). Weekly non-blocking full scan instead | Blocks on unrelated clean commits in the realistic profile |
| F6 | Paper, dev ↔ security-testing disconnect | Testers "have zero knowledge about the code itself" (P8) | Shift-left: the same pinned gate runs locally and in CI, and every developer sees the result | (qualitative; demo) |
| F7 | Paper, learning | Developers "favored in-context learning activities (Semi-Formal and Informal)" | Feedback explains *why* and links CWE / OWASP cheat-sheets on every block (semi-formal in-context learning) | Actionability coverage (as F2) |
| L-a | Related work, not in the paper: Johnson et al., ICSE 2013; Sadowski et al., CACM 2018 | False positives and poor warning presentation are the main reason developers abandon static analysis. Google's "effective false-positive" rate target is < 10 % | FBR target < 10 % on `good()` | FBR with Wilson 95 % CI |
| L-b | Related work (not in the paper) | Slow analyses are skipped or moved out of the developer loop | Differential scanning | Speed-up vs baseline; scalability curve |

### Methodological limitations of the paper (reproduction checklist)

1. **Small, homogeneous sample**: 13 participants, North America, all degree
   holders. Generalisability is limited, as the authors acknowledge.
2. **Self-report / volunteer bias**: people who agree to talk about security may
   be more motivated than average.
3. **No inter-rater reliability reported** for the qualitative coding.
4. **No quantitative outcome measures**: there are no tool metrics or security
   outcomes, so no effect sizes can be reproduced.
5. **Tooling is peripheral**: CI/CD, automation and false positives are not
   studied, so our CI-specific hypotheses extend the paper rather than replicate it.
6. **One participant per company**: organisational factors are inferred from a
   single viewpoint.

## 4. Hypotheses tested here

- **H1 (F1, L-a)**: the adaptive gate has a lower False Block Rate than the
  zero-tolerance baseline on `good()` samples, without lower detection coverage.
- **H2 (F3, L-b)**: the adaptive gate has a shorter per-commit CI duration, and
  its cost does not grow with repository size.
- **H3 (F2, F7)**: every blocking issue in adaptive feedback is actionable
  (location + CWE + fix). The baseline raw log provides none of these.
- **H4 (F4, F5)**: in a repository with pre-existing debt, the adaptive gate does
  not block unrelated clean commits, while the baseline blocks all of them.
- **H5 (generalisation)**: triage gains carry over to held-out Juliet Java cases
  (#111) and, without any tuning, to Juliet C/C++ (#112).

The mapping of measured results to H1–H5 is in `docs/RESULTS.md`, which is
generated after the experiments.
