#!/usr/bin/env python3
"""Policy Threshold Engine: read scanner JSON, triage, decide PASS / BLOCK.

Inputs (in --results DIR, written by gate/cli.py or by hand):
  semgrep.json  gitleaks.json  trivy.json  sbom.cdx.json  sbom_base.cdx.json  meta.json
Outputs:
  findings.json                 normalised findings with triage verdicts
  decision.json                 decision, counts, timings (machine-readable)
  SECURITY_GATE_FEEDBACK.md     developer feedback (adaptive mode)
  baseline_raw.log              raw tool log (baseline mode)
  findings.sarif                SARIF 2.1.0 for GitHub code scanning
Exit code: 0 = PASS / OVERRIDDEN, 1 = BLOCK.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

GATE_ROOT = Path(__file__).resolve().parent.parent
SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
LEVEL = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

# OWASP Risk Rating Methodology, "Determining Severity" matrix:
# OWASP_MATRIX[impact][likelihood] -> overall severity
OWASP_MATRIX = {
    "HIGH":   {"LOW": "MEDIUM", "MEDIUM": "HIGH",   "HIGH": "CRITICAL"},
    "MEDIUM": {"LOW": "LOW",    "MEDIUM": "MEDIUM", "HIGH": "HIGH"},
    "LOW":    {"LOW": "INFO",   "MEDIUM": "LOW",    "HIGH": "MEDIUM"},
}
SEMGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


@dataclass
class Finding:
    tool: str
    category: str                  # sast | secret | sca
    rule_id: str
    title: str
    message: str
    file: str
    line: int
    end_line: int
    severity: str                  # normalised overall risk
    confidence: str = "MEDIUM"
    likelihood: str | None = None
    impact: str | None = None
    cwe: list[str] = field(default_factory=list)
    evidence: str = "pattern"      # taint | pattern | secret | cve
    subcategory: str = "vuln"
    trace: list[int] = field(default_factory=list)
    package: str | None = None
    installed: str | None = None
    fixed: str | None = None
    vuln_id: str | None = None
    url: str | None = None
    reachable: bool | None = None
    new_in_diff: bool | None = None
    sanitized: bool = False
    blocking: bool = False
    reason: str = ""

    @property
    def key(self) -> tuple:
        return (self.tool, self.rule_id, self.file, self.line, self.vuln_id, self.package)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def glob_to_regex(pattern: str) -> re.Pattern:
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile("^" + out + "$")


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(glob_to_regex(p).match(path) for p in patterns or [])


def in_scope(path: str, policy: dict) -> bool:
    scope = policy.get("scope", {})
    return matches_any(path, scope.get("include", ["**"])) and not matches_any(path, scope.get("exclude", []))


def cwe_ids(values) -> list[str]:
    ids = []
    for v in values or []:
        ids += [f"CWE-{n}" for n in re.findall(r"CWE-(\d+)", str(v))]
    return list(dict.fromkeys(ids))


def read_lines(repo: Path, rel: str) -> list[str]:
    try:
        return (repo / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def load_json(path: Path, default):
    if not path.exists() or path.stat().st_size == 0:
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def at_least(sev: str, threshold: str) -> bool:
    return SEVERITIES.index(sev) >= SEVERITIES.index(threshold)


def owasp_severity(likelihood: str | None, impact: str | None, fallback: str) -> str:
    if likelihood in LEVEL and impact in LEVEL:
        return OWASP_MATRIX[impact][likelihood]
    return fallback


def _trace_lines(node) -> list[int]:
    """Collect every source line mentioned in a Semgrep dataflow_trace."""
    found = []
    if isinstance(node, dict):
        if "start" in node and isinstance(node["start"], dict) and "line" in node["start"]:
            found.append(node["start"]["line"])
        for v in node.values():
            found += _trace_lines(v)
    elif isinstance(node, list):
        for v in node:
            found += _trace_lines(v)
    return found


# --------------------------------------------------------------------------- #
# normalisers
# --------------------------------------------------------------------------- #
def rule_catalogue(configs: list[str]) -> dict[str, str]:
    """rule id -> mode ('taint' | 'search') for every rule file Semgrep loaded."""
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    modes = {}
    for cfg in configs:
        p = Path(cfg)
        for f in ([p] if p.is_file() else sorted(p.rglob("*.y*ml")) if p.is_dir() else []):
            doc = yaml.load(f.read_text(encoding="utf-8"), Loader=loader) or {}
            for rule in doc.get("rules", []) or []:
                modes[rule["id"]] = rule.get("mode", "search")
    return modes


def canonical_rule(check_id: str, modes: dict[str, str]) -> str:
    """Semgrep prefixes ids with the config path (e.g. 'opt.gate.rules.registry.'); strip it."""
    parts = check_id.split(".")
    for i in range(len(parts)):
        cand = ".".join(parts[i:])
        if cand in modes:
            return cand
    return check_id


def from_semgrep(data: dict, modes: dict[str, str] | None = None) -> list[Finding]:
    modes = modes or {}
    out = []
    for r in data.get("results", []):
        rid = canonical_rule(r["check_id"], modes)
        extra = r.get("extra", {})
        md = extra.get("metadata", {}) or {}
        lik = str(md.get("likelihood", "")).upper() or None
        imp = str(md.get("impact", "")).upper() or None
        sub = md.get("subcategory") or ["vuln"]
        sub = sub[0] if isinstance(sub, list) else sub
        fallback = SEMGREP_SEVERITY.get(extra.get("severity", "WARNING"), "MEDIUM")
        trace = extra.get("dataflow_trace")
        taint = bool(trace) or modes.get(rid) == "taint"
        cwes = cwe_ids(md.get("cwe"))
        out.append(Finding(
            tool="semgrep",
            category="secret" if "secrets" in rid and "CWE-798" in cwes else "sast",
            rule_id=rid,
            title=rid.rsplit(".", 1)[-1],
            message=" ".join(str(extra.get("message", "")).split()),
            file=r["path"], line=r["start"]["line"], end_line=r["end"]["line"],
            severity=owasp_severity(lik, imp, fallback),
            confidence=str(md.get("confidence", "MEDIUM")).upper(),
            likelihood=lik, impact=imp, cwe=cwes,
            evidence="taint" if taint else "pattern", subcategory=str(sub),
            trace=sorted(set(_trace_lines(trace))) if trace else [],
            url=(md.get("references") or [None])[0] if isinstance(md.get("references"), list) else None,
        ))
    return out


def from_gitleaks(data: list) -> list[Finding]:
    out = []
    for g in data or []:
        secret = g.get("Secret", "")
        out.append(Finding(
            tool="gitleaks", category="secret", rule_id=g.get("RuleID", "secret"),
            title=g.get("Description") or g.get("RuleID", "secret"),
            message=f"{g.get('Description', 'Secret')} detected "
                    f"(value {secret[:4]}{'*' * 8}, commit {str(g.get('Commit', ''))[:8]})",
            file=g.get("File", ""), line=int(g.get("StartLine", 0) or 0),
            end_line=int(g.get("EndLine", 0) or 0),
            severity="HIGH", confidence="HIGH", likelihood="HIGH", impact="HIGH",
            cwe=["CWE-798"], evidence="secret",
        ))
    return out


def sbom_components(sbom: dict) -> dict[str, dict]:
    """purl -> {name, version, path} from a CycloneDX SBOM produced by Syft."""
    comps = {}
    for c in sbom.get("components", []) or []:
        purl = c.get("purl")
        if not purl:
            continue
        path = next((p["value"] for p in c.get("properties", []) or []
                     if p.get("name", "").startswith("syft:location:") and p["name"].endswith(":path")), "")
        comps[purl] = {"name": c.get("name"), "version": c.get("version"), "path": path.lstrip("/")}
    return comps


def from_trivy(data: dict, head_sbom: dict, manifest_prefix: str = "") -> list[Finding]:
    comps = sbom_components(head_sbom)
    out = []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            purl = (v.get("PkgIdentifier") or {}).get("PURL", "")
            path = comps.get(purl, {}).get("path") or res.get("Target", "")
            sev = v.get("Severity", "UNKNOWN").upper()
            out.append(Finding(
                tool="trivy", category="sca", rule_id=v["VulnerabilityID"],
                title=v.get("Title") or v["VulnerabilityID"],
                message=f"{v.get('PkgName')} {v.get('InstalledVersion')} is affected by "
                        f"{v['VulnerabilityID']} ({sev}); fixed in {v.get('FixedVersion') or 'no release yet'}",
                file=manifest_prefix + path, line=1, end_line=1,
                severity=sev if sev in SEVERITIES else "MEDIUM", confidence="HIGH",
                cwe=cwe_ids(v.get("CweIDs")) or ["CWE-1395"], evidence="cve",
                package=v.get("PkgName"), installed=v.get("InstalledVersion"),
                fixed=v.get("FixedVersion") or None, vuln_id=v["VulnerabilityID"],
                url=v.get("PrimaryURL"),
            ))
    return out


# --------------------------------------------------------------------------- #
# triage
# --------------------------------------------------------------------------- #
def python_imports(pkg: str, policy: dict) -> list[str]:
    name = pkg.lower().replace("_", "-")
    mapping = policy.get("sca", {}).get("python_import_names", {})
    return mapping.get(name, [name.replace("-", "_")])


def is_reachable(f: Finding, repo: Path, files: list[str], policy: dict) -> bool:
    """Import-level reachability: is the vulnerable package imported by in-scope code?"""
    if not f.package:
        return False
    if ":" in f.package:  # maven group:artifact
        group = f.package.split(":", 1)[0]
        rx = re.compile(r"^\s*import\s+(static\s+)?" + re.escape(group) + r"\.", re.M)
        exts = (".java", ".kt")
    else:
        mods = "|".join(re.escape(m) for m in python_imports(f.package, policy))
        rx = re.compile(r"^\s*(from|import)\s+(" + mods + r")(\.|\s|$|,)", re.M)
        exts = (".py",)
    for rel in files:
        if rel.endswith(exts) and rx.search("\n".join(read_lines(repo, rel))):
            return True
    return False


def triage(findings: list[Finding], policy: dict, repo: Path, meta: dict) -> None:
    mode = policy.get("name")
    if mode == "baseline":
        for f in findings:
            f.blocking, f.reason = True, "zero-tolerance: every finding fails the build"
        return

    sast, sca = policy.get("sast", {}), policy.get("sca", {})
    sanitizers = {lang: [re.compile(p) for p in pats]
                  for lang, pats in (sast.get("sanitizers") or {}).items()}
    base_purls = set(meta.get("base_components", []))
    repo_files = meta.get("repo_files", [])

    for f in findings:
        if not in_scope(f.file, policy):
            f.blocking, f.reason = False, "out of policy scope"
            continue
        if f.category == "secret" and f.tool == "gitleaks":
            allowed = matches_any(f.file, policy.get("secrets", {}).get("allow_paths", []))
            f.blocking = policy.get("secrets", {}).get("block", True) and not allowed
            f.reason = "secret committed in this change" if f.blocking else "allow-listed path"
            continue

        if f.tool == "semgrep":
            lang = "java" if f.file.endswith(".java") else "python" if f.file.endswith(".py") else ""
            lines = read_lines(repo, f.file)
            span = "\n".join(lines[max(f.line - 1, 0):max(f.end_line, f.line)])
            if sast.get("sanitizer_triage") and any(rx.search(span) for rx in sanitizers.get(lang, [])):
                f.sanitized = True
            if f.subcategory == "audit" and not sast.get("audit_blocks", False):
                f.reason = "audit-grade rule (not a confirmed vulnerability)"
            elif LEVEL.get(f.confidence, 2) < LEVEL[sast.get("min_confidence", "MEDIUM")]:
                f.reason = f"rule confidence {f.confidence} below {sast.get('min_confidence')}"
            elif not at_least(f.severity, sast.get("block_at", "HIGH")):
                f.reason = (f"OWASP risk {f.severity} (likelihood {f.likelihood or '?'} x "
                            f"impact {f.impact or '?'}) below {sast.get('block_at')}")
            elif f.sanitized:
                f.reason = "value passes through a known sanitiser on the reported line"
            else:
                f.blocking = True
                f.reason = (f"OWASP risk {f.severity}"
                            + (" with confirmed source-to-sink data flow" if f.evidence == "taint" else "")
                            + f", confidence {f.confidence}")
            continue

        if f.tool == "trivy":
            purl_key = f"{f.package}@{f.installed}"
            f.new_in_diff = purl_key not in base_purls
            f.reachable = is_reachable(f, repo, repo_files, policy)
            if sca.get("only_new_components", True) and not f.new_in_diff:
                f.reason = "pre-existing dependency (not introduced by this change)"
            elif f.severity in sca.get("always_block", ["CRITICAL"]):
                f.blocking, f.reason = True, f"{f.severity} CVE introduced by this change"
            elif not at_least(f.severity, sca.get("block_at", "HIGH")):
                f.reason = f"CVE severity {f.severity} below {sca.get('block_at')}"
            elif sca.get("require_fix_available", True) and not f.fixed:
                f.reason = "no fixed version published yet (tracked, not blocking)"
            elif sca.get("require_reachable", True) and not f.reachable:
                f.reason = "package is not imported by in-scope code"
            else:
                f.blocking = True
                f.reason = f"{f.severity} CVE, fix available ({f.fixed}), package imported"


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def load_kb() -> dict:
    return yaml.safe_load((GATE_ROOT / "rules" / "remediation.yml").read_text(encoding="utf-8"))


def kb_entry(kb: dict, cwes: list[str]) -> tuple[str, dict]:
    for c in cwes:
        c = kb["aliases"].get(c, c)
        if c in kb["entries"]:
            return c, kb["entries"][c]
    return "default", kb["entries"]["default"]


def group_issues(findings: list[Finding], kb: dict) -> list[list[Finding]]:
    """Merge findings of the same weakness in the same file (several rules / tools
    often report one bug). The representative is the most severe, most precise one."""
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        key = (f.file, kb_entry(kb, f.cwe)[0], f.package if f.category == "sca" else None)
        groups.setdefault(key, []).append(f)
    rank = lambda f: (-SEVERITIES.index(f.severity), -LEVEL.get(f.confidence, 2),  # noqa: E731
                      f.evidence != "taint", f.end_line - f.line)
    ordered = [sorted(g, key=rank) for g in groups.values()]
    return sorted(ordered, key=lambda g: rank(g[0]))


def snippet(repo: Path, f: Finding, ctx: int) -> str:
    lines = read_lines(repo, f.file)
    if not lines or f.line <= 0 or f.category == "sca":
        return ""
    end = min(max(f.end_line, f.line), f.line + 3)          # cap multi-line matches
    lo, hi = max(f.line - 1 - ctx, 0), min(end + ctx, len(lines))
    width = len(str(hi))
    out = []
    for i in range(lo, hi):
        text = lines[i]
        if f.category == "secret":
            text = re.sub(r"([\"'])([^\"']{4})[^\"']{4,}([\"'])", r"\1\2********\3", text)
        mark = ">" if f.line - 1 <= i <= end - 1 else " "
        out.append(f"{mark} {str(i + 1).rjust(width)} | {text}")
    return "\n".join(out)


def lang_of(path: str) -> str:
    if path.endswith((".java", "pom.xml")):
        return "java"
    if path.endswith((".c", ".h", ".cpp", ".cc", ".hpp")):
        return "c"
    return "python"


def render_feedback(findings: list[Finding], decision: dict, policy: dict, repo: Path, meta: dict) -> str:
    kb = load_kb()
    fb = policy.get("feedback", {})
    blocking = [f for f in findings if f.blocking]
    advisory = [f for f in findings if not f.blocking and f.reason != "out of policy scope"]
    icon = {"BLOCK": "❌ BLOCKED", "PASS": "✅ PASSED", "OVERRIDDEN": "⚠️ OVERRIDDEN"}[decision["decision"]]
    scope = meta.get("scope", {})
    md = [f"# 🔒 Security Gate: {icon}", "",
          f"**{len(group_issues(blocking, kb))} blocking issue(s)** ({len(blocking)} findings) · {len(advisory)} advisory · "
          f"scope: {len(scope.get('scanned_files', []))} changed file(s) "
          f"(`{meta.get('base', '')[:10]}..{meta.get('head', '')[:10]}`) · "
          f"{decision['total_seconds']:.1f}s · policy `{policy.get('name')}` v{policy.get('version')}", ""]
    if decision["decision"] == "OVERRIDDEN":
        o = decision["override"]
        md += [f"> ⚠️ **Emergency override** by `{o['actor']}`: {o['reason']}",
               "> Blocking findings below were NOT fixed. A follow-up fix is required; this event is logged in `audit.jsonl`.", ""]
    if blocking:
        md += ["## Blocking issues — fix before merge", ""]
        for i, group in enumerate(group_issues(blocking, kb), 1):
            f = group[0]
            cwe, e = kb_entry(kb, f.cwe)
            lang = lang_of(f.file)
            loc = f"`{f.file}:{f.line}`" if f.category != "sca" else f"`{f.file}`"
            md += [f"### {i}. [{f.severity}] {e['title']} — {cwe} — {loc}", "",
                   f"- **Rule:** `{f.rule_id}` ({f.tool}, {f.evidence}, confidence {f.confidence})",
                   f"- **Why it blocks:** {f.reason}",
                   f"- **Risk:** {e['why']}"]
            if len(group) > 1:
                also = ", ".join(sorted({f"`{g.rule_id.rsplit('.', 1)[-1]}` (L{g.line})" for g in group[1:]}))
                md.append(f"- **Also reported by:** {also} — merged into one issue")
            if f.message:
                md.append(f"- **Detail:** {f.message}")
            if f.trace:
                md.append(f"- **Data flow (lines):** {' → '.join(map(str, f.trace))}")
            snip = snippet(repo, f, fb.get("context_lines", 2))
            if snip:
                md += ["", f"```{lang}", snip, "```"]
            fix = e["fix"].get(lang) or e["fix"].get("generic")
            if f.category == "sca" and f.fixed:
                fix = f"Upgrade {f.package} {f.installed} → {f.fixed.split(',')[0].strip()}\n" + (fix or "")
            md += ["", f"**How to fix ({lang if lang in e['fix'] else 'general'}):**", "",
                   f"```{lang if lang in e['fix'] else 'text'}", (fix or "").rstrip(), "```"]
            if e.get("extra"):
                md += ["", e["extra"].rstrip()]
            refs = ([f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"] if cwe != "default" else []) \
                + [r for r in e.get("refs", []) if "cwe.mitre.org" not in r] + ([f.url] if f.url else [])
            md += ["", "References: " + " · ".join(dict.fromkeys(refs)), ""]
    if advisory:
        limit = fb.get("max_advisories", 25)
        md += ["<details><summary>" + f"{len(advisory)} advisory finding(s) — not blocking</summary>", "",
               "| Severity | Tool | Location | Rule | Why not blocking |", "|---|---|---|---|---|"]
        for f in advisory[:limit]:
            md.append(f"| {f.severity} | {f.tool} | `{f.file}:{f.line}` | `{f.rule_id.rsplit('.', 1)[-1]}` | {f.reason} |")
        md += ["", "</details>", ""]
    md += ["## Scanner summary", "", "| Tool | Status | Findings | Wall time (s) | Max RSS (MB) |", "|---|---|---|---|---|"]
    for name, t in meta.get("tools", {}).items():
        n = sum(1 for f in findings if f.tool == name)
        rss = f"{t['max_rss_kb'] / 1024:.0f}" if t.get("max_rss_kb") else "-"
        md.append(f"| {name} | {t.get('status')} | {n if t.get('status') == 'ok' else '-'} | {t.get('wall', 0):.2f} | {rss} |")
    if decision["decision"] == "BLOCK" and policy.get("override", {}).get("enabled"):
        md += ["", "<sub>Production emergency? A maintainer can add the `security-override` label and a line "
               "`Override-Reason: <ticket + justification>` to the PR description. Overrides are audited.</sub>"]
    return "\n".join(md) + "\n"


def render_raw_log(findings: list[Finding], meta: dict) -> str:
    out = ["=== BASELINE SECURITY GATE (full scan, zero tolerance) ==="]
    for name, t in meta.get("tools", {}).items():
        out.append(f"[{name}] status={t.get('status')} wall={t.get('wall', 0):.2f}s")
    for f in findings:
        out.append(f"{f.tool}:{f.rule_id}:{f.file}:{f.line}:{f.severity}:{f.message}")
    out.append(f"BUILD {'FAILED' if findings else 'PASSED'}: {len(findings)} finding(s)")
    return "\n".join(out) + "\n"


def to_sarif(findings: list[Finding]) -> dict:
    level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    rules, results = {}, []
    for f in findings:
        rules.setdefault(f.rule_id, {"id": f.rule_id, "shortDescription": {"text": f.title[:120]},
                                     "properties": {"tags": f.cwe}})
        results.append({
            "ruleId": f.rule_id, "level": level[f.severity],
            "message": {"text": f"{f.message} [{'BLOCKING' if f.blocking else 'advisory'}: {f.reason}]"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                "region": {"startLine": max(f.line, 1)}}}],
        })
    return {"version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "dt074-security-gate", "rules": list(rules.values())}},
                      "results": results}]}


# --------------------------------------------------------------------------- #
def evaluate(results: Path, policy_path: Path, repo: Path) -> dict:
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    meta = load_json(results / "meta.json", {})
    modes = rule_catalogue(meta.get("semgrep_configs", []))
    findings = (from_semgrep(load_json(results / "semgrep.json", {}), modes)
                + from_gitleaks(load_json(results / "gitleaks.json", []))
                + from_trivy(load_json(results / "trivy.json", {}),
                             load_json(results / "sbom.cdx.json", {}), meta.get("sbom_prefix", "")))
    unique = {}
    for f in findings:
        unique.setdefault(f.key, f)
    findings = list(unique.values())
    triage(findings, policy, repo, meta)

    failed_tools = [n for n, t in meta.get("tools", {}).items() if t.get("status") == "error"]
    blocking = [f for f in findings if f.blocking]
    decision = "BLOCK" if blocking or failed_tools else "PASS"   # fail closed on scanner error
    override = None
    reason = os.environ.get("GATE_OVERRIDE_REASON", "").strip()
    ov = policy.get("override", {})
    if decision == "BLOCK" and reason and ov.get("enabled"):
        if len(reason) >= ov.get("min_reason_length", 15):
            decision = "OVERRIDDEN"
            override = {"actor": os.environ.get("GATE_OVERRIDE_ACTOR", "unknown"), "reason": reason,
                        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "blocking_findings": [f"{f.rule_id}@{f.file}:{f.line}" for f in blocking]}
            with (results / "audit.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(override) + "\n")
        else:
            print(f"[gate] override ignored: reason shorter than {ov.get('min_reason_length', 15)} chars",
                  file=sys.stderr)

    total = meta.get("total_seconds", sum(t.get("wall", 0) for t in meta.get("tools", {}).values()))
    result = {
        "mode": policy.get("name"), "decision": decision,
        "exit_code": 1 if decision == "BLOCK" else 0,
        "failed_tools": failed_tools,
        "counts": {"total": len(findings), "blocking": len(blocking),
                   "blocking_issues": len(group_issues(blocking, load_kb())),
                   "advisory": len(findings) - len(blocking),
                   "by_tool": {t: sum(1 for f in findings if f.tool == t) for t in ("semgrep", "gitleaks", "trivy")},
                   "blocking_by_tool": {t: sum(1 for f in blocking if f.tool == t)
                                        for t in ("semgrep", "gitleaks", "trivy")}},
        "total_seconds": total, "tools": meta.get("tools", {}),
        "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "override": override,
    }
    (results / "findings.json").write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")
    (results / "decision.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (results / "findings.sarif").write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")
    if policy.get("feedback", {}).get("markdown"):
        (results / policy["feedback"]["markdown"]).write_text(
            render_feedback(findings, result, policy, repo, meta), encoding="utf-8")
    else:
        (results / "baseline_raw.log").write_text(render_raw_log(findings, meta), encoding="utf-8")
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="DT074 policy threshold engine")
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--repo", type=Path, default=Path("."))
    args = ap.parse_args()
    res = evaluate(args.results, args.policy, args.repo.resolve())
    print(f"[gate] {res['mode']}: {res['decision']} ({res['counts']['blocking']} blocking / "
          f"{res['counts']['total']} findings)")
    sys.exit(res["exit_code"])


if __name__ == "__main__":
    main()
