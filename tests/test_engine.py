"""Unit + negative tests for the policy threshold engine (no scanners needed)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "gate"))      # gate/ first: scripts/evaluate_gate.py is only a CLI alias

import yaml  # noqa: E402
import evaluate_gate as eg  # noqa: E402
import setup_fixtures as sf  # noqa: E402

ADAPTIVE = yaml.safe_load((ROOT / "policy" / "adaptive.yml").read_text(encoding="utf-8"))
BASELINE = yaml.safe_load((ROOT / "policy" / "baseline.yml").read_text(encoding="utf-8"))


def sast(**kw):
    base = dict(tool="semgrep", category="sast", rule_id="r", title="t", message="m", file="app/A.java",
                line=3, end_line=3, severity="HIGH", confidence="HIGH", likelihood="HIGH", impact="MEDIUM",
                cwe=["CWE-89"], evidence="taint")
    base.update(kw)
    return eg.Finding(**base)


def cve(**kw):
    base = dict(tool="trivy", category="sca", rule_id="CVE-1", title="t", message="m",
                file="app/requirements.txt", line=1, end_line=1, severity="HIGH", confidence="HIGH",
                cwe=["CWE-1395"], evidence="cve", package="pyyaml", installed="5.3.1", fixed="5.4",
                vuln_id="CVE-1")
    base.update(kw)
    return eg.Finding(**base)


class RepoCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        (self.repo / "app").mkdir()
        (self.repo / "app" / "A.java").write_text(
            "class A {\n void f() {\n  s.executeQuery(\"x\" + d);\n  w.println(Encode.forHtml(d));\n }\n}\n")
        (self.repo / "app" / "cfg.py").write_text("import yaml\n")

    def tearDown(self):
        self.tmp.cleanup()


class GlobAndScope(unittest.TestCase):
    def test_globstar(self):
        self.assertTrue(eg.matches_any("dataset/sard_samples/bad/x.java", ["dataset/**"]))
        self.assertTrue(eg.matches_any("a/b/requirements.txt", ["**/requirements*.txt"]))
        self.assertTrue(eg.matches_any("requirements.txt", ["**/requirements*.txt"]))
        self.assertFalse(eg.matches_any("app/testcases/x.java", ["**/test/**"]))

    def test_dataset_is_out_of_scope(self):
        self.assertFalse(eg.in_scope("dataset/sard_samples/bad/a.py", ADAPTIVE))
        self.assertTrue(eg.in_scope("app/python/service.py", ADAPTIVE))


class OwaspMatrix(unittest.TestCase):
    def test_matrix(self):
        self.assertEqual(eg.owasp_severity("HIGH", "HIGH", "LOW"), "CRITICAL")
        self.assertEqual(eg.owasp_severity("HIGH", "MEDIUM", "LOW"), "HIGH")
        self.assertEqual(eg.owasp_severity("MEDIUM", "MEDIUM", "LOW"), "MEDIUM")
        self.assertEqual(eg.owasp_severity("LOW", "LOW", "LOW"), "INFO")

    def test_fallback_when_metadata_missing(self):
        self.assertEqual(eg.owasp_severity(None, "HIGH", "MEDIUM"), "MEDIUM")


class Triage(RepoCase):
    def triage(self, findings, policy=ADAPTIVE, meta=None):
        eg.triage(findings, policy, self.repo, meta or {"repo_files": ["app/cfg.py", "app/A.java"]})
        return findings

    def test_baseline_blocks_everything(self):
        f = self.triage([sast(severity="INFO", confidence="LOW")], BASELINE)[0]
        self.assertTrue(f.blocking)

    def test_high_risk_taint_blocks(self):
        self.assertTrue(self.triage([sast()])[0].blocking)

    def test_medium_risk_is_advisory(self):
        f = self.triage([sast(severity="MEDIUM")])[0]
        self.assertFalse(f.blocking)
        self.assertIn("below HIGH", f.reason)

    def test_low_confidence_is_advisory(self):
        self.assertFalse(self.triage([sast(confidence="LOW")])[0].blocking)

    def test_audit_rule_is_advisory(self):
        self.assertFalse(self.triage([sast(subcategory="audit")])[0].blocking)

    def test_sanitised_line_is_advisory(self):
        f = self.triage([sast(line=4, end_line=4, cwe=["CWE-79"])])[0]
        self.assertTrue(f.sanitized)
        self.assertFalse(f.blocking)

    def test_out_of_scope_never_blocks(self):
        self.assertFalse(self.triage([sast(file="dataset/sard_samples/bad/A.java")])[0].blocking)

    def test_secret_always_blocks(self):
        f = eg.Finding(tool="gitleaks", category="secret", rule_id="generic-api-key", title="k", message="m",
                       file="app/cfg.py", line=1, end_line=1, severity="HIGH")
        self.assertTrue(self.triage([f])[0].blocking)

    def test_sca_critical_new_blocks(self):
        self.assertTrue(self.triage([cve(severity="CRITICAL")])[0].blocking)

    def test_sca_preexisting_is_advisory(self):
        meta = {"repo_files": ["app/cfg.py"], "base_components": ["pyyaml@5.3.1"]}
        f = self.triage([cve(severity="CRITICAL")], meta=meta)[0]
        self.assertFalse(f.blocking)
        self.assertIn("pre-existing", f.reason)

    def test_sca_high_needs_reachability(self):
        self.assertTrue(self.triage([cve()])[0].blocking)                  # yaml is imported
        self.assertFalse(self.triage([cve(package="requests")])[0].blocking)  # not imported

    def test_sca_high_without_fix_is_advisory(self):
        self.assertFalse(self.triage([cve(fixed=None)])[0].blocking)

    def test_sca_medium_is_advisory(self):
        self.assertFalse(self.triage([cve(severity="MEDIUM")])[0].blocking)

    def test_java_reachability_by_group(self):
        (self.repo / "app" / "L.java").write_text("import org.apache.logging.log4j.LogManager;\n")
        f = cve(package="org.apache.logging.log4j:log4j-core", file="app/pom.xml")
        self.assertTrue(eg.is_reachable(f, self.repo, ["app/L.java"], ADAPTIVE))


class Decision(RepoCase):
    """End-to-end evaluate() on hand-written scanner JSON (integration without scanners)."""

    def write(self, semgrep=None, gitleaks=None, tools=None):
        res = self.repo / "out"
        res.mkdir(exist_ok=True)
        (res / "semgrep.json").write_text(json.dumps({"results": semgrep or []}))
        (res / "gitleaks.json").write_text(json.dumps(gitleaks or []))
        meta = {"tools": tools or {"semgrep": {"status": "ok", "wall": 1.0}}, "repo_files": [],
                "scope": {"scanned_files": ["app/A.java"]}, "base": "a" * 40, "head": "b" * 40}
        (res / "meta.json").write_text(json.dumps(meta))
        return res

    SQLI = {"check_id": "dt074.java.sqli.tainted-jdbc", "path": "app/A.java",
            "start": {"line": 3}, "end": {"line": 3},
            "extra": {"severity": "ERROR", "message": "sqli",
                      "metadata": {"cwe": ["CWE-89: SQLi"], "confidence": "HIGH", "likelihood": "HIGH",
                                   "impact": "HIGH", "subcategory": ["vuln"]}}}

    def test_block_writes_feedback_with_fix(self):
        res = self.write([self.SQLI])
        out = eg.evaluate(res, ROOT / "policy" / "adaptive.yml", self.repo)
        self.assertEqual(out["decision"], "BLOCK")
        md = (res / "SECURITY_GATE_FEEDBACK.md").read_text(encoding="utf-8")
        self.assertIn("CWE-89", md)
        self.assertIn("prepareStatement", md)          # remediation snippet
        self.assertIn("app/A.java:3", md)              # exact location
        sarif = json.loads((res / "findings.sarif").read_text())
        self.assertEqual(sarif["version"], "2.1.0")

    def test_clean_passes(self):
        out = eg.evaluate(self.write([]), ROOT / "policy" / "adaptive.yml", self.repo)
        self.assertEqual(out["decision"], "PASS")
        self.assertEqual(out["exit_code"], 0)

    def test_fail_closed_on_scanner_error(self):
        res = self.write([], tools={"semgrep": {"status": "error", "wall": 0.1}})
        out = eg.evaluate(res, ROOT / "policy" / "adaptive.yml", self.repo)
        self.assertEqual(out["decision"], "BLOCK")

    def test_override_requires_reason(self):
        res = self.write([self.SQLI])
        os.environ["GATE_OVERRIDE_REASON"] = "hotfix"
        try:
            self.assertEqual(eg.evaluate(res, ROOT / "policy" / "adaptive.yml", self.repo)["decision"], "BLOCK")
            os.environ["GATE_OVERRIDE_REASON"] = "INC-4211 payment outage, fix tracked in SEC-77"
            out = eg.evaluate(res, ROOT / "policy" / "adaptive.yml", self.repo)
            self.assertEqual(out["decision"], "OVERRIDDEN")
            self.assertEqual(out["exit_code"], 0)
            audit = (res / "audit.jsonl").read_text().strip().splitlines()
            self.assertEqual(len(audit), 1)
            self.assertIn("dt074.java.sqli.tainted-jdbc@app/A.java:3", audit[0])
        finally:
            os.environ.pop("GATE_OVERRIDE_REASON", None)

    def test_baseline_cannot_be_overridden(self):
        res = self.write([self.SQLI])
        os.environ["GATE_OVERRIDE_REASON"] = "INC-4211 payment outage, fix tracked in SEC-77"
        try:
            out = eg.evaluate(res, ROOT / "policy" / "baseline.yml", self.repo)
            self.assertEqual(out["decision"], "BLOCK")
            self.assertTrue((res / "baseline_raw.log").exists())
        finally:
            os.environ.pop("GATE_OVERRIDE_REASON", None)

    def test_secret_value_is_redacted(self):
        (self.repo / "app" / "k.py").write_text('api_key = "Zq8vN3kLx7Tb2RmW9pYc4HsJ6dFa1GeU"\n')
        leak = [{"RuleID": "generic-api-key", "Description": "Generic API Key", "File": "app/k.py",
                 "StartLine": 1, "EndLine": 1, "Secret": "Zq8vN3kLx7Tb2RmW9pYc4HsJ6dFa1GeU", "Commit": "abc"}]
        res = self.write([], leak)
        eg.evaluate(res, ROOT / "policy" / "adaptive.yml", self.repo)
        md = (res / "SECURITY_GATE_FEEDBACK.md").read_text(encoding="utf-8")
        self.assertNotIn("Zq8vN3kLx7Tb2RmW9pYc4HsJ6dFa1GeU", md)
        self.assertIn("Rotate", md)

    def test_duplicate_rules_merge_into_one_issue(self):
        dup = json.loads(json.dumps(self.SQLI))
        dup["check_id"] = "java.lang.security.audit.formatted-sql-string.formatted-sql-string"
        out = eg.evaluate(self.write([self.SQLI, dup]), ROOT / "policy" / "adaptive.yml", self.repo)
        self.assertEqual(out["counts"]["blocking"], 2)
        self.assertEqual(out["counts"]["blocking_issues"], 1)


class CanonicalRuleIds(unittest.TestCase):
    def test_prefix_stripped(self):
        modes = {"dt074.java.sqli.tainted-jdbc": "taint"}
        self.assertEqual(eg.canonical_rule("src.rules.custom.dt074.java.sqli.tainted-jdbc", modes),
                         "dt074.java.sqli.tainted-jdbc")

    def test_custom_rules_parse_and_are_taint(self):
        modes = eg.rule_catalogue([str(ROOT / "rules" / "custom")])
        self.assertEqual(modes["dt074.java.sqli.tainted-jdbc"], "taint")
        self.assertEqual(modes["dt074.java.secrets.hardcoded-credential"], "search")
        for rid in modes:
            self.assertTrue(rid.startswith("dt074."))


class JulietSplitter(unittest.TestCase):
    SRC = """package p;
public class T_01 extends AbstractTestCase
{
    public void bad() throws Throwable
    {
        String s = "}{ not a brace";   /* } */
        // }
        char c = '}';
    }
    public void good() throws Throwable
    {
        goodG2B();
    }
    /* goodG2B() - uses goodsource */
    private void goodG2B() throws Throwable
    {
        if (true) { int x = 1; }
    }
    public static void main(String[] args)
    {
        mainFromParent(args);
    }
}
"""

    def test_split_is_brace_and_literal_aware(self):
        bad, good = sf.split_juliet(self.SRC, "T_01")
        self.assertIn("class T_01_bad", bad)
        self.assertIn('"}{ not a brace"', bad)
        self.assertNotIn("goodG2B", bad)
        self.assertNotIn("main(", bad)
        self.assertIn("class T_01_good", good)
        self.assertIn("/* goodG2B() - uses goodsource */", good)
        self.assertNotIn("void bad(", good)
        self.assertEqual(good.count("{"), good.count("}"))


class DatasetIntegrity(unittest.TestCase):
    def test_manifest_matches(self):
        self.assertTrue(sf.verify_manifest())

    def test_tampering_is_detected(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:          # never touch the real dataset
            copy = Path(tmp) / "dataset"
            shutil.copytree(ROOT / "dataset", copy)
            self.assertTrue(sf.verify_manifest(copy))
            target = next((copy / "sard_samples" / "good").rglob("*.py"))
            target.write_bytes(target.read_bytes() + b"\n# tampered\n")
            self.assertFalse(sf.verify_manifest(copy))

    def test_no_train_test_leakage(self):
        """No sample (by content hash) appears in both main and holdout, and no duplicates."""
        lines = (ROOT / "dataset" / "manifest.sha256").read_text().splitlines()
        by_split = {"sard_samples": set(), "holdout_samples": set()}
        seen = {}
        for line in lines:
            digest, rel = line.split("  ", 1)
            top = rel.split("/")[0]
            if top in by_split:
                by_split[top].add(digest)
                self.assertNotIn(digest, seen, f"duplicate sample {rel} == {seen.get(digest)}")
                seen[digest] = rel
        self.assertFalse(by_split["sard_samples"] & by_split["holdout_samples"])

    def test_labels_are_balanced(self):
        import csv
        with (ROOT / "dataset" / "labels.csv").open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        for split in ("main", "holdout"):
            labels = [r["label"] for r in rows if r["split"] == split]
            self.assertEqual(labels.count("bad"), labels.count("good"))


if __name__ == "__main__":
    unittest.main()
