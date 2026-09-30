"""Integration + negative tests with the real scanners (run inside the gate container).

Skipped automatically when semgrep / gitleaks / syft / trivy are not installed.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "gate" / "cli.py"
REGISTRY = os.environ.get("GATE_REGISTRY", str(ROOT / "rules" / "registry"))
HAVE_TOOLS = all(shutil.which(t) for t in ("semgrep", "gitleaks", "syft", "trivy"))
SARD = ROOT / "dataset" / "sard_samples"


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@unittest.skipUnless(HAVE_TOOLS, "scanners not installed (run inside the security-gate container)")
class GateIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        shutil.copytree(ROOT / "app", self.repo / "app")
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "base")

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, files: dict, msg="change"):
        for rel, content in files.items():
            p = self.repo / rel
            if content is None:
                p.unlink()
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, Path):
                shutil.copy2(content, p)
            else:
                p.write_text(content, encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", msg)

    def gate(self, mode="adaptive", base="HEAD~1", registry=REGISTRY, extra=()):
        out = Path(self.tmp.name) / f"out-{mode}"
        cmd = [sys.executable, str(CLI), "--mode", mode, "--repo", str(self.repo), "--out", str(out),
               "--registry", registry, *extra]
        if mode == "adaptive":
            cmd += ["--base", base]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        decision = json.loads((out / "decision.json").read_text())
        return proc.returncode, decision, out

    # ------------------------------------------------------------------ positive
    def test_sqli_commit_is_blocked_with_feedback(self):
        self.commit({"app/java/Q.java": SARD / "bad/java/CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01_bad.java"})
        code, d, out = self.gate()
        self.assertEqual(code, 1)
        self.assertEqual(d["decision"], "BLOCK")
        md = (out / "SECURITY_GATE_FEEDBACK.md").read_text(encoding="utf-8")
        self.assertIn("CWE-89", md)
        self.assertIn("app/java/Q.java:", md)

    def test_clean_commit_passes_and_scans_only_diff(self):
        self.commit({"app/java/Q.java": SARD / "good/java/CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01_good.java"})
        code, d, out = self.gate()
        self.assertEqual((code, d["decision"]), (0, "PASS"))
        meta = json.loads((out / "meta.json").read_text())
        self.assertEqual(meta["scope"]["scanned_files"], ["app/java/Q.java"])
        self.assertEqual(d["tools"]["trivy"]["status"], "skipped")      # no manifest touched

    def test_docs_only_change_skips_sast(self):
        self.commit({"docs/NOTES.md": "# notes\n"})
        code, d, _ = self.gate()
        self.assertEqual(code, 0)
        self.assertEqual(d["tools"]["semgrep"]["status"], "skipped")

    def test_vulnerable_dependency_is_blocked(self):
        self.commit({"app/python/requirements.txt": "Flask==3.1.2\nPyYAML==5.3.1\n",
                     "app/python/cfg.py": "import yaml\n\ndef load(t):\n    return yaml.load(t, Loader=yaml.FullLoader)\n"})
        code, d, _ = self.gate()
        self.assertEqual(code, 1)
        self.assertGreaterEqual(d["counts"]["blocking_by_tool"]["trivy"], 1)

    def test_preexisting_cve_does_not_block_unrelated_manifest_edit(self):
        # app/java/pom.xml already pins postgresql 42.7.8 (HIGH CVEs) at base; a
        # comment-only edit must not make the developer pay for old debt.
        pom = (self.repo / "app/java/pom.xml").read_text() + "<!-- touch -->\n"
        self.commit({"app/java/pom.xml": pom})
        code, d, _ = self.gate()
        self.assertEqual((code, d["decision"]), (0, "PASS"))

    # ------------------------------------------------------------------ negative
    def test_secret_removed_in_later_commit_still_blocks(self):
        """Deleting a secret in a follow-up commit does not erase it from history."""
        self.commit({"app/python/t.py": SARD / "bad/python/CWE798_Hard_Coded_Credentials__jwt_secret_01_bad.py"}, "add")
        self.commit({"app/python/t.py": SARD / "good/python/CWE798_Hard_Coded_Credentials__jwt_secret_01_good.py"}, "rm")
        code, d, _ = self.gate(base="HEAD~2")
        self.assertEqual(code, 1)
        self.assertGreaterEqual(d["counts"]["blocking_by_tool"]["gitleaks"], 1)

    def test_scanner_failure_fails_closed(self):
        self.commit({"app/java/Q.java": SARD / "good/java/CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01_good.java"})
        code, d, _ = self.gate(registry="/nonexistent/rules")
        self.assertEqual(code, 1)
        self.assertIn("semgrep", d["failed_tools"])

    def test_short_override_reason_is_rejected(self):
        self.commit({"app/java/Q.java": SARD / "bad/java/CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01_bad.java"})
        os.environ["GATE_OVERRIDE_REASON"] = "pls"
        try:
            code, d, _ = self.gate()
        finally:
            os.environ.pop("GATE_OVERRIDE_REASON")
        self.assertEqual((code, d["decision"]), (1, "BLOCK"))

    def test_baseline_blocks_clean_change_on_legacy_repo(self):
        """Zero tolerance + full scan: pre-existing advisories block an unrelated clean commit."""
        self.commit({"docs/NOTES.md": "# notes\n"})
        code, d, out = self.gate(mode="baseline")
        self.assertEqual(code, 1)
        self.assertTrue((out / "baseline_raw.log").exists())


if __name__ == "__main__":
    unittest.main()
