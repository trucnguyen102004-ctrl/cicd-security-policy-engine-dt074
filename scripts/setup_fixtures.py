#!/usr/bin/env python3
"""Build the representative NIST SARD subset used to evaluate the gates.

Reproducible from scratch on any machine:
  1. Download Juliet Java 1.3 (SARD test suite #111) once, verify its SHA-256.
  2. Extract a fixed, documented list of flow-variant-01 test cases.
  3. Split each Juliet file into two labelled units:
       bad/  -> class containing only bad()            (ground truth: vulnerable)
       good/ -> class containing good(), goodG2B(), goodB2G()  (ground truth: safe)
     Method bodies are copied verbatim; only the class name is suffixed.
  4. Emit SARD-derived Python cases (Juliet has no Python suite) that mirror
     the Juliet bad()/goodG2B()/goodB2G() template for the same CWEs.
  5. Emit dependency (SCA) cases.
  6. Write labels.csv and manifest.sha256 (SHA-256 of every sample).

Usage:  python scripts/setup_fixtures.py [--zip PATH] [--verify-only]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import re
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
SARD = DATASET / "sard_samples"
SCA = DATASET / "sca_cases"
CACHE = ROOT / ".cache"

JULIET_URL = ("https://samate.nist.gov/SARD/downloads/test-suites/"
              "2017-10-01-juliet-test-suite-for-java-v1-3.zip")
JULIET_SHA256 = "d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60"
JULIET_PREFIX = "Java/src/testcases/"

# Selection rule (fixed a priori, not tuned on scanner output):
#   flow variant 01 only; per CWE family, web-request sources
#   (getParameter / getCookies / getQueryString) plus one non-web source
#   (Environment) where Juliet provides it.
# (case_id, CWE family reported in the paper tables, path under testcases/)
JAVA_CASES = [
    ("J01", "CWE-89", "CWE89_SQL_Injection/s02/CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01.java"),
    ("J02", "CWE-89", "CWE89_SQL_Injection/s02/CWE89_SQL_Injection__getCookies_Servlet_executeUpdate_01.java"),
    ("J03", "CWE-89", "CWE89_SQL_Injection/s02/CWE89_SQL_Injection__Environment_execute_01.java"),
    ("J04", "CWE-79", "CWE80_XSS/s01/CWE80_XSS__Servlet_getParameter_Servlet_01.java"),
    ("J05", "CWE-79", "CWE80_XSS/s01/CWE80_XSS__Servlet_getCookies_Servlet_01.java"),
    ("J06", "CWE-22", "CWE23_Relative_Path_Traversal/CWE23_Relative_Path_Traversal__getParameter_Servlet_01.java"),
    ("J07", "CWE-22", "CWE23_Relative_Path_Traversal/CWE23_Relative_Path_Traversal__Environment_01.java"),
    ("J08", "CWE-22", "CWE36_Absolute_Path_Traversal/CWE36_Absolute_Path_Traversal__getQueryString_Servlet_01.java"),
    ("J09", "CWE-798", "CWE259_Hard_Coded_Password/CWE259_Hard_Coded_Password__driverManager_01.java"),
    ("J10", "CWE-798", "CWE259_Hard_Coded_Password/CWE259_Hard_Coded_Password__passwordAuth_01.java"),
    ("J11", "CWE-798", "CWE321_Hard_Coded_Cryptographic_Key/CWE321_Hard_Coded_Cryptographic_Key__basic_01.java"),
]

# Held-out set: fixed before any rule/policy was written and never inspected
# while designing the triage. Different flow variants (02/03), sources and
# sinks, so it measures generalisation instead of fit to the main subset.
HOLDOUT_CASES = [
    ("H01", "CWE-89", "CWE89_SQL_Injection/s03/CWE89_SQL_Injection__getQueryString_Servlet_executeBatch_02.java"),
    ("H02", "CWE-89", "CWE89_SQL_Injection/s03/CWE89_SQL_Injection__PropertiesFile_executeQuery_02.java"),
    ("H03", "CWE-89", "CWE89_SQL_Injection/s03/CWE89_SQL_Injection__getParameter_Servlet_prepareStatement_02.java"),
    ("H04", "CWE-89", "CWE89_SQL_Injection/s03/CWE89_SQL_Injection__getParameter_Servlet_executeUpdate_03.java"),
    ("H05", "CWE-79", "CWE80_XSS/s01/CWE80_XSS__Servlet_getQueryString_Servlet_02.java"),
    ("H06", "CWE-79", "CWE80_XSS/s02/CWE80_XSS__Servlet_URLConnection_02.java"),
    ("H07", "CWE-79", "CWE80_XSS/s01/CWE80_XSS__Servlet_getParameter_Servlet_03.java"),
    ("H08", "CWE-22", "CWE23_Relative_Path_Traversal/CWE23_Relative_Path_Traversal__getCookies_Servlet_02.java"),
    ("H09", "CWE-22", "CWE23_Relative_Path_Traversal/CWE23_Relative_Path_Traversal__Property_02.java"),
    ("H10", "CWE-22", "CWE36_Absolute_Path_Traversal/CWE36_Absolute_Path_Traversal__getParameter_Servlet_02.java"),
    ("H11", "CWE-798", "CWE259_Hard_Coded_Password/CWE259_Hard_Coded_Password__kerberosKey_01.java"),
]
HOLDOUT = DATASET / "holdout_samples"


# --------------------------------------------------------------------------- #
# Java method splitter
# --------------------------------------------------------------------------- #
METHOD_RE = re.compile(
    r"(?P<indent>[ \t]*)(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+"
    r"(?P<name>\w+)\s*\([^)]*\)\s*(?:throws[\w\s,.]+)?\{", re.M)


def _skip_literal(src: str, i: int) -> int:
    """Return index after the string/char literal or comment starting at i."""
    if src.startswith("//", i):
        j = src.find("\n", i)
        return len(src) if j < 0 else j
    if src.startswith("/*", i):
        return src.index("*/", i + 2) + 2
    quote = src[i]
    j = i + 1
    while src[j] != quote:
        j += 2 if src[j] == "\\" else 1
    return j + 1


def _match_brace(src: str, open_idx: int) -> int:
    """Index just past the '}' matching the '{' at open_idx (literal-aware)."""
    depth, i = 0, open_idx
    while i < len(src):
        c = src[i]
        if c in "\"'" or src.startswith("//", i) or src.startswith("/*", i):
            i = _skip_literal(src, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced braces")


def _leading_comment_start(src: str, start: int) -> int:
    """Extend a method span backwards over its directly preceding /* */ comment."""
    head = src[:start].rstrip()
    if head.endswith("*/"):
        c = head.rfind("/*")
        line_start = src.rfind("\n", 0, c) + 1
        if src[line_start:c].strip() == "":
            return line_start
    return start


def split_juliet(src: str, cls: str) -> tuple[str, str]:
    """Split a Juliet test case into (bad_source, good_source)."""
    class_m = re.search(r"public class (\w+)([^{]*)\{", src)
    header = src[:class_m.start()]
    class_open = class_m.end() - 1
    class_close = _match_brace(src, class_open) - 1

    methods = []
    for m in METHOD_RE.finditer(src, class_open, class_close):
        if methods and m.start() < methods[-1][2]:
            continue  # nested match inside a previous method body
        body_open = m.end() - 1
        end = _match_brace(src, body_open)
        methods.append((m.group("name"), _leading_comment_start(src, m.start()), end))

    def render(suffix: str, keep) -> str:
        parts = [src[s:e] for name, s, e in methods if keep(name)]
        decl = f"public class {cls}_{suffix}{class_m.group(2)}"
        return header + decl + "{\n" + "\n\n".join(parts) + "\n}\n"

    bad = render("bad", lambda n: n == "bad" or n.startswith("bad"))
    good = render("good", lambda n: n == "good" or n.startswith("good"))
    return bad, good


# --------------------------------------------------------------------------- #
# SARD-derived Python cases (same template: bad / goodG2B / goodB2G)
# --------------------------------------------------------------------------- #
PY_HEADER = '''"""SARD-derived test case (Juliet template ported to Python).
CWE: {cwe}
Label: {label}
Template: sources-sinks-01 (bad / goodG2B / goodB2G), flow variant 01
"""
'''

PY_CASES = {
    "P01": ("CWE-89", "CWE89_SQL_Injection__flask_args_execute_01", {
        "bad": '''import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/bad")
def bad():
    # POTENTIAL FLAW: read data from the query string
    data = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # POTENTIAL FLAW: data concatenated into SQL statement
    cur.execute("select * from users where name='" + data + "'")
    return str(cur.fetchall())
''',
        "good": '''import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/goodG2B")
def good_g2b():
    # FIX: use a hardcoded string
    data = "foo"
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("select * from users where name='" + data + "'")
    return str(cur.fetchall())


@app.route("/goodB2G")
def good_b2g():
    data = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # FIX: parameterised query
    cur.execute("select * from users where name=?", (data,))
    return str(cur.fetchall())
'''}),
    "P02": ("CWE-79", "CWE79_XSS__flask_args_response_01", {
        "bad": '''from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/bad")
def bad():
    # POTENTIAL FLAW: read data from the query string
    data = request.args.get("name")
    # POTENTIAL FLAW: display of data in web page without any encoding
    return make_response("<br>bad(): data = " + data)
''',
        "good": '''from flask import Flask, request, make_response
from markupsafe import escape

app = Flask(__name__)


@app.route("/goodG2B")
def good_g2b():
    # FIX: use a hardcoded string
    data = "foo"
    return make_response("<br>goodG2B(): data = " + data)


@app.route("/goodB2G")
def good_b2g():
    data = request.args.get("name")
    # FIX: HTML-encode before output
    return make_response("<br>goodB2G(): data = " + escape(data))
'''}),
    "P03": ("CWE-22", "CWE22_Path_Traversal__flask_args_open_01", {
        "bad": '''import os
from flask import Flask, request

app = Flask(__name__)
ROOT = "/srv/uploads"


@app.route("/bad")
def bad():
    # POTENTIAL FLAW: read data from the query string
    data = request.args.get("file")
    # POTENTIAL FLAW: no validation of concatenated path
    with open(os.path.join(ROOT, data)) as fh:
        return fh.readline()
''',
        "good": '''import os
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
ROOT = "/srv/uploads"


@app.route("/goodG2B")
def good_g2b():
    # FIX: use a hardcoded string
    data = "foo.txt"
    with open(os.path.join(ROOT, data)) as fh:
        return fh.readline()


@app.route("/goodB2G")
def good_b2g():
    data = request.args.get("file")
    # FIX: strip directory components before joining
    with open(os.path.join(ROOT, secure_filename(data))) as fh:
        return fh.readline()
'''}),
    "P04": ("CWE-798", "CWE798_Hard_Coded_Credentials__jwt_secret_01", {
        # Deliberately fake, provider-neutral secret: it trips generic
        # high-entropy detectors but no vendor push-protection pattern.
        "bad": '''import datetime
import jwt

# FLAW: signing secret hard-coded in source
api_secret_key = "Zq8vN3kLx7Tb2RmW9pYc4HsJ6dFa1GeU"


def bad(user_id: str) -> str:
    payload = {"sub": user_id,
               "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
    return jwt.encode(payload, api_secret_key, algorithm="HS256")
''',
        "good": '''import datetime
import os
import jwt


def good(user_id: str) -> str:
    # FIX: read the signing secret from the environment / secret manager
    api_secret_key = os.environ["JWT_SIGNING_KEY"]
    payload = {"sub": user_id,
               "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
    return jwt.encode(payload, api_secret_key, algorithm="HS256")
'''}),
}

# Dependency (SCA) cases: a PR that adds a dependency plus code that imports it.
SCA_CASES = {
    "S01": ("bad", "CWE-1395", "pyyaml_5.3.1_fullloader", {
        "requirements.txt": "PyYAML==5.3.1\n",
        "config_loader.py": "import yaml\n\n\ndef load(text):\n"
                            "    return yaml.load(text, Loader=yaml.FullLoader)\n",
    }),
    "S02": ("bad", "CWE-1395", "log4j_core_2.14.1", {
        "pom.xml": None,  # rendered below
        "AuditLog.java": "import org.apache.logging.log4j.LogManager;\n"
                         "import org.apache.logging.log4j.Logger;\n\n"
                         "public class AuditLog {\n"
                         "    private static final Logger LOG = LogManager.getLogger(AuditLog.class);\n"
                         "    public void record(String event) { LOG.info(\"event={}\", event); }\n}\n",
    }),
    "S03": ("good", "CWE-1395", "pyyaml_6.0.3_safe_load", {
        "requirements.txt": "PyYAML==6.0.3\n",
        "config_loader.py": "import yaml\n\n\ndef load(text):\n"
                            "    return yaml.safe_load(text)\n",
    }),
    "S04": ("good", "CWE-1395", "log4j_core_2.25.3", {
        "pom.xml": None,
        "AuditLog.java": "import org.apache.logging.log4j.LogManager;\n"
                         "import org.apache.logging.log4j.Logger;\n\n"
                         "public class AuditLog {\n"
                         "    private static final Logger LOG = LogManager.getLogger(AuditLog.class);\n"
                         "    public void record(String event) { LOG.info(\"event={}\", event); }\n}\n",
    }),
}
POM_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>edu.demo</groupId>
  <artifactId>audit-service</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>{version}</version>
    </dependency>
  </dependencies>
</project>
"""


# --------------------------------------------------------------------------- #
def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_juliet(zip_path: Path) -> Path:
    if not zip_path.exists():
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        print(f"[fixtures] downloading Juliet Java 1.3 (~73 MB) -> {zip_path}")
        with urllib.request.urlopen(JULIET_URL) as r, zip_path.open("wb") as fh:
            shutil.copyfileobj(r, fh)
    digest = sha256(zip_path)
    if digest != JULIET_SHA256:
        sys.exit(f"[fixtures] SHA-256 mismatch for {zip_path}: {digest}")
    print(f"[fixtures] Juliet archive verified sha256={digest[:16]}...")
    return zip_path


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def build(zip_path: Path) -> list[dict]:
    for d in (SARD, SCA, HOLDOUT):
        if d.exists():
            shutil.rmtree(d)
    rows = []
    with zipfile.ZipFile(zip_path) as zf:
        for split, base, cases in (("main", SARD, JAVA_CASES), ("holdout", HOLDOUT, HOLDOUT_CASES)):
            for cid, cwe, rel in cases:
                # Juliet ships CRLF; normalise so hashes match on every OS / git checkout
                src = zf.read(JULIET_PREFIX + rel).decode("utf-8").replace("\r\n", "\n")
                cls = Path(rel).stem
                bad, good = split_juliet(src, cls)
                for label, text in (("bad", bad), ("good", good)):
                    out = base / label / "java" / f"{cls}_{label}.java"
                    write(out, text)
                    rows.append(dict(case_id=f"{cid}-{label}", pair=cid, label=label, cwe=cwe,
                                     lang="java", kind="sast", split=split,
                                     origin=f"SARD#111:{rel}",
                                     path=out.relative_to(DATASET).as_posix()))
    for cid, (cwe, stem, variants) in PY_CASES.items():
        for label, body in variants.items():
            out = SARD / label / "python" / f"{stem}_{label}.py"
            write(out, PY_HEADER.format(cwe=cwe, label=label) + body)
            rows.append(dict(case_id=f"{cid}-{label}", pair=cid, label=label, cwe=cwe,
                             lang="python", kind="sast", split="main",
                             origin="SARD-derived (Juliet template)",
                             path=out.relative_to(DATASET).as_posix()))
    for cid, (label, cwe, name, files) in SCA_CASES.items():
        case_dir = SCA / label / f"{cid}_{name}"
        for fname, text in files.items():
            if fname == "pom.xml":
                text = POM_TEMPLATE.format(version=name.rsplit("_", 1)[1])
            write(case_dir / fname, text)
        rows.append(dict(case_id=f"{cid}-{label}", pair=cid, label=label, cwe=cwe,
                         lang="python" if "requirements.txt" in files else "java",
                         kind="sca", split="main", origin="synthetic dependency PR",
                         path=case_dir.relative_to(DATASET).as_posix()))
    return rows


def write_manifest() -> Path:
    manifest = DATASET / "manifest.sha256"
    files = sorted(p for p in DATASET.rglob("*")
                   if p.is_file() and p.name not in ("manifest.sha256",))
    lines = [f"{sha256(p)}  {p.relative_to(DATASET).as_posix()}" for p in files]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return manifest


def verify_manifest() -> bool:
    ok = True
    for line in (DATASET / "manifest.sha256").read_text().splitlines():
        digest, rel = line.split("  ", 1)
        p = DATASET / rel
        if not p.exists() or sha256(p) != digest:
            print(f"[fixtures] MISMATCH {rel}")
            ok = False
    print("[fixtures] manifest OK" if ok else "[fixtures] manifest FAILED")
    return ok


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--zip", type=Path, default=CACHE / "juliet_java_v1.3.zip")
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()
    if args.verify_only:
        sys.exit(0 if verify_manifest() else 1)

    rows = build(fetch_juliet(args.zip))
    with (DATASET / "labels.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    manifest = write_manifest()
    n_bad = sum(r["label"] == "bad" for r in rows)
    print(f"[fixtures] {len(rows)} cases ({n_bad} bad / {len(rows) - n_bad} good) -> {DATASET}")
    print(f"[fixtures] manifest: {manifest} sha256={sha256(manifest)[:16]}...")


if __name__ == "__main__":
    main()
