#!/usr/bin/env python3
"""External-validity subset from NIST SARD test suite #112 (Juliet C/C++ 1.3).

Purpose: check whether the gate's *policy engine* generalises to a language for
which NO custom rule was written and NOTHING was tuned (registry rules only).
The Java/Python evaluation (#111) remains the primary experiment.

Selection rule (fixed a priori): flow variant 01, `char` variants, the three CWE
families of the project that exist in the C/C++ suite:
  injection   CWE-78 OS Command Injection (closest C analogue of CWE-89)
  path        CWE-23 / CWE-36 Path Traversal  -> reported as CWE-22
  credentials CWE-259 / CWE-321                -> reported as CWE-798
(Juliet C/C++ has no XSS / SQL injection test cases.)

Juliet C marks the two halves with `#ifndef OMITBAD` / `#ifndef OMITGOOD`; each
file is split into a bad-only and a good-only translation unit (main() dropped).

Usage:  python scripts/setup_fixtures_cpp.py [--zip PATH] [--verify-only]
"""
from __future__ import annotations

import argparse
import csv
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from setup_fixtures import DATASET, CACHE, sha256, write  # noqa: E402

import urllib.request  # noqa: E402
import zipfile  # noqa: E402

URL = ("https://samate.nist.gov/SARD/downloads/test-suites/"
       "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip")
SHA256 = "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
PREFIX = "C/testcases/"
OUT = DATASET / "sard112_cpp"
LABELS = DATASET / "labels_cpp.csv"

CASES = [
    ("C01", "CWE-78", "CWE78_OS_Command_Injection/s02/CWE78_OS_Command_Injection__char_environment_system_01.c"),
    ("C02", "CWE-78", "CWE78_OS_Command_Injection/s02/CWE78_OS_Command_Injection__char_console_popen_01.c"),
    ("C03", "CWE-78", "CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_connect_socket_system_01.c"),
    ("C04", "CWE-78", "CWE78_OS_Command_Injection/s02/CWE78_OS_Command_Injection__char_environment_execl_01.c"),
    ("C05", "CWE-22", "CWE23_Relative_Path_Traversal/s01/CWE23_Relative_Path_Traversal__char_environment_fopen_01.cpp"),
    ("C06", "CWE-22", "CWE23_Relative_Path_Traversal/s01/CWE23_Relative_Path_Traversal__char_console_open_01.cpp"),
    ("C07", "CWE-22", "CWE23_Relative_Path_Traversal/s01/CWE23_Relative_Path_Traversal__char_connect_socket_fopen_01.cpp"),
    ("C08", "CWE-22", "CWE36_Absolute_Path_Traversal/s02/CWE36_Absolute_Path_Traversal__char_file_open_01.cpp"),
    ("C09", "CWE-798", "CWE259_Hard_Coded_Password/CWE259_Hard_Coded_Password__w32_char_01.c"),
    ("C10", "CWE-798", "CWE259_Hard_Coded_Password/CWE259_Hard_Coded_Password__w32_wchar_t_01.c"),
    ("C11", "CWE-798", "CWE321_Hard_Coded_Cryptographic_Key/CWE321_Hard_Coded_Cryptographic_Key__w32_char_01.c"),
    ("C12", "CWE-798", "CWE321_Hard_Coded_Cryptographic_Key/CWE321_Hard_Coded_Cryptographic_Key__w32_wchar_t_01.c"),
]


def split_c(src: str) -> tuple[str, str]:
    start = src.index("#ifndef OMITBAD")
    header = src[:start]
    bad = re.search(r"#ifndef OMITBAD\n(.*?)#endif /\* OMITBAD \*/", src, re.S).group(1)
    good = re.search(r"#ifndef OMITGOOD\n(.*?)#endif /\* OMITGOOD \*/", src, re.S).group(1)
    close = "\n} /* close namespace */\n" if re.search(r"^namespace \w+", header, re.M) else "\n"
    return header + bad + close, header + good + close


def fetch(zip_path: Path) -> Path:
    if not zip_path.exists():
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        print(f"[fixtures-cpp] downloading Juliet C/C++ 1.3 (~146 MB) -> {zip_path}")
        with urllib.request.urlopen(URL) as r, zip_path.open("wb") as fh:
            shutil.copyfileobj(r, fh)
    digest = sha256(zip_path)
    if digest != SHA256:
        sys.exit(f"[fixtures-cpp] SHA-256 mismatch: {digest}")
    print(f"[fixtures-cpp] Juliet C/C++ archive verified sha256={digest[:16]}...")
    return zip_path


def verify() -> bool:
    ok = True
    for line in (OUT / "manifest.sha256").read_text().splitlines():
        digest, rel = line.split("  ", 1)
        if sha256(OUT / rel) != digest:
            print(f"[fixtures-cpp] MISMATCH {rel}")
            ok = False
    print("[fixtures-cpp] manifest OK" if ok else "[fixtures-cpp] manifest FAILED")
    return ok


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--zip", type=Path, default=CACHE / "juliet_cpp_v1.3.zip")
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()
    if args.verify_only:
        sys.exit(0 if verify() else 1)
    if OUT.exists():
        shutil.rmtree(OUT)
    rows = []
    with zipfile.ZipFile(fetch(args.zip)) as zf:
        for cid, cwe, rel in CASES:
            src = zf.read(PREFIX + rel).decode("utf-8", errors="replace").replace("\r\n", "\n")
            bad, good = split_c(src)
            stem, ext = Path(rel).stem, Path(rel).suffix
            for label, text in (("bad", bad), ("good", good)):
                out = OUT / label / f"{stem}_{label}{ext}"
                write(out, text)
                rows.append(dict(case_id=f"{cid}-{label}", pair=cid, label=label, cwe=cwe,
                                 lang="c", kind="sast", split="cpp112", origin=f"SARD#112:{rel}",
                                 path=out.relative_to(DATASET).as_posix()))
    with LABELS.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    files = sorted(p for p in OUT.rglob("*") if p.is_file() and p.name != "manifest.sha256")
    (OUT / "manifest.sha256").write_text(
        "".join(f"{sha256(p)}  {p.relative_to(OUT).as_posix()}\n" for p in files), encoding="utf-8", newline="\n")
    print(f"[fixtures-cpp] {len(rows)} cases ({len(rows) // 2} bad / {len(rows) // 2} good) -> {OUT}")


if __name__ == "__main__":
    main()
