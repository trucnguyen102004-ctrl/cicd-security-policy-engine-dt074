#!/usr/bin/env bash
# Midterm demo (runs inside the gate container):
#   Demo 1 - a commit adds a NIST SARD bad() sample  -> gate BLOCKS + feedback .md
#   Demo 2 - the developer applies the suggested fix -> gate PASSES quickly
# Output lands in /src/results/demo (or $DEMO_OUT).
set -uo pipefail
SRC="${SRC:-/src}"
OUT="${DEMO_OUT:-$SRC/results/demo}"
REG="${GATE_REGISTRY:-/opt/gate/rules/registry}"
W=/tmp/dt074-demo
rm -rf "$W" "$OUT"; mkdir -p "$W" "$OUT"
cp -r "$SRC/app" "$W/"; cd "$W"
git init -q -b main && git add -A && git commit -qm "base: demo user service"

gate() { python "$SRC/gate/cli.py" --mode adaptive --repo "$W" --base HEAD~1 --out "$1" --registry "$REG"; }
banner() { printf '\n\033[1;36m==================== %s ====================\033[0m\n' "$*"; }

banner "DEMO 1: commit a vulnerable change (SARD CWE-89 + CWE-798)"
cp "$SRC/dataset/sard_samples/bad/java/CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01_bad.java" \
   app/java/src/main/java/edu/demo/
cp "$SRC/dataset/sard_samples/bad/python/CWE798_Hard_Coded_Credentials__jwt_secret_01_bad.py" app/python/token_service.py
git add -A && git commit -qm "feat: user search + token service"
git show --stat --oneline HEAD | head -5
gate "$OUT/demo1"; echo "exit code: $?  (1 = build blocked)"
banner "SECURITY_GATE_FEEDBACK.md (what the developer sees)"
sed -n '1,60p' "$OUT/demo1/SECURITY_GATE_FEEDBACK.md"

banner "DEMO 2: apply the suggested fixes (PreparedStatement + os.environ)"
rm app/java/src/main/java/edu/demo/CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01_bad.java
cp "$SRC/dataset/sard_samples/good/java/CWE89_SQL_Injection__getParameter_Servlet_executeQuery_01_good.java" \
   app/java/src/main/java/edu/demo/
cp "$SRC/dataset/sard_samples/good/python/CWE798_Hard_Coded_Credentials__jwt_secret_01_good.py" app/python/token_service.py
git add -A && git commit -qm "fix: parameterised query, secret from environment"
gate "$OUT/demo2"; echo "exit code: $?  (0 = build passes)"
sed -n '1,4p' "$OUT/demo2/SECURITY_GATE_FEEDBACK.md"
echo "NOTE: the secret from Demo 1 is still in git history; the gate flagged it on that"
echo "commit, and the remediation text tells the developer to rotate it."

banner "Same Demo-2 commit through the BASELINE gate (full scan, zero tolerance)"
python "$SRC/gate/cli.py" --mode baseline --repo "$W" --out "$OUT/demo2-baseline" --registry "$REG" | tail -6
echo "exit code: ${PIPESTATUS[0]}"
