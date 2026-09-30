#!/usr/bin/env bash
# Download a frozen snapshot of the Semgrep Registry rulesets used by both gates.
# The snapshot is NOT committed (Semgrep Rules License forbids redistribution);
# instead its SHA-256 is recorded so every experiment log states which rules ran.
set -euo pipefail
OUT="${1:-rules/registry}"
mkdir -p "$OUT"
for pack in java python secrets; do
  curl -fsSL --retry 3 -o "$OUT/p-$pack.yml" "https://semgrep.dev/c/p/$pack"
done
( cd "$OUT" && sha256sum p-*.yml > SNAPSHOT.sha256 && date -u +%FT%TZ > SNAPSHOT_DATE )
cat "$OUT/SNAPSHOT.sha256"
