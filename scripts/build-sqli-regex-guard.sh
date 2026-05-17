#!/usr/bin/env bash
# Builds fixtures/sqli-regex-guard-prefix/source/RegexGuardSqliDemo.csproj into
# artifacts/sqli-regex-guard-prefix/. Mirrors scripts/build-sqli-command-builder.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/sqli-regex-guard-prefix/source"
OUT_DIR="$REPO_ROOT/artifacts/sqli-regex-guard-prefix"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/RegexGuardSqliDemo.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "sqli-regex-guard-prefix built at $OUT_DIR/RegexGuardSqliDemo.dll"
