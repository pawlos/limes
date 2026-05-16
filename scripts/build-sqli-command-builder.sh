#!/usr/bin/env bash
# Builds fixtures/sqli-command-builder-prefix/source/CommandBuilderSqliDemo.csproj into
# artifacts/sqli-command-builder-prefix/. Mirrors scripts/build-sqli-interpolated.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/sqli-command-builder-prefix/source"
OUT_DIR="$REPO_ROOT/artifacts/sqli-command-builder-prefix"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/CommandBuilderSqliDemo.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "sqli-command-builder-prefix built at $OUT_DIR/CommandBuilderSqliDemo.dll"
