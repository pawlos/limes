#!/usr/bin/env bash
# Builds fixtures/sqli-synthetic-prefix/source/SqliDemo.csproj into
# artifacts/sqli-synthetic-prefix/. Mirrors scripts/build-synthetic-stackalloc.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/sqli-synthetic-prefix/source"
OUT_DIR="$REPO_ROOT/artifacts/sqli-synthetic-prefix"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/SqliDemo.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "sqli-synthetic-prefix built at $OUT_DIR/SqliDemo.dll"
