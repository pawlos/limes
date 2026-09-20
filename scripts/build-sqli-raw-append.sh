#!/usr/bin/env bash
# Builds fixtures/sqli-raw-append-prefix/source/RawAppendSqliDemo.csproj into
# artifacts/sqli-raw-append-prefix/. Mirrors scripts/build-sqli-command-builder.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/sqli-raw-append-prefix/source"
OUT_DIR="$REPO_ROOT/artifacts/sqli-raw-append-prefix"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/RawAppendSqliDemo.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "sqli-raw-append-prefix built at $OUT_DIR/RawAppendSqliDemo.dll"
