#!/usr/bin/env bash
# Builds fixtures/sqli-interpolated-prefix/source/InterpolatedSqliDemo.csproj into
# artifacts/sqli-interpolated-prefix/. Mirrors scripts/build-sqli-synthetic.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/sqli-interpolated-prefix/source"
OUT_DIR="$REPO_ROOT/artifacts/sqli-interpolated-prefix"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/InterpolatedSqliDemo.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "sqli-interpolated-prefix built at $OUT_DIR/InterpolatedSqliDemo.dll"
