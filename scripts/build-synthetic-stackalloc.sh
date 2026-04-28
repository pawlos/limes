#!/usr/bin/env bash
# Builds fixtures/synthetic-stackalloc/source/Decoder.csproj into
# artifacts/synthetic-stackalloc/. Mirrors scripts/build-synthetic-callee-arithmetic.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/synthetic-stackalloc/source"
OUT_DIR="$REPO_ROOT/artifacts/synthetic-stackalloc"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/Decoder.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "synthetic-stackalloc built at $OUT_DIR/Decoder.dll"
