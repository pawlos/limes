#!/usr/bin/env bash
# Builds fixtures/synthetic-callee-arithmetic/source/Decoder.csproj into
# artifacts/synthetic-callee-arithmetic/. Mirrors the materialize-imagesharp scripts
# but uses an in-tree source tree instead of a `git archive | tar -x` extraction.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/synthetic-callee-arithmetic/source"
OUT_DIR="$REPO_ROOT/artifacts/synthetic-callee-arithmetic"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/Decoder.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet \
    /p:GenerateDocumentationFile=false

echo "synthetic-callee-arithmetic built at $OUT_DIR/Decoder.dll"
