#!/usr/bin/env bash
# Builds fixtures/sqli-quote-escape-postfix/source/QuoteEscapeSqliDemo.csproj into
# artifacts/sqli-quote-escape-postfix/. Mirrors scripts/build-sqli-raw-append.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$REPO_ROOT/fixtures/sqli-quote-escape-postfix/source"
OUT_DIR="$REPO_ROOT/artifacts/sqli-quote-escape-postfix"

mkdir -p "$OUT_DIR"
dotnet build "$SRC_DIR/QuoteEscapeSqliDemo.csproj" \
    -c Debug \
    -o "$OUT_DIR" \
    --nologo \
    /v:quiet

echo "sqli-quote-escape-postfix built at $OUT_DIR/QuoteEscapeSqliDemo.dll"
