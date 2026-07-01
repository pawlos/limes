#!/usr/bin/env bash
# Builds the Microsoft.OpenApi BaseOpenApiReferenceHolder prefix (vulnerable,
# GHSA-v5pm-xwqc-g5wc / CVE-2026-49451, CWE-674) and postfix (patched, 2.7.5/3.5.4)
# fixtures into artifacts/. Mirrors scripts/build-naudio-loopstream.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

build() {
  local variant="$1"
  local src="$REPO_ROOT/fixtures/microsoft-openapi-v5pm-$variant/source"
  local out="$REPO_ROOT/artifacts/microsoft-openapi-v5pm-$variant"
  mkdir -p "$out"
  dotnet build "$src/OpenApi.csproj" -c Debug -o "$out" --nologo /v:quiet
  echo "microsoft-openapi-v5pm-$variant built at $out/Microsoft.OpenApi.dll"
}

build prefix
build postfix
