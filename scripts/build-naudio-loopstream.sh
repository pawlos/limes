#!/usr/bin/env bash
# Builds the NAudio.Extras.LoopStream prefix (vulnerable, naudio/NAudio#1338, CWE-835)
# and postfix (patched, naudio/NAudio#1339) fixtures into artifacts/.
# Mirrors scripts/build-synthetic-stackalloc.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

build() {
  local variant="$1"
  local src="$REPO_ROOT/fixtures/naudio-loopstream-1338-$variant/source"
  local out="$REPO_ROOT/artifacts/naudio-loopstream-1338-$variant"
  mkdir -p "$out"
  dotnet build "$src/LoopStream.csproj" -c Debug -o "$out" --nologo /v:quiet
  echo "naudio-loopstream-1338-$variant built at $out/NAudio.Extras.dll"
}

build prefix
build postfix
