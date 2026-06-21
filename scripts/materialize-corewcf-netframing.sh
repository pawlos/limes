#!/usr/bin/env bash
# Materialize CoreWCF.NetFramingBase 1.9.0 (vulnerable, GHSA-p86g-xrr2-pf7c) and
# 1.9.1 (patched) DLLs into artifacts/ for the loop-termination fixture e2e tests.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ART="$ROOT/artifacts"

fetch() {
  local ver="$1"
  local dir="$ART/corewcf-netframing-$ver"
  mkdir -p "$dir"
  local tmp; tmp="$(mktemp -d)"
  curl -sL -o "$tmp/p.nupkg" "https://www.nuget.org/api/v2/package/CoreWCF.NetFramingBase/$ver"
  unzip -o -q "$tmp/p.nupkg" -d "$tmp/x"
  cp "$tmp/x/lib/netstandard2.0/CoreWCF.NetFramingBase.dll" "$dir/"
  rm -rf "$tmp"
  echo "materialized $dir"
}

fetch 1.9.0
fetch 1.9.1
