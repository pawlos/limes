#!/usr/bin/env bash
# Materialize OpenTelemetry.Resources.AWS for the milestone-J AWS FP-fixed fixture.
# The DLL is the analyzer target; the rules + trace ground-truth live in the fixture dir.
set -euo pipefail

REPO=/tmp/otel-contrib-opamp     # reuse the milestone-I clone if present
SHA=0f70479e655bf3602a713de9e6ee7085f6634b88   # contrib main as of 2026-05-06; update if AWS source shape changes
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACTS="${REPO_ROOT}/artifacts"

if [[ ! -d "$REPO/.git" ]]; then
    git clone https://github.com/open-telemetry/opentelemetry-dotnet-contrib.git "$REPO"
fi

dest="${ARTIFACTS}/${SHA}"
mkdir -p "$dest"
git -C "$REPO" -c advice.detachedHead=false fetch --depth 1 origin "$SHA" 2>/dev/null || true
git -C "$REPO" -c advice.detachedHead=false checkout "$SHA"
DOTNET_NOLOGO=1 dotnet build "$REPO/src/OpenTelemetry.Resources.AWS/OpenTelemetry.Resources.AWS.csproj" \
    -c Debug --framework net10.0 \
    -p:DebugType=portable -p:DebugSymbols=true -p:Optimize=false
cp "$REPO/artifacts/bin/OpenTelemetry.Resources.AWS/debug_net10.0/OpenTelemetry.Resources.AWS.dll" "$dest/"
cp "$REPO/artifacts/bin/OpenTelemetry.Resources.AWS/debug_net10.0/OpenTelemetry.Resources.AWS.pdb" "$dest/"

echo "[materialize] AWS DLL: ${dest}/OpenTelemetry.Resources.AWS.dll"
