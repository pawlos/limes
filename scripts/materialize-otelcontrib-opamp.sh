#!/usr/bin/env bash
# Materialize OpenTelemetry.OpAmp.Client at pre-fix and post-fix commits for the
# GHSA-w2jh-77fq-7gp8 / CVE-2026-42348 fixture pair.
set -euo pipefail

REPO=/tmp/otel-contrib-opamp
PREFIX_SHA=d6e87d8af403554107671e98e1913a3b2dfe141a
POSTFIX_SHA=bf1fad4fa298ff451cda0efb0ee9c7a7eb46212a
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACTS="${REPO_ROOT}/artifacts"

if [[ ! -d "$REPO/.git" ]]; then
    git clone https://github.com/open-telemetry/opentelemetry-dotnet-contrib.git "$REPO"
fi

build_at() {
    local sha=$1
    local dest="${ARTIFACTS}/${sha}"
    mkdir -p "$dest"
    git -C "$REPO" -c advice.detachedHead=false fetch --depth 1 origin "$sha" 2>/dev/null || true
    git -C "$REPO" -c advice.detachedHead=false checkout "$sha"
    DOTNET_NOLOGO=1 dotnet build "$REPO/src/OpenTelemetry.OpAmp.Client/OpenTelemetry.OpAmp.Client.csproj" \
        -c Debug --framework net10.0 \
        -p:DebugType=portable -p:DebugSymbols=true -p:Optimize=false
    cp "$REPO/artifacts/bin/OpenTelemetry.OpAmp.Client/debug_net10.0/OpenTelemetry.OpAmp.Client.dll" "$dest/"
    cp "$REPO/artifacts/bin/OpenTelemetry.OpAmp.Client/debug_net10.0/OpenTelemetry.OpAmp.Client.pdb" "$dest/"
}

build_at "$PREFIX_SHA"
build_at "$POSTFIX_SHA"

echo "[materialize] prefix DLL:  ${ARTIFACTS}/${PREFIX_SHA}/OpenTelemetry.OpAmp.Client.dll"
echo "[materialize] postfix DLL: ${ARTIFACTS}/${POSTFIX_SHA}/OpenTelemetry.OpAmp.Client.dll"
