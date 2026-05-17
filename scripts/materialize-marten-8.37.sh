#!/usr/bin/env bash
# Materializes Marten 8.37.0 from NuGet into artifacts/marten-8.37/.
# Mirrors the structure of scripts/materialize-marten-8.36.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARTEN_VERSION=8.37.0
OUT_DIR="$REPO_ROOT/artifacts/marten-8.37"
TFM="net9.0"

mkdir -p "$OUT_DIR"

SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT

cat > "$SCRATCH/scratch.csproj" << EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>$TFM</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Marten" Version="$MARTEN_VERSION" />
  </ItemGroup>
</Project>
EOF

dotnet restore "$SCRATCH/scratch.csproj" --nologo /v:quiet

PKG_DIR="$HOME/.nuget/packages/marten/$MARTEN_VERSION/lib/$TFM"
if [ ! -f "$PKG_DIR/Marten.dll" ]; then
    # Fall back to net8.0 if net9.0 isn't shipped in this version.
    TFM_FALLBACK="net8.0"
    PKG_DIR="$HOME/.nuget/packages/marten/$MARTEN_VERSION/lib/$TFM_FALLBACK"
    if [ ! -f "$PKG_DIR/Marten.dll" ]; then
        echo "error: Marten.dll not found in $HOME/.nuget/packages/marten/$MARTEN_VERSION/lib/{$TFM,$TFM_FALLBACK}/" >&2
        exit 1
    fi
    TFM="$TFM_FALLBACK"
fi

cp "$PKG_DIR/Marten.dll" "$OUT_DIR/Marten.dll"

if [ -f "$PKG_DIR/Marten.pdb" ]; then
    cp "$PKG_DIR/Marten.pdb" "$OUT_DIR/Marten.pdb"
    rm -f "$OUT_DIR/.nopdb-marker"
else
    touch "$OUT_DIR/.nopdb-marker"
fi

echo "marten-8.37 materialized at $OUT_DIR (TFM=$TFM)"
sha256sum "$OUT_DIR/Marten.dll"
