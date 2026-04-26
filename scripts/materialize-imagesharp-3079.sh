#!/usr/bin/env bash
# Materialize ImageSharp pre-fix and post-fix DLLs for the #3079 PNG iTXt-chunk
# sanitizer-absence vulnerability. Mirrors materialize-imagesharp-3074.sh.
set -euo pipefail

SHARED_CLONE="${SHARED_CLONE:-/mnt/c/work/dotnet-fuzzing/external/ImageSharp}"
PRE_FIX_SHA="533ed51d3acc313bfcdadf120de316fdada52a72"
POST_FIX_SHA="89face0b8930068f43db1064a0c00e2170993549"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACTS="${REPO_ROOT}/artifacts"

if [[ ! -d "${SHARED_CLONE}/.git" ]]; then
  echo "error: shared clone not found at ${SHARED_CLONE}" >&2
  exit 2
fi

materialize_one() {
  local sha="$1"
  local dest="${ARTIFACTS}/${sha}"
  if [[ -f "${dest}/src/ImageSharp/ImageSharp.csproj" ]]; then
    echo "[materialize] ${sha} already present at ${dest}"
    return 0
  fi
  echo "[materialize] extracting ${sha}..."
  mkdir -p "${dest}"
  git -C "${SHARED_CLONE}" archive "${sha}" | tar -x -C "${dest}"

  local submodule_src="${SHARED_CLONE}/shared-infrastructure"
  if [[ -d "${submodule_src}/msbuild" ]]; then
    echo "[materialize] copying shared-infrastructure submodule..."
    cp -r "${submodule_src}/." "${dest}/shared-infrastructure/"
    for dotfile in .editorconfig .gitattributes; do
      if [[ -f "${submodule_src}/${dotfile}" && ! -f "${dest}/shared-infrastructure/${dotfile}" ]]; then
        cp "${submodule_src}/${dotfile}" "${dest}/shared-infrastructure/${dotfile}"
      fi
    done
  else
    echo "warning: shared-infrastructure submodule not found at ${submodule_src}" >&2
    echo "         Run: git -C '${SHARED_CLONE}' submodule update --init" >&2
  fi
}

build_one() {
  local sha="$1"
  local dest="${ARTIFACTS}/${sha}"
  local dll_glob="${dest}/artifacts/bin/src/ImageSharp/Debug/net*/SixLabors.ImageSharp.dll"
  # shellcheck disable=SC2086
  if compgen -G ${dll_glob} > /dev/null 2>&1; then
    echo "[build] ${sha} already built — skipping"
    return 0
  fi
  echo "[build] dotnet build ${sha}..."
  dotnet build "${dest}/src/ImageSharp/ImageSharp.csproj" -c Debug --nologo --verbosity minimal
}

ONLY="${1:-both}"
if [[ "${ONLY}" == "--pre-only" ]]; then
  materialize_one "${PRE_FIX_SHA}"
  build_one "${PRE_FIX_SHA}"
  echo "[ok] pre-fix DLL: ${ARTIFACTS}/${PRE_FIX_SHA}/artifacts/bin/src/ImageSharp/Debug/net*/SixLabors.ImageSharp.dll"
else
  materialize_one "${PRE_FIX_SHA}"
  materialize_one "${POST_FIX_SHA}"
  build_one "${PRE_FIX_SHA}"
  build_one "${POST_FIX_SHA}"
  echo "[ok] pre-fix:  ${ARTIFACTS}/${PRE_FIX_SHA}/artifacts/bin/src/ImageSharp/Debug/net*/SixLabors.ImageSharp.dll"
  echo "[ok] post-fix: ${ARTIFACTS}/${POST_FIX_SHA}/artifacts/bin/src/ImageSharp/Debug/net*/SixLabors.ImageSharp.dll"
fi
