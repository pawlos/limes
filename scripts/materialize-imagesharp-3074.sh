#!/usr/bin/env bash
set -euo pipefail

SHARED_CLONE="${SHARED_CLONE:-/mnt/c/work/dotnet-fuzzing/external/ImageSharp}"
PRE_FIX_SHA="67bac23cff7c32743d0c8e166e9cccbf567837e0"
POST_FIX_SHA="461c021608802370374afabd5d3c2720b3e46f04"
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

  # `git archive` does NOT include submodule content (shared-infrastructure is a submodule).
  # Copy the checked-out submodule from the shared clone's working tree.
  # The shared clone must have the submodule initialised (git submodule update --init).
  local submodule_src="${SHARED_CLONE}/shared-infrastructure"
  if [[ -d "${submodule_src}/msbuild" ]]; then
    echo "[materialize] copying shared-infrastructure submodule..."
    cp -r "${submodule_src}/." "${dest}/shared-infrastructure/"
    # `git archive` also omits dotfiles (.editorconfig, .gitattributes).
    # SixLabors.Src.targets tries to copy them during build; supply them now to avoid the error.
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

# Allow `--pre-only` to short-circuit when we just want one commit (saves time on first runs).
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
