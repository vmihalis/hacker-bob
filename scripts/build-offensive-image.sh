#!/usr/bin/env bash
#
# build-offensive-image.sh — build + push + DIGEST-PIN the Hacker Bob offensive arsenal image.
#
# WHY THIS EXISTS: offensive-sandbox.js runs the offensive container with `--pull=never` +
# `name@sha256:<digest>` (IMAGE_DIGEST_RE). A purely-local `docker build` has NO RepoDigest, so it
# cannot be run by digest. The only sound way to mint a resolvable digest is: build -> push to a
# registry -> pull-by-digest. This script does exactly that against ghcr.io and writes the resulting
# digest to mcp/lib/offensive-image.json (the SOLE source of runOffensiveTool's imageDigest).
#
# PROVENANCE: the arsenal binaries are fetched on THIS host (where ghcr/github egress is verified
# clean) and sha256-verified against each tool's official GitHub release checksums file, then COPIED
# into a hermetic image (no in-build network, no builder toolchain).
#
# ONE-TIME OPERATOR PREREQS (the script refuses to push without them):
#   1. Docker Desktop running.
#   2. docker login ghcr.io   (Personal Access Token with the write:packages scope)
#
# Usage:
#   scripts/build-offensive-image.sh                # full: fetch+verify+stage -> build -> push -> pin
#   scripts/build-offensive-image.sh --stage-only   # fetch+verify+stage binaries only (no docker)
#
# Override knobs (env): HTTPX_VERSION, DALFOX_VERSION, OFFENSIVE_REGISTRY, OFFENSIVE_ARCH, BASE_IMAGE
set -euo pipefail

# --- pinned arsenal versions — VERIFY against the current GitHub releases before a real run ---
# A wrong version fails loudly at download (404); a tampered asset fails at the checksum gate.
HTTPX_VERSION="${HTTPX_VERSION:-1.6.10}"
DALFOX_VERSION="${DALFOX_VERSION:-2.9.6}"

REGISTRY="${OFFENSIVE_REGISTRY:-ghcr.io/bobnetsec/bob-offense}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTEXT_DIR="${REPO_ROOT}/docker/offensive-context"
BIN_DIR="${CONTEXT_DIR}/bin"
DOCKERFILE="${REPO_ROOT}/docker/offensive.Dockerfile"
LOCKFILE="${REPO_ROOT}/mcp/lib/offensive-image-lock.js"

STAGE_ONLY=0
[ "${1:-}" = "--stage-only" ] && STAGE_ONLY=1

# target platform: linux + host arch (override with OFFENSIVE_ARCH=amd64|arm64)
host_arch="$(uname -m)"
case "${OFFENSIVE_ARCH:-${host_arch}}" in
  arm64|aarch64) ARCH=arm64 ;;
  x86_64|amd64)  ARCH=amd64 ;;
  *) echo "unsupported arch: ${OFFENSIVE_ARCH:-${host_arch}}" >&2; exit 2 ;;
esac
PLATFORM="linux/${ARCH}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 2; }; }
need curl; need shasum; need unzip; need tar; need awk

sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

# fetch a release asset + verify it against the release's official checksums file.
# args: tool, version, asset_filename, checksums_filename, github_owner/repo ; echoes the asset path
fetch_verify() {
  local tool="$1" ver="$2" asset="$3" checks="$4" slug="$5"
  local tmp base want got
  tmp="$(mktemp -d)"
  base="https://github.com/${slug}/releases/download/v${ver}"
  echo ">> ${tool} v${ver} (${ARCH}): downloading ${asset}" >&2
  curl -fsSL "${base}/${asset}"  -o "${tmp}/${asset}"
  curl -fsSL "${base}/${checks}" -o "${tmp}/${checks}"
  # checksums lines are "<sha>  <file>" or "<sha> *<file>"
  want="$(awk -v f="${asset}" '$2 == f || $2 == "*" f {print $1; exit}' "${tmp}/${checks}")"
  [ -n "${want}" ] || { echo "no checksum for ${asset} in ${checks}" >&2; exit 3; }
  got="$(sha256_of "${tmp}/${asset}")"
  [ "${want}" = "${got}" ] || { echo "CHECKSUM MISMATCH ${tool}: want ${want} got ${got}" >&2; exit 3; }
  echo ">> ${tool}: checksum OK (${got})" >&2
  echo "${tmp}/${asset}"
}

mkdir -p "${BIN_DIR}"
rm -f "${BIN_DIR:?}"/*

# httpx (projectdiscovery) — .zip containing the bare `httpx` binary
hx="$(fetch_verify httpx "${HTTPX_VERSION}" "httpx_${HTTPX_VERSION}_linux_${ARCH}.zip" "httpx_${HTTPX_VERSION}_checksums.txt" projectdiscovery/httpx)"
unzip -o -j "${hx}" httpx -d "${BIN_DIR}" >/dev/null

# dalfox (hahwul) — .tar.gz containing the bare `dalfox` binary (flat layout)
dx="$(fetch_verify dalfox "${DALFOX_VERSION}" "dalfox_${DALFOX_VERSION}_linux_${ARCH}.tar.gz" "dalfox_${DALFOX_VERSION}_checksums.txt" hahwul/dalfox)"
tar -xzf "${dx}" -C "${BIN_DIR}" dalfox

chmod 0755 "${BIN_DIR}"/*
echo ">> staged binaries:"; ls -l "${BIN_DIR}"

if [ "${STAGE_ONLY}" = "1" ]; then echo "stage-only: skipping docker build/push/pin"; exit 0; fi

docker version >/dev/null 2>&1 || { echo "Docker daemon not running — start Docker Desktop" >&2; exit 4; }

TAG="${REGISTRY}:$(date -u +%Y%m%d)-${ARCH}-httpx${HTTPX_VERSION}-dalfox${DALFOX_VERSION}"
echo ">> building ${TAG} (${PLATFORM})"
build_args=()
[ -n "${BASE_IMAGE:-}" ] && build_args+=(--build-arg "BASE_IMAGE=${BASE_IMAGE}")
docker build --platform "${PLATFORM}" "${build_args[@]}" -f "${DOCKERFILE}" -t "${TAG}" "${CONTEXT_DIR}"

echo ">> pushing ${TAG}  (needs: docker login ghcr.io with write:packages)"
docker push "${TAG}"

DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "${TAG}")"
[ -n "${DIGEST}" ] || { echo "could not resolve RepoDigest after push" >&2; exit 5; }
echo ">> pulling by digest so --pull=never can resolve it locally: ${DIGEST}"
docker pull "${DIGEST}" >/dev/null

# write the lockfile (the SOLE source of runOffensiveTool's imageDigest) as a generated `.js` module,
# so install.js's mcp/lib `.js` copy picks it up automatically (a `.json` would be silently dropped) — commit it.
printf '"use strict";\n// Generated by scripts/build-offensive-image.sh — pinned offensive arsenal image digest. Commit this file.\nmodule.exports = {\n  image_digest: "%s",\n  built_platform: "%s",\n  tools: { httpx: "%s", dalfox: "%s" },\n};\n' \
  "${DIGEST}" "${PLATFORM}" "${HTTPX_VERSION}" "${DALFOX_VERSION}" > "${LOCKFILE}"
echo ">> wrote ${LOCKFILE}:"; cat "${LOCKFILE}"
echo ">> DONE. Commit mcp/lib/offensive-image-lock.js."
