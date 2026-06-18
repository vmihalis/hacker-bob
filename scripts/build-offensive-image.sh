#!/usr/bin/env bash
#
# build-offensive-image.sh — build + push + DIGEST-PIN the Hacker Bob offensive arsenal image.
#
# WHY: offensive-sandbox.js runs the container with `--pull=never` + `name@sha256:<digest>`. A local
# `docker build` has NO RepoDigest, so the only way to mint a resolvable digest is build -> push to a
# registry -> pull-by-digest. This does that against ghcr.io and writes mcp/lib/offensive-image.json
# (the SOLE source of runOffensiveTool's imageDigest).
#
# PROVENANCE: you supply each tool's exact release archive URL + its published sha256 (both REQUIRED).
# The script verifies the download against your pin — no upstream asset-name guessing (release naming
# differs per tool/version) and no trust-on-first-use. The base image is resolved to an immutable
# @sha256: digest before the build (reproducible); the final image digest is bound to ${REGISTRY}.
#
# ONE-TIME PREREQS: Docker running + `docker login ghcr.io` (PAT with the write:packages scope).
#
# Usage — from each project's releases page, copy the linux archive URL for your arch + its sha256:
#   HTTPX_URL=...  HTTPX_SHA256=...  DALFOX_URL=...  DALFOX_SHA256=...  scripts/build-offensive-image.sh
#   ... same env ... scripts/build-offensive-image.sh --stage-only     # fetch+verify+stage, no docker
#
# Override knobs (env): OFFENSIVE_REGISTRY, OFFENSIVE_ARCH, BASE_IMAGE
set -euo pipefail

# REQUIRED per-tool inputs — the exact release ARCHIVE URL + its published sha256 (no defaults). Supplying
# the URL avoids guessing release asset names; supplying the sha pins the binary to the published hash.
HTTPX_URL="${HTTPX_URL:?set HTTPX_URL to the httpx linux release archive (github.com/projectdiscovery/httpx/releases)}"
HTTPX_SHA256="${HTTPX_SHA256:?set HTTPX_SHA256 to the published sha256 of HTTPX_URL}"
DALFOX_URL="${DALFOX_URL:?set DALFOX_URL to the dalfox linux release archive (github.com/hahwul/dalfox/releases)}"
DALFOX_SHA256="${DALFOX_SHA256:?set DALFOX_SHA256 to the published sha256 of DALFOX_URL}"

REGISTRY="${OFFENSIVE_REGISTRY:-ghcr.io/bobnetsec/bob-offense}"
BASE_IMAGE="${BASE_IMAGE:-gcr.io/distroless/base-debian12:nonroot}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTEXT_DIR="${REPO_ROOT}/docker/offensive-context"
BIN_DIR="${CONTEXT_DIR}/bin"
DOCKERFILE="${REPO_ROOT}/docker/offensive.Dockerfile"
LOCKFILE="${REPO_ROOT}/mcp/lib/offensive-image.json"

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
need curl; need unzip; need tar; need awk; need find

# sha256 helper — prefer sha256sum (Linux), fall back to shasum (macOS)
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "need sha256sum or shasum" >&2; exit 2
fi

# strip a tag/digest off an image ref -> bare repo, PORT-AWARE (a registry host:port colon is not a tag).
bare_repo() {
  local r="${1%@*}"                # strip @digest
  case "${r##*/}" in               # only the part after the last '/' can hold a :tag
    *:*) printf '%s' "${r%:*}" ;;  # has a tag -> strip it
    *)   printf '%s' "${r}" ;;     # no tag (a host:port colon lives before the last '/')
  esac
}

# pick the RepoDigest bound to a given repo (never blindly index 0 across registries).
repo_digest_for() {
  docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$1" |
    awk -v p="$2@sha256:" 'index($0,p)==1 && length($0)==length(p)+64 && substr($0,length(p)+1) ~ /^[0-9a-f]{64}$/ {print; exit}'
}

# clean up all temp dirs on exit
TMPDIRS=()
cleanup() { local d; for d in "${TMPDIRS[@]:-}"; do [ -n "${d}" ] && rm -rf "${d}"; done; }
trap cleanup EXIT

# download an archive, verify its sha256 against the REQUIRED pin, extract a named binary into BIN_DIR.
# args: binary_name url expected_sha
fetch_bin() {
  local name="$1" url="$2" want="$3" tmp got found
  tmp="$(mktemp -d)"; TMPDIRS+=("${tmp}")
  echo ">> ${name}: downloading ${url}" >&2
  curl -fsSL "${url}" -o "${tmp}/archive"
  got="$(sha256_of "${tmp}/archive")"
  [ "${want}" = "${got}" ] || { echo "CHECKSUM MISMATCH ${name}: expected ${want} got ${got}" >&2; exit 3; }
  echo ">> ${name}: sha256 OK (${got})" >&2
  case "${url}" in
    *.zip)          ( cd "${tmp}" && unzip -oq archive ) ;;
    *.tar.gz|*.tgz) tar -xzf "${tmp}/archive" -C "${tmp}" ;;
    *.tar.xz)       tar -xJf "${tmp}/archive" -C "${tmp}" ;;
    *) echo "unsupported archive type for ${url} (want .zip / .tar.gz / .tgz / .tar.xz)" >&2; exit 3 ;;
  esac
  found="$(find "${tmp}" -type f -name "${name}" | head -1)"
  [ -n "${found}" ] || { echo "binary '${name}' not found inside ${url}" >&2; exit 3; }
  cp "${found}" "${BIN_DIR}/${name}"
}

# reset the WHOLE build context — `docker build "${CONTEXT_DIR}"` uploads the entire dir to the daemon,
# so nothing stale/secret elsewhere under the gitignored context should ever be sent. Only bin/ remains.
rm -rf "${CONTEXT_DIR:?}"
mkdir -p "${BIN_DIR}"

fetch_bin httpx  "${HTTPX_URL}"  "${HTTPX_SHA256}"
fetch_bin dalfox "${DALFOX_URL}" "${DALFOX_SHA256}"
chmod 0755 "${BIN_DIR}"/*
echo ">> staged binaries:"; ls -l "${BIN_DIR}"

if [ "${STAGE_ONLY}" = "1" ]; then echo "stage-only: skipping docker build/push/pin"; exit 0; fi

docker version >/dev/null 2>&1 || { echo "Docker daemon not running — start Docker Desktop" >&2; exit 4; }

# resolve the base image to an immutable digest so the build is reproducible (recorded in the lockfile)
echo ">> resolving base image digest for ${BASE_IMAGE}"
docker pull "${BASE_IMAGE}" >/dev/null
BASE_DIGEST="$(repo_digest_for "${BASE_IMAGE}" "$(bare_repo "${BASE_IMAGE}")")"
[ -n "${BASE_DIGEST}" ] || { echo "could not resolve a digest for base image ${BASE_IMAGE}" >&2; exit 5; }
echo ">> base pinned: ${BASE_DIGEST}"

TAG="${REGISTRY}:$(date -u +%Y%m%d%H%M%S)-${ARCH}"
echo ">> building ${TAG} (${PLATFORM}, base ${BASE_DIGEST})"
docker build --platform "${PLATFORM}" --build-arg "BASE_IMAGE=${BASE_DIGEST}" -f "${DOCKERFILE}" -t "${TAG}" "${CONTEXT_DIR}"

echo ">> pushing ${TAG}  (needs: docker login ghcr.io with write:packages)"
docker push "${TAG}"

# bind the pinned digest to the registry we just pushed to (never blindly take RepoDigests[0])
DIGEST="$(repo_digest_for "${TAG}" "$(bare_repo "${REGISTRY}")")"
[ -n "${DIGEST}" ] || { echo "could not resolve ${REGISTRY}@sha256:<digest> after push" >&2; docker inspect --format '{{json .RepoDigests}}' "${TAG}" >&2; exit 5; }
echo ">> pulling by digest so --pull=never can resolve it locally: ${DIGEST}"
docker pull "${DIGEST}" >/dev/null

# write the lockfile (the SOLE source of runOffensiveTool's imageDigest) as JSON DATA — commit it.
printf '{\n  "image_digest": "%s",\n  "base_image": "%s",\n  "built_platform": "%s",\n  "tools": { "httpx_sha256": "%s", "dalfox_sha256": "%s" }\n}\n' \
  "${DIGEST}" "${BASE_DIGEST}" "${PLATFORM}" "${HTTPX_SHA256}" "${DALFOX_SHA256}" > "${LOCKFILE}"
echo ">> wrote ${LOCKFILE}:"; cat "${LOCKFILE}"
echo ">> DONE. Commit mcp/lib/offensive-image.json."
