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
# clean) and sha256-verified. PREFER an IN-REPO pinned SHA (HTTPX_SHA256/DALFOX_SHA256 below) so a
# compromised upstream release fails against an in-repo reference; otherwise the FIRST mint is TOFU
# (verified against the release's own checksums file — same channel — with a loud warning + the
# computed SHA printed for you to pin). The base image is resolved to a digest before the build so the
# build is reproducible, and the final image digest is bound to ${REGISTRY} (never RepoDigests[0]).
#
# ONE-TIME OPERATOR PREREQS (the script refuses to push without them):
#   1. Docker Desktop running.
#   2. docker login ghcr.io   (Personal Access Token with the write:packages scope)
#
# Usage:
#   HTTPX_VERSION=x.y.z DALFOX_VERSION=x.y.z scripts/build-offensive-image.sh                # full mint
#   HTTPX_VERSION=x.y.z DALFOX_VERSION=x.y.z scripts/build-offensive-image.sh --stage-only   # no docker
#
# Override knobs (env): HTTPX_SHA256, DALFOX_SHA256, OFFENSIVE_REGISTRY, OFFENSIVE_ARCH, BASE_IMAGE
set -euo pipefail

# --- pinned arsenal versions (REQUIRED — no default: a hardcoded guess can 404, and there is no
#     'current' version that stays valid). Look up + pin the exact release tags:
#       httpx:  https://github.com/projectdiscovery/httpx/releases
#       dalfox: https://github.com/hahwul/dalfox/releases
HTTPX_VERSION="${HTTPX_VERSION:?set HTTPX_VERSION to a current httpx release (see github.com/projectdiscovery/httpx/releases)}"
DALFOX_VERSION="${DALFOX_VERSION:?set DALFOX_VERSION to a current dalfox release (see github.com/hahwul/dalfox/releases)}"

# --- in-repo pinned SHA256 of each downloaded asset (release-tamper protection); empty => TOFU 1st mint ---
HTTPX_SHA256="${HTTPX_SHA256:-}"
DALFOX_SHA256="${DALFOX_SHA256:-}"

REGISTRY="${OFFENSIVE_REGISTRY:-ghcr.io/bobnetsec/bob-offense}"
BASE_IMAGE="${BASE_IMAGE:-gcr.io/distroless/base-debian12:nonroot}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTEXT_DIR="${REPO_ROOT}/docker/offensive-context"
BIN_DIR="${CONTEXT_DIR}/bin"
DOCKERFILE="${REPO_ROOT}/docker/offensive.Dockerfile"
LOCKFILE="${REPO_ROOT}/mcp/lib/offensive-image.json"

STAGE_ONLY=0
[ "${1:-}" = "--stage-only" ] && STAGE_ONLY=1

# version-format guard — keep the version env vars from injecting path/URL segments into the curl URL
valid_ver() { case "$1" in *[!0-9.]* | "" ) return 1 ;; *.*.* ) return 0 ;; * ) return 1 ;; esac; }
valid_ver "${HTTPX_VERSION}"  || { echo "bad HTTPX_VERSION (want N.N.N): ${HTTPX_VERSION}" >&2; exit 2; }
valid_ver "${DALFOX_VERSION}" || { echo "bad DALFOX_VERSION (want N.N.N): ${DALFOX_VERSION}" >&2; exit 2; }

# target platform: linux + host arch (override with OFFENSIVE_ARCH=amd64|arm64)
host_arch="$(uname -m)"
case "${OFFENSIVE_ARCH:-${host_arch}}" in
  arm64|aarch64) ARCH=arm64 ;;
  x86_64|amd64)  ARCH=amd64 ;;
  *) echo "unsupported arch: ${OFFENSIVE_ARCH:-${host_arch}}" >&2; exit 2 ;;
esac
PLATFORM="linux/${ARCH}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 2; }; }
need curl; need unzip; need tar; need awk

# sha256 helper — prefer sha256sum (Linux), fall back to shasum (macOS)
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "need sha256sum or shasum" >&2; exit 2
fi

upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

# strip a tag/digest off an image ref -> bare repo (handles an optional registry :port)
bare_repo() { local r="${1%@*}"; printf '%s' "${r%:*}"; }

# pick the RepoDigest bound to a given repo (never blindly index 0 across registries).
# args: image_ref repo_prefix -> echoes repo@sha256:<64hex> (empty if none match)
repo_digest_for() {
  docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$1" |
    awk -v p="$2@sha256:" 'index($0,p)==1 && length($0)==length(p)+64 && substr($0,length(p)+1) ~ /^[0-9a-f]{64}$/ {print; exit}'
}

# clean up all temp dirs on exit
TMPDIRS=()
cleanup() { local d; for d in "${TMPDIRS[@]:-}"; do [ -n "${d}" ] && rm -rf "${d}"; done; }
trap cleanup EXIT

# fetch a release asset and verify it against an IN-REPO pinned sha if provided, else (TOFU) against the
# release's own checksums file with a loud warning. args: tool version asset checks slug pinned_sha
# echoes the verified asset path on stdout.
fetch_verify() {
  local tool="$1" ver="$2" asset="$3" checks="$4" slug="$5" pinned="$6"
  local tmp base got want
  tmp="$(mktemp -d)"; TMPDIRS+=("${tmp}")
  base="https://github.com/${slug}/releases/download/v${ver}"
  echo ">> ${tool} v${ver} (${ARCH}): downloading ${asset}" >&2
  curl -fsSL "${base}/${asset}" -o "${tmp}/${asset}"
  got="$(sha256_of "${tmp}/${asset}")"
  if [ -n "${pinned}" ]; then
    [ "${pinned}" = "${got}" ] || { echo "CHECKSUM MISMATCH ${tool}: in-repo pinned ${pinned} got ${got}" >&2; exit 3; }
    echo ">> ${tool}: verified against in-repo pinned SHA (${got})" >&2
  else
    curl -fsSL "${base}/${checks}" -o "${tmp}/${checks}"
    want="$(awk -v f="${asset}" '$2 == f || $2 == "*" f {print $1; exit}' "${tmp}/${checks}")"
    [ -n "${want}" ] || { echo "no checksum for ${asset} in ${checks}" >&2; exit 3; }
    [ "${want}" = "${got}" ] || { echo "CHECKSUM MISMATCH ${tool}: release-checksums ${want} got ${got}" >&2; exit 3; }
    echo "!! ${tool}: TOFU — verified against the release's OWN checksums (same channel; NOT release-tamper-proof)." >&2
    echo "!! Pin in-repo to harden: $(upper "${tool}")_SHA256=${got}" >&2
  fi
  echo "${tmp}/${asset}"
}

# reset the WHOLE build context — `docker build "${CONTEXT_DIR}"` uploads the entire dir to the daemon,
# so nothing stale/secret elsewhere under the gitignored context should ever be sent. Only bin/ remains.
rm -rf "${CONTEXT_DIR:?}"
mkdir -p "${BIN_DIR}"

# httpx (projectdiscovery) — .zip containing the bare `httpx` binary
hx="$(fetch_verify httpx "${HTTPX_VERSION}" "httpx_${HTTPX_VERSION}_linux_${ARCH}.zip" "httpx_${HTTPX_VERSION}_checksums.txt" projectdiscovery/httpx "${HTTPX_SHA256}")"
unzip -o -j "${hx}" httpx -d "${BIN_DIR}" >/dev/null

# dalfox (hahwul) — .tar.gz containing the bare `dalfox` binary (flat layout)
dx="$(fetch_verify dalfox "${DALFOX_VERSION}" "dalfox_${DALFOX_VERSION}_linux_${ARCH}.tar.gz" "dalfox_${DALFOX_VERSION}_checksums.txt" hahwul/dalfox "${DALFOX_SHA256}")"
tar -xzf "${dx}" -C "${BIN_DIR}" dalfox

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

TAG="${REGISTRY}:$(date -u +%Y%m%d)-${ARCH}-httpx${HTTPX_VERSION}-dalfox${DALFOX_VERSION}"
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
printf '{\n  "image_digest": "%s",\n  "base_image": "%s",\n  "built_platform": "%s",\n  "tools": { "httpx": "%s", "dalfox": "%s" }\n}\n' \
  "${DIGEST}" "${BASE_DIGEST}" "${PLATFORM}" "${HTTPX_VERSION}" "${DALFOX_VERSION}" > "${LOCKFILE}"
echo ">> wrote ${LOCKFILE}:"; cat "${LOCKFILE}"
echo ">> DONE. Commit mcp/lib/offensive-image.json."
