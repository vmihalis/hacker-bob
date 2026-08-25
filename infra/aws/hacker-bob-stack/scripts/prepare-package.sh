#!/usr/bin/env bash
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${STACK_DIR}/../../.." && pwd)"
LAYER_ROOT="${STACK_DIR}/.build/asff-builder-layer"

rm -rf "${LAYER_ROOT}"

# The ASFF builder and its transitive deps live under mcp/{domains,core}/... and
# one workspace package, and they have CROSS-DIRECTORY require()s
# (asff-builder.js -> ../../core/scoring/cvss31.js, ../../core/io/envelope.js;
#  verification-contracts.js -> ../../../packages/bob-instrument-contracts/lib/...).
# So the layer must PRESERVE their repo-relative structure — a flat copy breaks
# the require graph at runtime. mcp/<x> maps to /opt/lib/<x>; the workspace
# package maps to /opt/packages/<x>, matching the ../../../packages/ hop from
# /opt/lib/core/verification/. The env vars ASFF_BUILDER_PATH and
# VERIFICATION_CONTRACTS_PATH (template.yaml) point at the structured locations.
for rel in \
  mcp/domains/repo/asff-builder.js \
  mcp/core/scoring/cvss31.js \
  mcp/core/scoring/cvss-bands.js \
  mcp/core/io/envelope.js \
  mcp/core/verification/verification-contracts.js \
  packages/bob-instrument-contracts/lib/verification-contracts.js; do
  case "${rel}" in
    mcp/*)      dest="${LAYER_ROOT}/lib/${rel#mcp/}" ;;
    packages/*) dest="${LAYER_ROOT}/${rel}" ;;
  esac
  mkdir -p "$(dirname "${dest}")"
  install -m 0644 "${REPO_ROOT}/${rel}" "${dest}"
done

printf 'Prepared %s (%s bytes)\n' \
  "${LAYER_ROOT}" \
  "$(du -sk "${LAYER_ROOT}" | awk '{print $1 * 1024}')"
