#!/usr/bin/env bash
set -euo pipefail

STACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${STACK_DIR}/../../.." && pwd)"
LAYER_DIR="${STACK_DIR}/.build/asff-builder-layer/lib"

rm -rf "${STACK_DIR}/.build/asff-builder-layer"
install -d -m 0755 "${LAYER_DIR}"

for source in asff-builder.js cvss31.js cvss-bands.js envelope.js verification-contracts.js; do
  install -m 0644 "${REPO_ROOT}/mcp/lib/${source}" "${LAYER_DIR}/${source}"
done

printf 'Prepared %s (%s bytes)\n' \
  "${LAYER_DIR}" \
  "$(du -sk "${STACK_DIR}/.build/asff-builder-layer" | awk '{print $1 * 1024}')"
