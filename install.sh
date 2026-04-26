#!/bin/bash
set -euo pipefail

# Compatibility wrapper for source installs.
# Preferred install:
#   npx -y hacker-bob-cc@latest install /path/to/project

TARGET="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

exec node "$SCRIPT_DIR/bin/hacker-bob.js" install "$TARGET" --source-install-sh
