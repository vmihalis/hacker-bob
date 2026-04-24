#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./dev-sync.sh /absolute/path/to/test-workspace [--no-health-check]

Sync the current repo into a local Claude Code test workspace.

What it does:
  1. Backs up target .mcp.json and .claude/settings.json if they exist
  2. Runs ./install.sh against the target workspace
  3. Re-merges .mcp.json and .claude/settings.json with the repo-backed
     bountyagent development config while preserving unrelated user config
  4. Optionally runs `claude mcp list` inside the target workspace

This script is intended for a dedicated local test workspace.
EOF
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 1
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

TARGET_INPUT="$1"
RUN_HEALTH_CHECK=1

if [[ $# -eq 2 ]]; then
  if [[ "$2" == "--no-health-check" ]]; then
    RUN_HEALTH_CHECK=0
  else
    usage
    exit 1
  fi
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_ABS="$(cd "$TARGET_INPUT" && pwd)"
CLAUDE_DIR="$TARGET_ABS/.claude"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

backup_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    cp "$path" "$path.$TIMESTAMP.bak"
    echo "Backed up $path -> $path.$TIMESTAMP.bak"
  fi
}

echo "Syncing repo into $TARGET_ABS"
echo ""

backup_file "$TARGET_ABS/.mcp.json"
backup_file "$CLAUDE_DIR/settings.json"

"$SCRIPT_DIR/install.sh" "$TARGET_ABS"

mkdir -p "$CLAUDE_DIR/hooks" "$CLAUDE_DIR/knowledge" "$CLAUDE_DIR/skills/bountyagent"
cp "$SCRIPT_DIR/.claude/hooks/session-write-guard.sh" "$CLAUDE_DIR/hooks/"
cp "$SCRIPT_DIR/.claude/hooks/hunter-subagent-stop.js" "$CLAUDE_DIR/hooks/"
chmod +x "$CLAUDE_DIR/hooks/session-write-guard.sh" "$CLAUDE_DIR/hooks/hunter-subagent-stop.js"
cp "$SCRIPT_DIR/.claude/knowledge/"*.json "$CLAUDE_DIR/knowledge/"
cp "$SCRIPT_DIR/.claude/skills/bountyagent/SKILL.md" "$CLAUDE_DIR/skills/bountyagent/"

mkdir -p "$TARGET_ABS/mcp/lib"
cp "$SCRIPT_DIR/mcp/server.js" "$TARGET_ABS/mcp/"
cp "$SCRIPT_DIR/mcp/auto-signup.js" "$TARGET_ABS/mcp/"
cp "$SCRIPT_DIR/mcp/redaction.js" "$TARGET_ABS/mcp/"
cp "$SCRIPT_DIR/mcp/lib/"*.js "$TARGET_ABS/mcp/lib/"
chmod +x "$TARGET_ABS/mcp/server.js"

node "$SCRIPT_DIR/scripts/merge-claude-config.js" "$TARGET_ABS" >/dev/null

echo ""
echo "Merged repo-backed dev config:"
echo "  $TARGET_ABS/.mcp.json"
echo "  $CLAUDE_DIR/settings.json"

if [[ $RUN_HEALTH_CHECK -eq 1 ]]; then
  echo ""
  if command -v claude >/dev/null 2>&1; then
    echo "Running Claude MCP health check..."
    (
      cd "$TARGET_ABS"
      claude mcp list
    )
  else
    echo "Skipping health check: \`claude\` is not installed."
  fi
fi

echo ""
echo "Next:"
echo "  1. Fully restart Claude Code in $TARGET_ABS"
echo "  2. Run /mcp"
echo "  3. Smoke test with bounty_http_scan against https://example.com"
