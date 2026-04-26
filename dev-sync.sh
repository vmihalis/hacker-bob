#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./dev-sync.sh /absolute/path/to/test-workspace [--adapter claude|codex|generic-mcp|all] [--no-health-check]

Sync the current repo into a local host-adapter test workspace.

What it does:
  1. Backs up target .mcp.json, and .claude/settings.json for Claude syncs
  2. Runs the local installer against the target workspace with the selected adapter
  3. Re-copies shared MCP runtime and neutral Bob resources from this repo
  4. In Claude mode, re-copies Claude commands, skills, hooks, and settings
  5. Optionally runs a local MCP load check, plus `claude mcp list` for Claude

This script is intended for a dedicated local test workspace.
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

TARGET_INPUT="$1"
ADAPTER="claude"
RUN_HEALTH_CHECK=1

shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --adapter)
      if [[ $# -lt 2 ]]; then
        usage
        exit 1
      fi
      ADAPTER="$2"
      shift 2
      ;;
    --adapter=*)
      ADAPTER="${1#--adapter=}"
      shift
      ;;
    --no-health-check)
    RUN_HEALTH_CHECK=0
      shift
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

case "$ADAPTER" in
  claude|codex|generic-mcp|all) ;;
  *)
    usage
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_ABS="$(cd "$TARGET_INPUT" && pwd)"
CLAUDE_DIR="$TARGET_ABS/.claude"
BOB_DIR="$TARGET_ABS/.hacker-bob"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

backup_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    cp "$path" "$path.$TIMESTAMP.bak"
    echo "Backed up $path -> $path.$TIMESTAMP.bak"
  fi
}

adapter_includes() {
  [[ "$ADAPTER" == "all" || "$ADAPTER" == "$1" ]]
}

sync_shared_runtime() {
  mkdir -p "$BOB_DIR/knowledge" "$BOB_DIR/bypass-tables"
  cp "$SCRIPT_DIR/.hacker-bob/knowledge/"*.json "$BOB_DIR/knowledge/"
  cp "$SCRIPT_DIR/.hacker-bob/bypass-tables/"*.txt "$BOB_DIR/bypass-tables/"

  mkdir -p "$TARGET_ABS/mcp/lib"
  cp "$SCRIPT_DIR/mcp/server.js" "$TARGET_ABS/mcp/"
  cp "$SCRIPT_DIR/mcp/auto-signup.js" "$TARGET_ABS/mcp/"
  cp "$SCRIPT_DIR/mcp/redaction.js" "$TARGET_ABS/mcp/"
  cp "$SCRIPT_DIR/mcp/lib/"*.js "$TARGET_ABS/mcp/lib/"
  rm -rf "$TARGET_ABS/mcp/lib/tools"
  mkdir -p "$TARGET_ABS/mcp/lib/tools"
  cp "$SCRIPT_DIR/mcp/lib/tools/"*.js "$TARGET_ABS/mcp/lib/tools/"
  chmod +x "$TARGET_ABS/mcp/server.js"
}

sync_claude_adapter() {
  mkdir -p "$CLAUDE_DIR/hooks" "$CLAUDE_DIR/commands" "$CLAUDE_DIR/skills/bob-hunt" "$CLAUDE_DIR/skills/bob-status" "$CLAUDE_DIR/skills/bob-debug"
  rm -f "$CLAUDE_DIR/hooks/bob-update-lib.js"
  cp "$SCRIPT_DIR/.claude/hooks/session-write-guard.sh" "$CLAUDE_DIR/hooks/"
  cp "$SCRIPT_DIR/.claude/hooks/hunter-subagent-stop.js" "$CLAUDE_DIR/hooks/"
  cp "$SCRIPT_DIR/.claude/hooks/bob-update.js" "$CLAUDE_DIR/hooks/"
  cp "$SCRIPT_DIR/.claude/hooks/bob-check-update.js" "$CLAUDE_DIR/hooks/"
  cp "$SCRIPT_DIR/.claude/hooks/bob-check-update-worker.js" "$CLAUDE_DIR/hooks/"
  chmod +x "$CLAUDE_DIR/hooks/session-write-guard.sh" "$CLAUDE_DIR/hooks/hunter-subagent-stop.js" "$CLAUDE_DIR/hooks/bob-update.js" "$CLAUDE_DIR/hooks/bob-check-update.js" "$CLAUDE_DIR/hooks/bob-check-update-worker.js"
  rm -f "$CLAUDE_DIR/commands/bountyagent.md" "$CLAUDE_DIR/commands/bountyagentdebug.md"
  rm -f "$CLAUDE_DIR/commands/bob/hunt.md" "$CLAUDE_DIR/commands/bob/status.md" "$CLAUDE_DIR/commands/bob/debug.md" "$CLAUDE_DIR/commands/bob/update.md"
  rmdir "$CLAUDE_DIR/commands/bob" 2>/dev/null || true
  rm -rf "$CLAUDE_DIR/skills/bountyagent" "$CLAUDE_DIR/skills/bountyagentstatus" "$CLAUDE_DIR/skills/bountyagentdebug"
  cp "$SCRIPT_DIR/.claude/commands/bob-update.md" "$CLAUDE_DIR/commands/"
  cp "$SCRIPT_DIR/.claude/skills/bob-hunt/SKILL.md" "$CLAUDE_DIR/skills/bob-hunt/"
  cp "$SCRIPT_DIR/.claude/skills/bob-status/SKILL.md" "$CLAUDE_DIR/skills/bob-status/"
  cp "$SCRIPT_DIR/.claude/skills/bob-debug/SKILL.md" "$CLAUDE_DIR/skills/bob-debug/"

  node "$SCRIPT_DIR/scripts/merge-claude-config.js" "$TARGET_ABS" >/dev/null
}

echo "Syncing repo into $TARGET_ABS with adapter: $ADAPTER"
echo ""

backup_file "$TARGET_ABS/.mcp.json"
if adapter_includes "claude"; then
  backup_file "$CLAUDE_DIR/settings.json"
fi

"$SCRIPT_DIR/install.sh" "$TARGET_ABS" --adapter "$ADAPTER"
sync_shared_runtime
if adapter_includes "claude"; then
  sync_claude_adapter
fi

echo ""
echo "Synced repo-backed dev config:"
echo "  $TARGET_ABS/.mcp.json"
echo "  $TARGET_ABS/mcp/server.js"
if adapter_includes "claude"; then
  echo "  $CLAUDE_DIR/settings.json"
fi

if [[ $RUN_HEALTH_CHECK -eq 1 ]]; then
  echo ""
  echo "Running MCP runtime load check..."
  node -e "const server = require(process.argv[1]); if (!Array.isArray(server.TOOLS) || server.TOOLS.length === 0) process.exit(2)" "$TARGET_ABS/mcp/server.js"
  if adapter_includes "claude" && command -v claude >/dev/null 2>&1; then
    echo "Running Claude MCP health check..."
    (
      cd "$TARGET_ABS"
      claude mcp list
    )
  elif adapter_includes "claude"; then
    echo "Skipping health check: \`claude\` is not installed."
  fi
fi

echo ""
echo "Next:"
if adapter_includes "claude"; then
  echo "  1. Fully restart Claude Code in $TARGET_ABS"
  echo "  2. Run /mcp"
  echo "  3. Smoke test with bounty_http_scan using target_domain: \"example.com\" against https://example.com"
elif adapter_includes "codex"; then
  echo "  1. Restart Codex in $TARGET_ABS"
  echo "  2. Confirm the hacker-bob plugin is available"
  echo "  3. Smoke test with the \$bob-status skill"
else
  echo "  1. Configure your MCP host to use $TARGET_ABS/mcp/server.js"
  echo "  2. Read $BOB_DIR/generic-mcp/hacker-bob.md"
  echo "  3. Smoke test by listing or calling the bountyagent MCP tools"
fi
