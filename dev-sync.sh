#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./dev-sync.sh /absolute/path/to/test-workspace [--no-health-check]

Sync the current repo into a local Claude Code test workspace.

What it does:
  1. Backs up target .mcp.json and .claude/settings.json if they exist
  2. Runs ./install.sh against the target workspace
  3. Overwrites the target .mcp.json and .claude/settings.json with the
     repo-backed bountyagent development config
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

mkdir -p "$CLAUDE_DIR/hooks" "$CLAUDE_DIR/knowledge"
cp "$SCRIPT_DIR/.claude/hooks/session-write-guard.sh" "$CLAUDE_DIR/hooks/"
chmod +x "$CLAUDE_DIR/hooks/session-write-guard.sh"
cp "$SCRIPT_DIR/.claude/knowledge/"*.json "$CLAUDE_DIR/knowledge/"

mkdir -p "$TARGET_ABS/mcp/lib"
cp "$SCRIPT_DIR/mcp/server.js" "$TARGET_ABS/mcp/"
cp "$SCRIPT_DIR/mcp/auto-signup.js" "$TARGET_ABS/mcp/"
cp "$SCRIPT_DIR/mcp/redaction.js" "$TARGET_ABS/mcp/"
cp "$SCRIPT_DIR/mcp/lib/"*.js "$TARGET_ABS/mcp/lib/"
chmod +x "$TARGET_ABS/mcp/server.js"

cat > "$TARGET_ABS/.mcp.json" <<EOF
{
  "mcpServers": {
    "bountyagent": {
      "command": "node",
      "args": ["$TARGET_ABS/mcp/server.js"]
    }
  }
}
EOF

cat > "$CLAUDE_DIR/settings.json" <<'EOF'
{
  "permissions": {
    "allow": [
      "mcp__bountyagent__bounty_http_scan",
      "mcp__bountyagent__bounty_import_http_traffic",
      "mcp__bountyagent__bounty_read_http_audit",
      "mcp__bountyagent__bounty_public_intel",
      "mcp__bountyagent__bounty_import_static_artifact",
      "mcp__bountyagent__bounty_static_scan",
      "mcp__bountyagent__bounty_record_finding",
      "mcp__bountyagent__bounty_read_findings",
      "mcp__bountyagent__bounty_list_findings",
      "mcp__bountyagent__bounty_write_verification_round",
      "mcp__bountyagent__bounty_read_verification_round",
      "mcp__bountyagent__bounty_write_grade_verdict",
      "mcp__bountyagent__bounty_read_grade_verdict",
      "mcp__bountyagent__bounty_init_session",
      "mcp__bountyagent__bounty_read_session_state",
      "mcp__bountyagent__bounty_read_state_summary",
      "mcp__bountyagent__bounty_transition_phase",
      "mcp__bountyagent__bounty_start_wave",
      "mcp__bountyagent__bounty_apply_wave_merge",
      "mcp__bountyagent__bounty_write_handoff",
      "mcp__bountyagent__bounty_write_wave_handoff",
      "mcp__bountyagent__bounty_wave_handoff_status",
      "mcp__bountyagent__bounty_merge_wave_handoffs",
      "mcp__bountyagent__bounty_read_wave_handoffs",
      "mcp__bountyagent__bounty_read_handoff",
      "mcp__bountyagent__bounty_auth_manual",
      "mcp__bountyagent__bounty_list_auth_profiles",
      "mcp__bountyagent__bounty_log_dead_ends",
      "mcp__bountyagent__bounty_log_coverage",
      "mcp__bountyagent__bounty_wave_status",
      "mcp__bountyagent__bounty_temp_email",
      "mcp__bountyagent__bounty_signup_detect",
      "mcp__bountyagent__bounty_auth_store",
      "mcp__bountyagent__bounty_auto_signup",
      "mcp__bountyagent__bounty_read_hunter_brief",
      "Bash(mkdir *)",
      "Bash(test *)",
      "Bash(cat *)",
      "Bash(ls *)",
      "Bash(sort *)",
      "Bash(wc *)",
      "Bash(head *)",
      "Bash(tail *)",
      "Bash(jq *)",
      "Bash(printf *)",
      "Bash(echo *)",
      "Read",
      "Glob",
      "Grep"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/scope-guard.sh\"",
            "timeout": 5
          },
          {
            "type": "command",
            "command": "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/session-write-guard.sh\"",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/session-write-guard.sh\"",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "mcp__bountyagent__bounty_http_scan",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/scope-guard-mcp.sh\"",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "mcp__bountyagent__bounty_signup_detect",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/scope-guard-mcp.sh\"",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "mcp__bountyagent__bounty_auto_signup",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/scope-guard-mcp.sh\"",
            "timeout": 5
          }
        ]
      }
    ]
  },
  "statusLine": {
    "type": "command",
    "command": "node \"$CLAUDE_PROJECT_DIR/.claude/hooks/bounty-statusline.js\""
  }
}
EOF

echo ""
echo "Wrote repo-backed dev config:"
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
