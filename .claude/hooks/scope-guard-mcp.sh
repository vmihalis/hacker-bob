#!/bin/bash
# Scope guard hook — PreToolUse on mcp__bountyagent__bounty_http_scan
# Validates the URL parameter against in-scope domains
# Warn-only for out-of-scope (logs to scope-warnings.log)
# Hard-block for deny-listed domains (exit 2)

# Read tool input from stdin
INPUT=$(cat)
URL=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_input',{}).get('url',''))" 2>/dev/null)

[ -z "$URL" ] && exit 0

# Extract domain from URL
DOMAIN=$(echo "$URL" | python3 -c "import sys; from urllib.parse import urlparse; print(urlparse(sys.stdin.read().strip()).hostname or '')" 2>/dev/null)
[ -z "$DOMAIN" ] && exit 0

# Find the active session directory
SESSION_DIR=$(ls -dt ~/bounty-agent-sessions/*/ 2>/dev/null | head -1)
[ -z "$SESSION_DIR" ] && exit 0

# --- HARD DENY CHECK (exit 2 = block) ---
if [ -f "$SESSION_DIR/deny-list.txt" ]; then
  while IFS= read -r denied; do
    [ -z "$denied" ] && continue
    if [ "$DOMAIN" = "$denied" ] || echo "$DOMAIN" | grep -qE "(^|\.)${denied//./\\.}$"; then
      echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] BLOCKED (deny-list): $DOMAIN via http_scan" >> "$SESSION_DIR/scope-warnings.log"
      echo "BLOCKED: $DOMAIN is on the deny list"
      exit 2
    fi
  done < "$SESSION_DIR/deny-list.txt"
fi

# --- BUILD ALLOWED LIST ---
ALLOWED=""

# From state.json target
if [ -f "$SESSION_DIR/state.json" ]; then
  TARGET=$(python3 -c "import json; print(json.load(open('$SESSION_DIR/state.json')).get('target',''))" 2>/dev/null)
  [ -n "$TARGET" ] && ALLOWED="$TARGET"
fi

# From attack_surface.json hosts
if [ -f "$SESSION_DIR/attack_surface.json" ]; then
  SURFACE_HOSTS=$(python3 -c "
import json
data = json.load(open('$SESSION_DIR/attack_surface.json'))
for s in data.get('surfaces', []):
    for h in s.get('hosts', []):
        print(h.replace('https://','').replace('http://','').split('/')[0])
" 2>/dev/null)
  ALLOWED="$ALLOWED
$SURFACE_HOSTS"
fi

# Recon infrastructure — always allowed
INFRA="web.archive.org
otx.alienvault.com
crt.sh
api.github.com
raw.githubusercontent.com"

ALLOWED="$ALLOWED
$INFRA"

# --- WARN CHECK (exit 0 = allow, but log) ---
MATCH=0
while IFS= read -r allowed; do
  [ -z "$allowed" ] && continue
  if [ "$DOMAIN" = "$allowed" ] || echo "$DOMAIN" | grep -qE "(^|\.)${allowed//./\\.}$"; then
    MATCH=1
    break
  fi
done <<< "$ALLOWED"

if [ "$MATCH" -eq 0 ]; then
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] OUT-OF-SCOPE (http_scan): $DOMAIN (url: $(echo "$URL" | head -c 200))" >> "$SESSION_DIR/scope-warnings.log"
fi

exit 0
