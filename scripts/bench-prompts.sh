#!/usr/bin/env bash
# Benchmark candidate hunter system prompts against a refused subagent transcript.
#
# Usage:
#   ANTHROPIC_API_KEY=sk-... \
#     scripts/bench-prompts.sh <transcript.jsonl> <candidates-dir> <n-trials> [model]
#
# Deprecated optional raw Anthropic API prompt bench.
#
# Prefer testing/policy-replay/bench.mjs, which uses the maintained case format
# and Claude Agent SDK local OAuth path. This script remains only for ad hoc
# API-key comparisons.
#
# For each *.md in <candidates-dir>, replays the transcript prefix N times
# and reports refusal-rate. Lower is better.

set -euo pipefail

if [ $# -lt 3 ]; then
  echo "usage: $0 <transcript.jsonl> <candidates-dir> <n-trials> [model]" >&2
  exit 2
fi

TRANSCRIPT="$1"
CANDIDATES_DIR="$2"
N="$3"
MODEL="${4:-claude-opus-4-7}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPLAY="$SCRIPT_DIR/replay-refusal.js"

if [ ! -f "$REPLAY" ]; then
  echo "error: replay-refusal.js not found next to this script" >&2
  exit 2
fi

if [ ! -f "$TRANSCRIPT" ]; then
  echo "error: transcript not found: $TRANSCRIPT" >&2
  exit 2
fi

if [ ! -d "$CANDIDATES_DIR" ]; then
  echo "error: candidates dir not found: $CANDIDATES_DIR" >&2
  exit 2
fi

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "error: ANTHROPIC_API_KEY not set" >&2
  exit 2
fi

printf "%-40s %8s %8s %8s\n" "candidate" "trials" "refused" "rate"
printf "%-40s %8s %8s %8s\n" "----------------------------------------" "------" "-------" "----"

shopt -s nullglob
for prompt in "$CANDIDATES_DIR"/*.md; do
  name="$(basename "$prompt" .md)"
  if [ "$name" = "README" ]; then continue; fi
  results="$(node "$REPLAY" \
    --transcript "$TRANSCRIPT" \
    --system "$prompt" \
    --model "$MODEL" \
    --n "$N" 2>/dev/null || true)"
  refused="$(echo "$results" | awk -F'"stop_reason":"' 'NF>1{split($2,a,"\""); if (a[1]=="refusal") c++} END{print c+0}')"
  printf "%-40s %8d %8d %7.1f%%\n" "$name" "$N" "$refused" "$(awk -v r="$refused" -v n="$N" 'BEGIN{printf "%.1f", (r/n)*100}')"
done
