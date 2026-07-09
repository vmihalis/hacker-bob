#!/usr/bin/env python3
"""
bob-approval-gate-impl.py — the human-approval gate implementation.

Matched (via scripts/generate-claude-settings.js, gated behind an AWS-branch env flag so
interactive local use is unaffected) on:
    mcp__hacker-bob__bob_advance_session   AND   mcp__hacker-bob__bob_finalize_report

Does a fast, non-blocking poll of an approval artifact (S3 object / DynamoDB item keyed by
engagementId) that ONLY a named human's Step Functions SendTaskSuccess can write. A
compromised bob can edit its own state.json but cannot forge SendTaskSuccess.
  exit 2  -> block (retryable): report step is withheld until a human approves.
  exit 0  -> allow: approval artifact present.

This is a defensive gate. It adds no offensive capability.
Runbook: aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md
"""
import os, sys

# TODO(build-day):
#  1. Only engage on the AWS branch: if os.environ.get("BOB_AGENTCORE") != "1": sys.exit(0)
#  2. Read the hook stdin JSON; extract tool name + (for advance_session) to_state.
#  3. Only gate the GRADE→REPORT edge: advance_session(to_state=="REPORT") or bob_finalize_report.
#  4. Look up the approval artifact keyed by engagementId (S3/DynamoDB).
#  5. If absent: print "awaiting named-human approval (Step Functions task token)" and sys.exit(2).
sys.exit(0)
