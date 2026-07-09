#!/usr/bin/env bash
# bob-approval-gate.sh — PreToolUse hook (sibling to bob-http-write-confirm.sh) that
# enforces the GRADE→REPORT human-approval gate: it BLOCKS bob_advance_session(to_state=REPORT)
# and bob_finalize_report until a named human's Step Functions SendTaskSuccess has written the
# approval artifact. Belt-and-suspenders alongside the additive external_approval_pending blocker
# in lifecycle-gates.js gateGradeToReport. This is a defensive human-in-the-loop gate — it adds
# no offensive capability; it only WITHHOLDS the report step until a human approves.
#
# Runbook: aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md
exec python3 "$(dirname "$0")/bob-approval-gate-impl.py"
