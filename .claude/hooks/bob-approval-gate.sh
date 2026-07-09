#!/usr/bin/env bash
# bob-approval-gate.sh — PreToolUse hook (sibling to bob-http-write-confirm.sh) that
# enforces the GRADE→REPORT human-approval gate: it BLOCKS bob_advance_session(to_state=REPORT)
# and bob_finalize_report until a named human's Step Functions SendTaskSuccess has written the
# approval artifact. Belt-and-suspenders alongside the additive external_approval_pending blocker
# in lifecycle-gates.js gateGradeToReport. This is a defensive human-in-the-loop gate — it adds
# no offensive capability; it only WITHHOLDS the report step until a human approves.
#
# Runbook: aabw-2026/projects/06-aws-glassbox/AGENTCORE-BRANCH-PLAN.md
#
# Fail CLOSED on exec failure (P1-4): if python3 is missing or not executable, a bare failed
# `exec` would exit this non-interactive shell with 127/126 — a non-2 code Claude Code treats as
# NON-BLOCKING, silently disabling this gate exactly when the human-approval withhold is supposed
# to be in force. `shopt -s execfail` makes a failed exec RETURN instead of exiting, so the
# explicit `exit 2` (Claude Code's block-with-error sentinel) runs. On exec SUCCESS the impl
# replaces this process and its own exit code (0/2, always fail-closed on ambiguity per its own
# docstring) is the hook's exit. Mirrors bob-http-write-confirm.sh's identical pattern.
shopt -s execfail
exec python3 "$(dirname "$0")/bob-approval-gate-impl.py"
exit 2
