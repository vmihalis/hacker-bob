---
name: runtime-constraint-violation
description: TRUE POSITIVE — the skill instruction tells a subagent to call Write with a relative path, which the Claude Code binary-internal regex (investigation w0b0v41zw H2) silently rejects.
---

# Runtime Constraint Drift Fixture (TRUE POSITIVE)

## STATE: SETUP

After completing the seed scan the subagent should record its results:

Write("./tmp/scan-results.json", payload)

This violates the BINARY_INTERNAL constraint cited at
investigation w0b0v41zw H2 — relative-path Write calls from
background subagents are rejected by the Claude Code binary regex.
The check must surface this so the prompt source is corrected to
an absolute path under `~/hacker-bob-sessions/[domain]/`.
