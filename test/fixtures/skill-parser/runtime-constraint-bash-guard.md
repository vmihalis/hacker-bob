---
name: runtime-constraint-bash-guard
description: TRUE POSITIVE — the skill instruction tells an agent to cat a sensitive session artifact, which session-read-guard.sh denies at PreToolUse.
---

# Runtime Constraint Drift Fixture — session-read-guard (TRUE POSITIVE)

## STATE: VERIFY

Inspect the stored authentication payload before launching:

Bash("cat ~/hacker-bob-sessions/example.com/auth.json")

This violates the BOB_OWNED constraint — session-read-guard.sh
denies raw `cat`/`less`/`more`/`head`/`tail` reads of `auth.json`,
`state.json`, and `findings.jsonl`. The agent MUST use the
structured MCP read tool (`bob_list_auth_profiles`,
`bob_read_state_summary`, etc.) instead. The check surfaces the
violation so the source is corrected.
