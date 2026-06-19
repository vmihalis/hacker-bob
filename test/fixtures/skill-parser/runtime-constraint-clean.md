---
name: runtime-constraint-clean
description: TRUE NEGATIVE — the skill exclusively uses MCP read tools and absolute Write paths, so neither BINARY_INTERNAL nor BOB_OWNED constraints fire.
---

# Runtime Constraint Clean Fixture (TRUE NEGATIVE)

## STATE: SETUP

Inspect the stored authentication context: call `bob_list_auth_profiles({ target_domain })`.

If a Write is needed, use an absolute path under the session root,
e.g. `Write("/Users/operator/staging/scratch.json", payload)`.
The binary-internal subagent Write regex rejects relative paths
from background spawns (investigation w0b0v41zw H2), so the
prompt must spell the absolute path explicitly.
