---
name: drift-unknown-write-tool
description: D3 violation fixture — a STATE block cites a bob_write_* token that does NOT exist in TOOL_REGISTRY.
---

# Drift Fixture — D3 Unknown Write Tool (TRUE POSITIVE)

## STATE: SETUP

Call `bob_write_typo_handoff({ target_domain })` to persist —
this token has the canonical prefix but does NOT exist in
TOOL_REGISTRY, so D3 fires.
