---
name: drift-stale-schema-ref
description: D2 violation fixture — an @schema_ref directive cites a tool that is NOT in TOOL_REGISTRY.
---

# Drift Fixture — D2 Stale @schema_ref (TRUE POSITIVE)

## STATE: REPORT

Call `bob_compose_report({ target_domain, sections })` to publish.

<!-- @schema_ref: bob_compose_report -->
<!-- @schema_ref: bob_write_phantom_tool_that_was_retired -->
