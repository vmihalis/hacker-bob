---
name: drift-missing-schema-ref
description: D1 violation fixture — a STATE block cites a write tool with NO matching @schema_ref directive.
---

# Drift Fixture — D1 Missing @schema_ref (TRUE POSITIVE)

## STATE: REPORT

Call `bob_compose_report({ target_domain, sections })` to publish the report.
This block contains the write-tool token but no `@schema_ref` directive ->
D1 structural containment fires.
