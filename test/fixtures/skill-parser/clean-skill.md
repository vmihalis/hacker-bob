---
name: clean-fixture
description: A canonical clean skill — every write-tool token is matched by an @schema_ref directive in the same STATE block.
---

# Clean Skill Fixture (TRUE NEGATIVE)

This fixture exercises the canonical happy path. Every dimension passes:
- D1 (structural containment): every write-tool token is bound by an `@schema_ref` directive in the same STATE block.
- D2 (registry coherence): every directive cites a real TOOL_REGISTRY entry.
- D3 (token registry coherence): every cited write-tool resolves.

## STATE: SETUP

Call `bob_init_session({ target_domain, target_url })` to seed.

## STATE: REPORT

Call `bob_compose_report({ target_domain, sections })` and `bob_amend_report({ target_domain, amendment })` to publish.
Use `bob_write_chain_rollup({ target_domain, chain_id })` for chain rollups.

<!-- @schema_ref: bob_compose_report -->
<!-- @schema_ref: bob_amend_report -->
<!-- @schema_ref: bob_write_chain_rollup -->
