---
name: non-state-section
description: TRUE NEGATIVE — write-tool tokens appear inside non-STATE sections (Hard Rules, anti-pattern callouts) and are correctly ignored by D1.
---

# Non-STATE Section Fixture (TRUE NEGATIVE)

## Hard Rules

- The orchestrator must never call `bob_write_wave_handoff` directly — handoffs flow only through evaluator agents.
- The orchestrator must never call `bob_write_chain_attempt` — chain attempts flow only through chain-builder.

## Asset Map

- `bob_write_evidence_packs` -> `evidence-packs.json`
- `bob_write_chain_attempt` -> `chain-attempts.jsonl`

These are anti-pattern callouts and asset-map references, not STATE
dispatch sites. The check only enforces structural containment
inside STATE blocks, so this fixture must produce zero violations.
