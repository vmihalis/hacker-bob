# Physical severance seam

This inventory is the post-N1, pre-DIP structural-debt baseline for the physical plane. It is generated from the checker’s current AST walk and is expected only to shrink in later hypergraph nodes.

## Census

- The walk holds **544 `.js` files** — **487 core, 57 plane** — and **2798 `require()` call sites**.
- **32** of those edges run core -> plane, from **15 distinct core files**.
- **0** call sites have a computed specifier.
- **14** edges leave the walk root; **5** of them run from core into a plane-named package.

35 inventoried rows = 32 policed core -> plane + 2 cross-package + 1 plane -> plane

| Adjudication | Count |
|---|---:|
| `composition_root` | 12 |
| `control_flow_core` | 5 |
| `plane_value_import` | 15 |
| `consolidatable_not_taken` | 0 |

Physical-only tools: 0

Shared tools that must remain core-visible: 0

**0** physical files touch a `paths` or lock-shaped dependency.

The live symbol-binding control cites `required_session_axes` at `mcp/tools/physical/record-physical-candidate-claim.js:312`.

One citation cannot use the symbol-anchored grammar: `mcp/core/session/session-authority.js:121` is an element inside an array literal, which declares no name for a symbol-anchored citation to bind to.

## Edge inventory

| # | Edge | Baseline rationale |
|---:|---|---|
| 1 | `mcp/core/capability/capability-pack-composition-adapters.js:21` -> `../../domains/physical/physical-capability-manifest.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 2 | `mcp/core/capability/capability-pack-composition-adapters.js:40` -> `../../domains/physical/physical-experiment-contract.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 3 | `mcp/core/capability/capability-pack-composition-adapters.js:18` -> `../../domains/physical/physical-finding-contract.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 4 | `mcp/core/capability/capability-pack-composition-adapters.js:24` -> `../../domains/physical/physical-surface-transition.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 5 | `mcp/core/capability/capability-pack-evidence-adapters.js:19` -> `../../domains/physical/capability-pack-physical-artifacts.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 6 | `mcp/core/capability/capability-pack-grade-adapters.js:23` -> `../../domains/physical/physical-capability-consumers.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 7 | `mcp/core/capability/capability-pack-grade-adapters.js:26` -> `../../domains/physical/physical-claim-lifecycle-adapter.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 8 | `mcp/core/capability/capability-pack-proof-adapters.js:17` -> `../../domains/physical/capability-pack-physical-artifacts.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 9 | `mcp/core/capability/capability-pack-report-adapters.js:20` -> `../../domains/physical/capability-pack-physical-artifacts.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 10 | `mcp/core/capability/capability-packs.js:10` -> `../../domains/physical/physical-capability-manifest.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 11 | `mcp/core/capability/capability-packs.js:6` -> `../../domains/physical/physical-surface-transition.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 12 | `mcp/core/executed-evidence-registry.js:12` -> `../domains/physical/physical-experiment-contract.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 13 | `mcp/core/executed-evidence-registry.js:18` -> `../domains/physical/physical-surface-transition.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 14 | `mcp/core/finding-contracts.js:654` -> `../domains/physical/physical-finding-record-adapter.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 15 | `mcp/core/frontier/frontier-readiness.js:288` -> `../../domains/physical/physical-campaign-coordinator.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 16 | `mcp/core/frontier/surface-graph.js:30` -> `../../domains/physical/physical-surface-transition.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 17 | `mcp/core/session/lifecycle-gates.js:604` -> `../../domains/physical/physical-campaign-coordinator.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 18 | `mcp/core/session/session-authority.js:41` -> `../../domains/physical/physical-session-journal.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 19 | `mcp/lib/physical-resource-contract.js:11` -> `../domains/physical/physical-quantities.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 20 | `mcp/lib/physical-session-identity.js:5` -> `../domains/physical/physical-quantities.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 21 | `mcp/tools/index.js:227` -> `./physical/credential-acquire.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 22 | `mcp/tools/index.js:229` -> `./physical/credential-emulate.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 23 | `mcp/tools/index.js:228` -> `./physical/credential-recover.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 24 | `mcp/tools/index.js:230` -> `./physical/credential-write.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 25 | `mcp/tools/index.js:62` -> `./physical/init-physical-session.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 26 | `mcp/tools/index.js:226` -> `./physical/physical-observe.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 27 | `mcp/tools/index.js:231` -> `./physical/protocol-transceive.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 28 | `mcp/tools/index.js:63` -> `./physical/query-instrument-capabilities.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 29 | `mcp/tools/index.js:39` -> `./physical/record-physical-candidate-claim.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 30 | `mcp/tools/index.js:232` -> `./physical/rf-trace.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 31 | `mcp/tools/index.js:220` -> `./physical/verify-physical-candidate-claim.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 32 | `mcp/tools/index.js:219` -> `./physical/verify-physical-verdict.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 33 | `mcp/core/waves/graph-scheduler.js:53` -> `../../../packages/bob-instrument-broker/lib/resource-reservations.js` | Cross-package resource-reservation seam outside the in-root plane partition. |
| 34 | `mcp/tools/prepare-node.js:96` -> `../../packages/bob-instrument-broker/lib/resource-reservations.js` | Cross-package resource-reservation seam outside the in-root plane partition. |
| 35 | `mcp/tools/physical/protocol-transceive.js:3` -> `./physical-technique-tool.js` | Plane-to-plane composition edge, recorded to keep the inventory census complete. |
