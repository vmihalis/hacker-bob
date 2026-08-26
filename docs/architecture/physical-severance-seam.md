# Physical severance seam

This inventory is the post-N1, pre-DIP structural-debt baseline for the physical plane. It is generated from the checker’s current AST walk and is expected only to shrink in later hypergraph nodes.

## Census

- The walk holds **603 `.js` files** — **544 core, 59 plane** — and **3031 `require()` call sites**.
- **21** of those edges run core -> plane, from **8 distinct core files**.
- **0** call sites have a computed specifier.
- **17** edges leave the walk root; **7** of them run from core into a plane-named package.

24 inventoried rows = 21 policed core -> plane + 2 cross-package + 1 plane -> plane

| Adjudication | Count |
|---|---:|
| `composition_root` | 12 |
| `control_flow_core` | 5 |
| `plane_value_import` | 4 |
| `consolidatable_not_taken` | 0 |

Physical-only tools: 0

Shared tools that must remain core-visible: 0

**0** physical files touch a `paths` or lock-shaped dependency.

The live symbol-binding control cites `required_session_axes` at `mcp/tools/physical/record-physical-candidate-claim.js:312`.

One citation cannot use the symbol-anchored grammar: `mcp/core/session/session-authority.js:121` is an element inside an array literal, which declares no name for a symbol-anchored citation to bind to.

## Edge inventory

| # | Edge | Baseline rationale |
|---:|---|---|
| 10 | `mcp/core/capability/capability-packs.js:10` -> `../../domains/physical/physical-capability-manifest.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 11 | `mcp/core/capability/capability-packs.js:6` -> `../../domains/physical/physical-surface-transition.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 12 | `mcp/core/executed-evidence-registry.js:12` -> `../domains/physical/physical-experiment-contract.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 13 | `mcp/core/executed-evidence-registry.js:18` -> `../domains/physical/physical-surface-transition.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 14 | `mcp/core/finding-contracts.js:729` -> `../domains/physical/physical-finding-record-adapter.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 15 | `mcp/core/frontier/frontier-readiness.js:288` -> `../../domains/physical/physical-campaign-coordinator.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 16 | `mcp/core/frontier/surface-graph.js:30` -> `../../domains/physical/physical-surface-transition.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 17 | `mcp/core/session/lifecycle-gates.js:605` -> `../../domains/physical/physical-campaign-coordinator.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 18 | `mcp/core/session/session-authority.js:44` -> `../../domains/physical/physical-session-journal.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 21 | `mcp/tools/index.js:71` -> `./physical/credential-acquire.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 22 | `mcp/tools/index.js:73` -> `./physical/credential-emulate.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 23 | `mcp/tools/index.js:72` -> `./physical/credential-recover.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 24 | `mcp/tools/index.js:74` -> `./physical/credential-write.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 25 | `mcp/tools/index.js:29` -> `./physical/init-physical-session.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 26 | `mcp/tools/index.js:70` -> `./physical/physical-observe.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 27 | `mcp/tools/index.js:75` -> `./physical/protocol-transceive.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 28 | `mcp/tools/index.js:30` -> `./physical/query-instrument-capabilities.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 29 | `mcp/tools/index.js:24` -> `./physical/record-physical-candidate-claim.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 30 | `mcp/tools/index.js:76` -> `./physical/rf-trace.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 31 | `mcp/tools/index.js:69` -> `./physical/verify-physical-candidate-claim.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 32 | `mcp/tools/index.js:68` -> `./physical/verify-physical-verdict.js` | Existing pre-DIP core-to-physical dependency; recorded so new edges fail closed. |
| 33 | `mcp/core/waves/graph-scheduler.js:53` -> `../../../packages/bob-instrument-broker/lib/resource-reservations.js` | Cross-package resource-reservation seam outside the in-root plane partition. |
| 34 | `mcp/tools/prepare-node.js:96` -> `../../packages/bob-instrument-broker/lib/resource-reservations.js` | Cross-package resource-reservation seam outside the in-root plane partition. |
| 35 | `mcp/tools/physical/protocol-transceive.js:3` -> `./physical-technique-tool.js` | Plane-to-plane composition edge, recorded to keep the inventory census complete. |
