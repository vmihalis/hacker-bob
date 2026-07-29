# Composition Floor Convergence

The composition edge floor is defined over transition edges proposed through the MCP ledger. An edge is the tuple `(from_surface, to_surface, transition_kind)`, represented by `transitionEdgeToken(from, to, kind)`. An edge-cell is `(edgeToken, bug_class)`, represented by `transitionCellKey(edgeToken, bugClass)` with an empty auth axis.

For one target domain, define:

`Phi(pass) = |uncovered edge-cells|`

The set counted by `Phi` is finite under the current invariant:

- The transition-proposal ledger is finite at the start of a materialization sequence.
- Each proposal contributes one deterministic edge token.
- `TRANSITION_BUG_CLASS_AXIS[kind]` is a fixed finite axis.
- `max_spawn_children` caps the per-edge fan-out emitted by the planner.

`Phi` is non-increasing across materialization passes. The transition-cell planner prunes any planning key already covered for the edge. A terminal `tested` row from `logCellCoverage` removes that edge-cell from later emissions. The shared stuck-cell backstop in `emitOrAutoBlock` records `blocked` after the configured emission threshold; `blocked` is also terminal coverage for the same prune path. No pass removes a terminal coverage row, so an edge-cell that leaves `Phi` cannot re-enter it.

If an evaluator writes no terminal coverage row, the edge-cell can be re-emitted, but that stall is bounded by the shared stuck-cell threshold. The emission count is MCP-owned: each re-emission is a real `cell_proposed` event, and the backstop writes a real terminal coverage row instead of trusting an agent-attested flag.

The convergence bound for the current edge space is:

`Phi(0) + STUCK_CELL_EMISSION_THRESHOLD * |edges|`

This is a hard bound on ledger passes, not a timer. Since `Phi` is a non-negative integer, terminal coverage and backstop coverage monotonically shrink the uncovered set until a pass emits zero transition cells. At that point the handler reports `floor_at_fixpoint === true`.

A real terminal row and a backstop row remain distinguishable. A genuinely tested edge-cell has `status: "tested"` and is pruned without appearing in `auto_blocked_cells`. A worst-case edge-cell that never receives terminal evaluator coverage is recorded as `status: "blocked"` by the backstop and appears in `auto_blocked_cells` with its emission count.

This proof depends on the reachable edge set staying finite during the convergence sequence. If a future leaked-identifier axis expands the edge space without bound per pass, this proof does not hold. The composition floor must not ship that axis without a new proof and executable test for the expanded measure.
