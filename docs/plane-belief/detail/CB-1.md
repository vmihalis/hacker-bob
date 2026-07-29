# CB-1 -- Mechanism Projection Over Surface Graph

## Node

- `id`: `CB-1`
- `action`: `extend_existing`
- `anchor`: `mcp/lib/surface-graph.js`; `mcp/lib/surface-graph-builder.js`;
  `mcp/lib/auth-differential.js`; `mcp/lib/tools/evm-role-table.js`;
  `mcp/lib/chain-state-tree.js`
- `status`: `done`

## Contract

Mechanism facts are a projection over the existing content-addressed
`surface-graph.jsonl` store. CB-1 adds principal, credential, policy gate,
effect, and intervention node types without creating `mechanism-graph.json` or a
second query authority.

## Implementation

- `mcp/lib/surface-graph.js` extends the graph taxonomy with mechanism node and
  edge types while preserving the existing `edge_hash` identity.
- `mcp/lib/surface-graph-builder.js` projects:
  - schema `claimed_auth` into `endpoint -> policy_gate -> credential`;
  - auth-differential rows into principal, credential, intervention, effect, and
    IDOR-like `principal -> policy_gate -> effect` paths for
    `unauth_succeeds_where_auth_blocked`;
  - optional EVM role-table matrices from `evm-role-table-results.json` into
    `principal -> credential` and `policy_gate -> credential` edges;
  - chain-tree outcomes into `intervention -> effect` observations.
- `bob_query_surface_graph` adds bounded `mode: "mechanism"` over the same
  `surface-graph.jsonl` edges.

## Findings

- Resolved during review: `bob_evm_role_table` exposes matrices, but the graph
  builder had no source artifact path to fold them. Added optional
  `evm-role-table-results.json` projection via `evmRoleTableResultsPath()`; it
  still writes only to `surface-graph.jsonl`.

## Review Evidence

Engineering review passed:

- `node --test test/surface-graph.test.js test/surface-graph-builder.test.js`
- `npm run check:syntax`
- `npm run check:stigmergy-coherence`
- `npm run test:mcp`
- `npm run test:prompts`
- `verify-CB-1-mechanism-projection: PASS`
- `verify-CB-1-no-mechanism-graph-store-in-runtime: PASS`

No field review is required for this node.
