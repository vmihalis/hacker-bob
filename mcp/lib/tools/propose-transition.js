"use strict";

// chain+evaluator-shared justified: chain-builder needs graph mutation/query authority via the chain bundle (rev 4.1 defect 3 absorption); single-spawner topology preserved per Y.9 chain-bundle audit
//
// Plane X Cycle X.1 / X.3 — bob_propose_transition.
//
// Records a TaskGraph Transition-node proposal. Reuses observation.recorded
// with payload.kind: "transition_proposed" per X-P8. The trust_assumption
// prose is bounded at append time (X-P9 / X.1 step 2). The transition_kind
// is restricted to the X-D3 closed enum (identity_propagation,
// value_movement, trust_handoff, state_dependency, oracle_dependency,
// message_passing). X.3 promotes "transition" to a first-class surface kind
// (SURFACE_KIND_VALUES in mcp/lib/constants.js) and wires endpoint-existence
// validation into this handler: both from_surface and to_surface must already
// be known to the session's materialized surface-index before a transition
// can be proposed. The check prevents a wave of bogus transitions referencing
// surfaces that have never been observed.

const {
  appendTransitionProposal,
  TRANSITION_KIND_VALUES,
  TRANSITION_TRUST_ASSUMPTION_MAX_CHARS,
} = require("../task-graph-events.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");
const {
  currentSurfaces,
} = require("../frontier-projections.js");

function knownSurfaceIds(targetDomain) {
  const projection = currentSurfaces(targetDomain);
  const ids = new Set();
  for (const surface of projection.surfaces) {
    if (surface == null || typeof surface !== "object") continue;
    const id = typeof surface.id === "string" ? surface.id.trim() : "";
    if (id) ids.add(id);
  }
  return ids;
}

function assertEndpointExists(known, value, fieldName) {
  if (known.has(value)) return;
  const err = new Error(
    `unknown_surface: ${fieldName} "${value}" is not in the session's surface-index; observe it (or promote a lead) before proposing a transition`,
  );
  err.code = "unknown_surface";
  err.details = {
    field: fieldName,
    surface_id: value,
  };
  throw err;
}

function handler(args) {
  const input = args || {};
  // X.3 Do step 3: both endpoints must exist in the session's surface-index
  // before a transition can be proposed. We trim the inputs the same way
  // appendTransitionProposal does so the check matches the persisted payload.
  const targetDomain = typeof input.target_domain === "string" ? input.target_domain.trim() : "";
  const fromSurface = typeof input.from_surface === "string" ? input.from_surface.trim() : "";
  const toSurface = typeof input.to_surface === "string" ? input.to_surface.trim() : "";
  if (targetDomain && fromSurface && toSurface) {
    const known = knownSurfaceIds(targetDomain);
    assertEndpointExists(known, fromSurface, "from_surface");
    assertEndpointExists(known, toSurface, "to_surface");
  }

  const event = appendTransitionProposal(input);
  try {
    scheduleMaterialization(event.target_domain);
  } catch {
    // Materialization debounce is best-effort; do not regress the append.
  }
  return JSON.stringify({
    version: 1,
    appended: true,
    event_id: event.event_id,
    event_hash: event.event_hash,
    kind: event.kind,
    payload_kind: event.payload && event.payload.kind,
    target_domain: event.target_domain,
  });
}

module.exports = Object.freeze({
  name: "bob_propose_transition",
  description:
    "Propose a TaskGraph Transition node bridging two surfaces. Appends an "
    + "observation.recorded frontier event with payload.kind: \"transition_proposed\". "
    + "trust_assumption is capped at "
    + `${TRANSITION_TRUST_ASSUMPTION_MAX_CHARS} characters at append time per X-P9 `
    + "(over → structured prose_too_long error). The transition_kind must be in "
    + "the X-D3 closed enum so the cross-stack brief composer (X.11) can "
    + "select the right hunting vocabulary.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      from_surface: {
        type: "string",
        description: "Origin surface_id of the proposed transition (e.g. a web auth endpoint).",
      },
      to_surface: {
        type: "string",
        description: "Destination surface_id of the proposed transition (e.g. an EVM contract entrypoint).",
      },
      kind: {
        type: "string",
        enum: [...TRANSITION_KIND_VALUES],
        description: "Transition kind from the X-D3 closed enum.",
      },
      trust_assumption: {
        type: "string",
        description:
          `Statement of the trust hop the transition implies, capped at ${TRANSITION_TRUST_ASSUMPTION_MAX_CHARS} characters. `
          + "Phrase as a falsifiable claim (\"X is recovered server-side and trusted on-chain\").",
      },
      evidence_refs: {
        type: "array",
        items: { type: "string" },
        description: "Optional artifact_ref strings backing the proposal (e.g. http_record:R7).",
      },
      proposal_id: {
        type: "string",
        description: "Optional caller-supplied proposal identifier (e.g. TP-<slug>).",
      },
      ts: { type: "string" },
      source: { type: "object" },
      actor: { type: "string" },
    },
    required: [
      "target_domain",
      "from_surface",
      "to_surface",
      "kind",
      "trust_assumption",
    ],
  },
  handler,
  // X-D10: Hypothesis proposal is allowed for operator OR evaluator;
  // transition proposal mirrors that surface in v1. Y.11 (rev 4.1
  // defect 3) extends with "chain" so chain-builder can propose
  // cross-stack transitions via the graph apparatus. The chain bundle
  // grants tool access, not dispatch authority — Y-P8 single-spawner
  // topology is preserved by the Y.9 chain-bundle audit + single-spawner
  // check.
  role_bundles: ["orchestrator", "evaluator-shared", "chain"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
