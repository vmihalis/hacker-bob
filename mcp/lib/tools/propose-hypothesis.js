"use strict";

// chain+evaluator-shared justified: chain-builder needs graph mutation/query authority via the chain bundle (rev 4.1 defect 3 absorption); single-spawner topology preserved per Y.9 chain-bundle audit
//
// Plane X Cycle X.1 — bob_propose_hypothesis.
//
// Records a TaskGraph Hypothesis-node proposal. Reuses the existing
// observation.recorded ledger kind with payload.kind: "hypothesis_proposed"
// per X-P8. The hypothesis_statement is prose-bounded at append time
// (X-P9 / X.1 step 2). Allowed bundles per X-D10 are evaluator + operator;
// in v1 the operator role bundle is realized as `orchestrator` (the only
// bundle wired to the operator-facing slash command at this point in the
// plane). X.4 (`bob_attach_contract`) rewires the bundle list explicitly
// when the operator-vs-orchestrator distinction is required.

const {
  appendHypothesisProposal,
  HYPOTHESIS_STATEMENT_MAX_CHARS,
} = require("../task-graph-events.js");
const {
  scheduleMaterialization,
} = require("../frontier-materialize-debounce.js");

function handler(args) {
  const event = appendHypothesisProposal(args || {});
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
  name: "bob_propose_hypothesis",
  description:
    "Propose a TaskGraph Hypothesis node. Appends an observation.recorded "
    + "frontier event with payload.kind: \"hypothesis_proposed\". The "
    + "hypothesis_statement is capped at "
    + `${HYPOTHESIS_STATEMENT_MAX_CHARS} characters at append time per X-P9 `
    + "(over → structured prose_too_long error). The Hypothesis stays "
    + "Contract-less until bob_attach_contract (X.4) attaches one and "
    + "binds the dispatcher-ready Contract hash to the node.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      hypothesis_statement: {
        type: "string",
        description:
          `Free-text statement of the conjecture under test, capped at ${HYPOTHESIS_STATEMENT_MAX_CHARS} characters. `
          + "Phrase as an actionable security claim (\"A can do B by ...\"); avoid speculative language.",
      },
      surface_refs: {
        type: "array",
        minItems: 1,
        items: { type: "string" },
        description:
          "Surface IDs the hypothesis is grounded in. At least one is required so the "
          + "X.2 materializer can fold the node onto its adjacent surfaces.",
      },
      suggested_contract: {
        type: "object",
        description:
          "Optional draft Contract (invariants/witnesses/production_paths). Treated as "
          + "advisory: X.4's bob_attach_contract revalidates and binds the hash before dispatch.",
      },
      proposal_id: {
        type: "string",
        description:
          "Optional caller-supplied proposal identifier (e.g. HP-<slug>). When omitted, the materializer mints the canonical TG-<...> node id.",
      },
      ts: { type: "string" },
      source: { type: "object" },
      actor: { type: "string" },
    },
    required: ["target_domain", "hypothesis_statement", "surface_refs"],
  },
  handler,
  // X-D10: Hypothesis proposal is allowed for operator OR evaluator. In
  // the v1 bundle taxonomy that maps to orchestrator + evaluator-shared.
  // Y.11 (rev 4.1 defect 3) extends with "chain" so chain-builder can
  // propose new chain-attempt nodes via the graph apparatus rather than
  // hand-writing chain-attempts.jsonl. The chain bundle grants tool
  // access, not dispatch authority — Y-P8 single-spawner topology is
  // preserved by the Y.9 chain-bundle audit + single-spawner check.
  role_bundles: ["orchestrator", "evaluator-shared", "chain"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["frontier-events.jsonl"],
});
