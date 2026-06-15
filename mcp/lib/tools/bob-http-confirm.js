"use strict";

const {
  httpConfirm,
  ORACLE_KIND_VALUES,
  READ_ONLY_METHODS,
} = require("../offensive-confirmer.js");
const { REPLAY_CONTEXT_SCHEMA } = require("./replay-context-schema.js");

module.exports = Object.freeze({
  name: "bob_http_confirm",
  description:
    "Trusted read-only confirmer for a routed surface. It mints a synthetic resource id, runs a same-endpoint unauth differential with read-only method/header/path allowlists that shrink, not eliminate, GET-side-effect risk, and writes a MAC-signed offensive-runs.jsonl row only when the low-severity oracle proves a missing auth gate.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: { type: "string" },
      oracle_kind: { type: "string", enum: [...ORACLE_KIND_VALUES] },
      path_template: {
        type: "string",
        description: "Absolute path template under the routed surface's recorded endpoint origin, containing exactly one server-substituted {id} path slot, for example /api/accounts/{id}. No URL, finding_id, request body, resource id, severity, or arbitrary headers are accepted.",
      },
      method: { type: "string", enum: [...READ_ONLY_METHODS] },
      replay_context: REPLAY_CONTEXT_SCHEMA,
    },
    required: ["target_domain", "surface_id", "oracle_kind", "path_template"],
    additionalProperties: false,
  },
  handler: httpConfirm,
  role_bundles: ["verifier", "evaluator-web", "evidence"],
  // Read-only against the TARGET, but it appends the audit-graded
  // offensive-runs.jsonl proof ledger + capture artifacts, so it is a
  // session-artifact writer like other producers (telemetry/role classification
  // keys off this flag).
  mutating: true,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["offensive-runs.jsonl", "offensive-runs/"],
});
