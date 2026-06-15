"use strict";

const {
  httpConfirm,
  ORACLE_KIND_VALUES,
  READ_ONLY_METHODS,
} = require("../offensive-confirmer.js");

module.exports = Object.freeze({
  name: "bob_http_confirm",
  description:
    "Trusted read-only confirmer for a routed surface. It mints a synthetic resource id and runs a same-endpoint unauth differential with read-only method/header/path allowlists that shrink, not eliminate, GET-side-effect risk, then reports the differential outcome as a diagnostic. It is NEGATIVE-ONLY: a resource-shaped response to a non-existent synthetic id is a catch-all / server-variance signal, not a sound per-object exposure, so this tool never mints a signed offensive-runs row. The sound signed-row producer (a real second-identity IDOR oracle) is a follow-up.",
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
    },
    required: ["target_domain", "surface_id", "oracle_kind", "path_template"],
    additionalProperties: false,
  },
  handler: httpConfirm,
  role_bundles: ["verifier", "evaluator-web", "evidence"],
  // Read-only against the TARGET, but it appends http-audit.jsonl records for its
  // probes (so the session request budget / circuit breaker counts confirm
  // traffic), so it is a session-artifact writer like bob_http_scan
  // (telemetry/role classification keys off this flag).
  mutating: true,
  global_preapproval: true,
  network_access: true,
  browser_access: false,
  scope_required: true,
  sensitive_output: true,
  session_artifacts_written: ["http-audit.jsonl"],
});
