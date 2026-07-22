"use strict";

const {
  resolvePhysicalVerdict,
} = require("../physical-verdict-runtime.js");

function verifyPhysicalVerdict(args) {
  const verdict = resolvePhysicalVerdict({
    target_domain: args.target_domain,
    asset_locator: args.asset_locator,
    verified_verdict_ref: args.verified_verdict_ref,
  });
  return JSON.stringify({
    version: 1,
    verdict,
  });
}

module.exports = Object.freeze({
  name: "bob_verify_physical_verdict",
  description:
    "Revalidate an already-recorded physical claim through Bob's server-owned PhysicalExperimentLedger projection. This tool accepts opaque references only, never invokes hardware, and fails closed until a production verdict resolver is installed.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
        minLength: 1,
        maxLength: 255,
        description: "Session authority key; not a base URL or physical asset identifier.",
      },
      asset_locator: {
        type: "string",
        pattern: "^[a-z][a-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$",
        description: "Opaque namespaced physical asset locator bound by the experiment ledger.",
      },
      verified_verdict_ref: {
        type: "string",
        pattern: "^physical-claim-verdict:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$",
        description: "Opaque claim-verdict reference already committed by the physical experiment ledger.",
      },
    },
    required: ["target_domain", "asset_locator", "verified_verdict_ref"],
    additionalProperties: false,
  },
  handler: verifyPhysicalVerdict,
  role_bundles: ["verifier", "evidence"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  required_session_axes: ["physical"],
  effect_surface: [],
});
