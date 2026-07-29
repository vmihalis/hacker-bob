"use strict";

const {
  MAX_QUERY_LIMIT,
  queryInstalledInstrumentCapabilities,
} = require("../instrument-capabilities.js");

function queryInstrumentCapabilities(args) {
  return JSON.stringify(queryInstalledInstrumentCapabilities(args));
}

module.exports = Object.freeze({
  name: "bob_query_instrument_capabilities",
  description:
    "Query Bob's bounded, provider-neutral physical instrument capability index. "
    + "Returns normalized operation/technique/parameter variants and report-safe "
    + "availability reasons only; it never returns firmware command IDs, proof "
    + "bodies, signatures, raw bytes, or execution authority. Fails closed until "
    + "an enrolled production index is installed.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
        minLength: 1,
        maxLength: 191,
        pattern: "^[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$",
        description: "Physical session authority key, not a device or target identifier.",
      },
      instrument_ref: {
        type: "string",
        pattern: "^instrument:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$",
        description: "Opaque enrolled instrument reference.",
      },
      operation_id: {
        type: "string",
        pattern: "^[a-z][a-z0-9._-]{0,127}$",
      },
      technique_id: {
        type: "string",
        pattern: "^[a-z][a-z0-9._-]{0,127}$",
      },
      parameter_selector_id: {
        type: "string",
        pattern: "^[a-z][a-z0-9._-]{0,127}$",
      },
      availability: {
        type: "string",
        enum: ["all", "available", "unavailable"],
        default: "all",
      },
      cursor: {
        type: "string",
        pattern: "^capability-cursor:v1:[a-f0-9]{64}:(0|[1-9][0-9]*)$",
      },
      limit: {
        type: "integer",
        minimum: 1,
        maximum: MAX_QUERY_LIMIT,
        default: 20,
      },
    },
    required: ["target_domain", "instrument_ref"],
    additionalProperties: false,
  },
  handler: queryInstrumentCapabilities,
  role_bundles: ["evaluator-physical", "orchestrator"],
  mutating: false,
  global_preapproval: true,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  required_session_axes: ["physical"],
  effect_surface: ["instrument.observe"],
});
