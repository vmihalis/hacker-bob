"use strict";

// Plane T Cycle T.8 — operator-facing toggle for adaptive pack curation.
//
// Per Pact T-D5 ("adaptive curation is opt-in") and Pact T-P5 ("telemetry as
// feedback"), the brief's CLI-tool relevance scoring stays in its T.3 form
// unless an operator explicitly persists `adaptive_curation: true` for a
// target_domain. This tool is the persistence path: writes
// `~/hacker-bob-sessions/<domain>/pack-telemetry-config.json` and returns the
// normalized config that subsequent brief assemblies will read.
//
// Role bundle: orchestrator-only. Adaptive curation modifies the rendered
// tool surface a hunter sees — it must not be flipped by an evaluator or
// surface-discovery role.

const { assertNonEmptyString } = require("../validation.js");
const {
  readPackTelemetryConfig,
  writePackTelemetryConfig,
} = require("../pack-telemetry.js");

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const configInput = args.config;
  if (!configInput || typeof configInput !== "object" || Array.isArray(configInput)) {
    throw new Error("config must be a plain object");
  }
  const normalized = writePackTelemetryConfig(domain, configInput);
  const persisted = readPackTelemetryConfig(domain);
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    pack_telemetry_config: persisted,
    requested: normalized,
  });
}

module.exports = Object.freeze({
  name: "bob_set_pack_telemetry_config",
  description:
    "Persist an operator-supplied pack-telemetry config for a target_domain to " +
    "~/hacker-bob-sessions/<domain>/pack-telemetry-config.json. Controls Plane T " +
    "Cycle T.8 adaptive CLI-tool pack curation. Schema: " +
    "{ adaptive_curation: boolean, window_ms?: number, correlation_window_ms?: " +
    "number, baseline_rate?: number, demotion_floor?: number, " +
    "min_invocation_count?: number }. When adaptive_curation is false (default), " +
    "the brief's CLI-tool scoring collapses to its T.3 form deterministically. " +
    "When true, telemetry_promotion = claim_correlation - baseline_rate enters " +
    "the relevance score, and packs whose invocation_rate * claim_correlation " +
    "falls below demotion_floor (with invocation_count >= min_invocation_count) " +
    "are demoted with a -1.0 score penalty.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      config: {
        type: "object",
        description:
          "Pack-telemetry config object. adaptive_curation is required; the " +
          "numeric overrides fall back to module defaults.",
        properties: {
          adaptive_curation: { type: "boolean" },
          window_ms: { type: "number" },
          correlation_window_ms: { type: "number" },
          baseline_rate: { type: "number" },
          demotion_floor: { type: "number" },
          min_invocation_count: { type: "integer" },
        },
        required: ["adaptive_curation"],
      },
    },
    required: ["target_domain", "config"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["pack-telemetry-config.json"],
});
