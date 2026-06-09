"use strict";

const {
  PROOF_BUNDLE_KINDS,
  writeProofBundles,
} = require("../proof-bundle.js");
const {
  DIFFERENTIAL_CONTROL_KINDS,
  DIFFERENTIAL_VERDICTS,
} = require("../evidence.js");
const { wrapWriteTool } = require("./_write-base.js");

module.exports = wrapWriteTool({
  name: "bob_write_proof_bundle",
  aliases: ["bounty_write_proof_bundle"],
  description:
    "Write machine-checkable proof bundles for final reportable findings to authoritative JSON plus a markdown mirror. Stores replay, invariant, or C10 differential run handles; never executes proof commands.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      packs: {
        type: "array",
        items: {
          type: "object",
          properties: {
            finding_id: { type: "string", pattern: "^F-[1-9][0-9]*$" },
            bundle_kind: { type: "string", enum: PROOF_BUNDLE_KINDS },
            bundle_hash: { type: "string", pattern: "^[0-9a-fA-F]{64}$" },
            artifacts: {
              type: "array",
              minItems: 1,
              items: {
                type: "object",
                properties: {
                  replay_command: {
                    type: "array",
                    minItems: 1,
                    maxItems: 64,
                    items: { type: "string", minLength: 1, maxLength: 2048 },
                  },
                  run_id: { type: "string" },
                  run_hash: { type: "string", pattern: "^[0-9a-fA-F]{64}$" },
                  replay_summary: { type: "string", maxLength: 2000 },
                  snippet: { type: "string", maxLength: 4000 },
                  finding_id: { type: "string", pattern: "^F-[1-9][0-9]*$" },
                  control_kind: { type: "string", enum: DIFFERENTIAL_CONTROL_KINDS },
                  vuln_run_id: { type: "string" },
                  control_run_id: { type: "string" },
                  control_ref: { type: "string" },
                  vuln_fired: { type: "boolean" },
                  control_fired: { type: "boolean" },
                  verdict: { type: "string", enum: DIFFERENTIAL_VERDICTS },
                  control_summary: { type: "string" },
                  differential: {
                    type: "object",
                    properties: {
                      control_kind: { type: "string", enum: DIFFERENTIAL_CONTROL_KINDS },
                      vuln_run_id: { type: "string" },
                      control_run_id: { type: "string" },
                      control_ref: { type: "string" },
                      vuln_fired: { type: "boolean" },
                      control_fired: { type: "boolean" },
                      verdict: { type: "string", enum: DIFFERENTIAL_VERDICTS },
                      control_summary: { type: "string" },
                    },
                    required: [
                      "control_kind",
                      "vuln_run_id",
                      "control_run_id",
                      "control_ref",
                      "vuln_fired",
                      "control_fired",
                      "verdict",
                      "control_summary",
                    ],
                    additionalProperties: false,
                  },
                },
                additionalProperties: false,
              },
            },
          },
          required: ["finding_id", "bundle_kind", "artifacts"],
          additionalProperties: false,
        },
      },
    },
    required: ["target_domain", "packs"],
  },
  handler: writeProofBundles,
  // Keep role-bundle access narrow; final-verifier gets an explicit role-model grant.
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["proof-bundles.json", "proof-bundles.md", "verification-manifest.json"],
});
