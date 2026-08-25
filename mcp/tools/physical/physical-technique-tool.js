"use strict";

const {
  executePhysicalTechnique,
} = require("../../domains/physical/physical-technique-runtime.js");

const DIGEST_PATTERN = "^[a-f0-9]{64}$";
const EXECUTION_REF_PATTERN = "^physical-execution:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$";
const CELL_REF_PATTERN = "^physical-cell:[A-Za-z0-9][A-Za-z0-9._:@-]{0,190}$";

const FAMILY_SPECS = Object.freeze({
  physical_observe: Object.freeze({
    name: "bob_physical_observe",
    description:
      "Execute one pre-issued provider-neutral physical discovery/classification experiment through Bob's production broker composition root. The opaque reference already binds the exact technique, authority, controls, resource reservation, RF bounds, restoration, and evidence plan; this tool accepts no provider command, frame, device path, or credential bytes.",
    capability_id: "physical.observe",
    effect_surface: Object.freeze(["target.transmit"]),
  }),
  credential_acquire: Object.freeze({
    name: "bob_credential_acquire",
    description:
      "Execute one pre-issued provider-neutral credential acquisition experiment into opaque vault custody. Plain and authenticated reads, persistent counters, lockout risk, irreversible effects, resource bounds, and cleanup are fixed by the server-owned execution reference; raw credential or secret material is never returned.",
    capability_id: "physical.credential.acquire",
    effect_surface: Object.freeze(["target.transmit", "target.mutate", "target.destroy"]),
  }),
  credential_recover: Object.freeze({
    name: "bob_credential_recover",
    description:
      "Execute one pre-issued provider-neutral secret-recovery experiment using allowlisted vault-side handle transforms. The server-owned plan fixes the recovery method, prerequisites, worst-case effects, host-tool provenance, controls, and cleanup; keys, nonces, traces, and credential bytes remain opaque.",
    capability_id: "physical.credential.recover",
    effect_surface: Object.freeze([
      "target.transmit",
      "target.present",
      "target.mutate",
      "target.destroy",
    ]),
  }),
  credential_emulate: Object.freeze({
    name: "bob_credential_emulate",
    description:
      "Execute one pre-issued provider-neutral credential emulation/replay experiment under a bounded lease. The exact staged representation, verifier/control assets, activation window, teardown, restoration, and evidence bindings are resolved server-side; no persistent unattended emulation or credential bytes are exposed.",
    capability_id: "physical.credential.emulate",
    effect_surface: Object.freeze(["instrument.configure", "target.present"]),
  }),
  credential_write: Object.freeze({
    name: "bob_credential_write",
    description:
      "Execute one pre-issued provider-neutral credential/media mutation experiment with a distinct persistent-effect grant, pre-read, independent post-read, rollback or terminal-state plan, and opaque evidence custody. The tool accepts no arbitrary write bytes or provider primitive.",
    capability_id: "physical.credential.write",
    effect_surface: Object.freeze(["instrument.configure", "target.mutate", "target.destroy"]),
  }),
  protocol_transceive: Object.freeze({
    name: "bob_protocol_transceive",
    description:
      "Execute one pre-issued closed-schema protocol experiment compiled by Bob's reviewed technique registry. Application/opcode/parameter domains, maximum effects, state machine, controls, teardown, and transcript custody are fixed server-side; arbitrary frames, APDUs, response scripts, or serial passthrough are impossible here.",
    capability_id: "physical.protocol.transceive",
    effect_surface: Object.freeze([
      "target.transmit",
      "target.present",
      "target.mutate",
      "target.destroy",
    ]),
  }),
  rf_trace: Object.freeze({
    name: "bob_rf_trace",
    description:
      "Execute one pre-issued provider-neutral RF interaction trace/signal-analysis experiment. The server-owned plan records whether the provider transmitted or emulated and sends raw traces/waveforms only to opaque vault custody; the public result contains bounded receipt and observation references.",
    capability_id: "physical.rf.trace",
    effect_surface: Object.freeze(["target.transmit", "target.present"]),
  }),
});

function definePhysicalTechniqueTool(family) {
  const spec = FAMILY_SPECS[family];
  if (!spec) throw new Error(`unknown physical technique tool family ${family}`);
  async function execute(args) {
    const result = await executePhysicalTechnique({
      target_domain: args.target_domain,
      family,
      execution_ref: args.execution_ref,
      cell_ref: args.cell_ref,
      assignment_context_digest: args.assignment_context_digest,
    });
    return JSON.stringify({ version: 1, execution: result });
  }
  return Object.freeze({
    name: spec.name,
    description: spec.description,
    inputSchema: Object.freeze({
      type: "object",
      additionalProperties: false,
      properties: Object.freeze({
        target_domain: Object.freeze({
          type: "string",
          minLength: 1,
          maxLength: 253,
          description: "Initialized physical-session authority key; never a device, room, credential, or provider identifier.",
        }),
        execution_ref: Object.freeze({
          type: "string",
          pattern: EXECUTION_REF_PATTERN,
          description: "Opaque one-use execution reference pre-issued by Bob's server-owned physical composition root.",
        }),
        cell_ref: Object.freeze({
          type: "string",
          pattern: CELL_REF_PATTERN,
          description: "Exact physical coverage cell bound by the assignment and execution plan.",
        }),
        assignment_context_digest: Object.freeze({
          type: "string",
          pattern: DIGEST_PATTERN,
          description: "Digest of the current provider-neutral physical assignment context.",
        }),
      }),
      required: Object.freeze([
        "target_domain",
        "execution_ref",
        "cell_ref",
        "assignment_context_digest",
      ]),
    }),
    handler: execute,
    role_bundles: Object.freeze(["evaluator-physical"]),
    capability_id: spec.capability_id,
    mutating: true,
    global_preapproval: false,
    network_access: false,
    browser_access: false,
    scope_required: false,
    sensitive_output: false,
    session_artifacts_written: Object.freeze(["physical-campaign/experiments/"]),
    required_session_axes: Object.freeze(["physical"]),
    effect_surface: spec.effect_surface,
  });
}

module.exports = Object.freeze({
  FAMILY_SPECS,
  definePhysicalTechniqueTool,
});
