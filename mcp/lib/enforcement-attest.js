"use strict";

// Enforcement-liveness self-attestation.
//
// BOB_SESSION_AUTHORITY_MODE=shadow downgrades a missing-session authority
// block to a soft `shadow_blocked`. That is a deliberate degradation of the
// authority kernel and MUST be (a) operator-acknowledged and (b) loud +
// audit-recorded — never a silent stderr line that a stripped/headless
// harness discards.
//
// This module is the ONLY place that knows the ack env-var name and the
// liveness predicate. session-authority.js and dispatch.js consult it; tests
// assert the contract through it so the env-var name has exactly one home.

const { ERROR_CODES, ToolError } = require("./envelope.js");

const AUTHORITY_MODE_ENV = "BOB_SESSION_AUTHORITY_MODE";
// Operator-ack escape: shadow mode is only honored when the operator has
// explicitly acknowledged the degraded enforcement posture. The token is an
// exact string match so a typo'd value fails closed (mode stays enforce-loud).
const SHADOW_ACK_ENV = "BOB_SESSION_AUTHORITY_SHADOW_ACK";
const SHADOW_ACK_TOKEN = "i-accept-degraded-session-authority";

function rawMode(env = process.env) {
  return env[AUTHORITY_MODE_ENV] === "shadow" ? "shadow" : "enforce";
}

function operatorAck(env = process.env) {
  return env[SHADOW_ACK_ENV] === SHADOW_ACK_TOKEN;
}

// The single liveness fact the kernel and dispatch branch on.
//   mode            : raw env-derived intent ("shadow" | "enforce")
//   shadow_active   : shadow honored == shadow requested AND acked
//   operator_ack    : operator presented the exact ack token
//   degraded_unacked: shadow requested but NOT acked  -> the dangerous state
//   attested        : enforcement posture is in a known-safe state
//                     (enforce, OR shadow with a recorded ack)
function enforcementLiveness(env = process.env) {
  const mode = rawMode(env);
  const operator_ack = operatorAck(env);
  const shadow_active = mode === "shadow" && operator_ack;
  const degraded_unacked = mode === "shadow" && !operator_ack;
  return Object.freeze({
    mode,
    operator_ack,
    shadow_active,
    degraded_unacked,
    attested: mode === "enforce" || shadow_active,
  });
}

// Dispatch-side guard. For a MUTATING tool call, an un-acked shadow request is
// refused loudly: we will NOT execute a session mutation while the authority
// kernel's posture is degraded-but-unacknowledged. Returns the liveness object
// for callers that want to record it; throws STATE_CONFLICT when unsafe.
function assertEnforcementLiveness(tool, env = process.env) {
  const liveness = enforcementLiveness(env);
  if (!liveness.degraded_unacked) {
    return liveness;
  }
  // Degraded + unacked. Read-only paths are allowed to proceed (they will hit
  // the kernel which, with no ack, will NOT shadow and will surface the real
  // missing-session block — see session-authority canShadowMissingSession).
  // Mutating calls are refused here so a degraded kernel can never accept a
  // session write under a silent env flip.
  if (tool && tool.mutating) {
    const authority = {
      authority_result: "blocked",
      authority_error_code: "enforcement_degraded_unacked",
      authority_block_reason: "enforcement_degraded_unacked",
      authority_mode: "shadow",
      authority_shadowed: false,
      operator_ack: false,
    };
    const err = new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Session-authority enforcement is in shadow mode (${AUTHORITY_MODE_ENV}=shadow) `
        + `without operator acknowledgement. Refusing the mutating tool call. `
        + `Set ${SHADOW_ACK_ENV}=${SHADOW_ACK_TOKEN} to acknowledge the degraded `
        + `posture, or unset ${AUTHORITY_MODE_ENV} to restore loud enforcement.`,
      {
        enforcement_liveness: liveness,
        authority,
      },
    );
    // R1: dispatch records the enforcement decision off `err.authority`, not
    // `err.details.authority`. Mirror the decision onto the top-level field so
    // the telemetry row carries authority_error_code=enforcement_degraded_unacked
    // instead of authority:null.
    err.authority = authority;
    err.enforcement_liveness = liveness;
    throw err;
  }
  return liveness;
}

module.exports = {
  AUTHORITY_MODE_ENV,
  SHADOW_ACK_ENV,
  SHADOW_ACK_TOKEN,
  enforcementLiveness,
  operatorAck,
  assertEnforcementLiveness,
};
