const {
  ERROR_CODES,
  classifyDataError,
  classifyException,
  errorEnvelope,
  okEnvelope,
  parseHandlerResult,
} = require("../io/envelope.js");
const {
  TOOL_HANDLERS,
  getRegisteredTool,
} = require("./tool-registry.js");
const {
  validateToolArguments,
} = require("./tool-validation.js");
const {
  enforceToolPolicy,
} = require("./tool-policy.js");
const {
  assertEnforcementLiveness,
} = require("../enforcement-attest.js");
const {
  safeRecordToolTelemetry,
} = require("../telemetry/tool-telemetry.js");
const {
  runWithReplaySafety,
} = require("../verification/verification-replay-safety.js");

function shadowSafeErrorMessage(error, authority) {
  const message = error && error.message ? error.message : String(error);
  if (
    authority &&
    authority.authority_shadowed === true &&
    authority.authority_error_code === "no_session" &&
    /Missing session state:/i.test(message)
  ) {
    return "Session state is missing";
  }
  return message;
}

async function executeTool(name, args) {
  const startedAt = Date.now();
  const safeArgs = args || {};
  let authority = null;
  const tool = getRegisteredTool(name);
  const finish = (envelope) => {
    safeRecordToolTelemetry({
      toolName: name,
      tool,
      args: safeArgs,
      envelope,
      elapsedMs: Date.now() - startedAt,
      authority,
    });
    return envelope;
  };

  if (!tool) {
    return finish(errorEnvelope(name, ERROR_CODES.UNKNOWN_TOOL, `Unknown tool: ${name}`));
  }

  try {
    validateToolArguments(name, safeArgs);
    // Enforcement-liveness self-attestation. If the authority kernel is in
    // shadow mode without operator-ack, refuse mutating calls loudly here
    // (read-only calls fall through to the kernel, which fails loud on its own
    // because authorityMode() reports "enforce" without an ack).
    assertEnforcementLiveness(tool);
    authority = enforceToolPolicy(tool, safeArgs);
  } catch (error) {
    if (error && error.authority) {
      authority = error.authority;
    }
    if (error && error.enforcement_liveness && error.enforcement_liveness.degraded_unacked) {
      // Best-effort loud drift record so the degraded posture is auditable even
      // when stderr is discarded. Never throws; idempotent on (run_id, sig, tool).
      try {
        const driftTool = getRegisteredTool("bob_emit_runtime_drift");
        if (driftTool && typeof safeArgs.target_domain === "string" && safeArgs.target_domain.trim()) {
          await driftTool.handler({
            target_domain: safeArgs.target_domain,
            run_id: typeof safeArgs.run_id === "string" && safeArgs.run_id.trim()
              ? safeArgs.run_id
              : "enforcement-liveness",
            drift_signature: "wrong_mode_tool_call",
            rationale: "Session-authority enforcement in shadow mode without operator-ack; mutating call refused.",
            details: { tool: name, session_mode: "shadow_unacked" },
          });
        }
      } catch {
        // Best-effort only — the refusal envelope below is the load-bearing signal.
      }
    }
    return finish(errorEnvelope(
      name,
      error.code && Object.values(ERROR_CODES).includes(error.code) ? error.code : ERROR_CODES.INVALID_ARGUMENTS,
      error.message || String(error),
      error.details,
      typeof error.remediation === "string" ? { remediation: error.remediation } : undefined,
    ));
  }

  try {
    const data = parseHandlerResult(await runWithReplaySafety(tool, safeArgs, () => tool.handler(safeArgs)));
    const dataErrorCode = classifyDataError(data);
    if (dataErrorCode) {
      return finish(errorEnvelope(name, dataErrorCode, data.error, data));
    }
    return finish(okEnvelope(name, data));
  } catch (error) {
    return finish(errorEnvelope(
      name,
      classifyException(error),
      shadowSafeErrorMessage(error, authority),
      error.details,
      typeof error.remediation === "string" ? { remediation: error.remediation } : undefined,
    ));
  }
}

module.exports = {
  TOOL_HANDLERS,
  executeTool,
};
