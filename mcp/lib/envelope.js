"use strict";

const ERROR_CODES = Object.freeze({
  UNKNOWN_TOOL: "UNKNOWN_TOOL",
  INVALID_ARGUMENTS: "INVALID_ARGUMENTS",
  SCOPE_BLOCKED: "SCOPE_BLOCKED",
  AUTH_MISSING: "AUTH_MISSING",
  STATE_CONFLICT: "STATE_CONFLICT",
  NOT_FOUND: "NOT_FOUND",
  INTERNAL_ERROR: "INTERNAL_ERROR",
});

// Y.3 (Y-D12 / D15): ToolError optionally carries a structured `remediation`
// string so STATE_CONFLICT (and any other) call sites can tell the caller
// exactly which tool to invoke to clear the conflict. The field is reflected
// uniformly through errorEnvelope(). Y.10 (Y-P12) lands the first concrete
// backfill: the OPEN_FRONTIER -> CLAIM_FREEZE partial_surfaces_remaining
// blocker propagates remediation through advanceSession() so MCP callers
// see the structured "call bob_set_queue_policy({partial_surface_advance_
// acknowledgements: [...]})" hint verbatim.
class ToolError extends Error {
  constructor(code, message, details = null, options = null) {
    super(message);
    this.name = "ToolError";
    this.code = code;
    this.details = details;
    const remediation = options && typeof options === "object" && !Array.isArray(options)
      ? options.remediation
      : null;
    if (remediation != null) {
      if (typeof remediation !== "string") {
        throw new TypeError("ToolError remediation must be a string when provided");
      }
      this.remediation = remediation;
    }
  }
}

function metaForTool(toolName) {
  return { tool: toolName, version: 1 };
}

function okEnvelope(toolName, data) {
  return {
    ok: true,
    data: data == null ? {} : data,
    meta: metaForTool(toolName),
  };
}

function errorEnvelope(toolName, code, message, details = undefined, options = undefined) {
  const error = {
    code,
    message: message || code,
  };
  if (details !== undefined) {
    error.details = details;
  }
  // Y.3 (Y-D12 / D15): propagate the optional structured remediation string
  // through the response envelope so MCP callers can present it verbatim. The
  // field is only emitted when the throwing site or caller explicitly attached
  // one; legacy STATE_CONFLICT sites without remediation continue to render
  // without the field.
  if (options && typeof options === "object" && !Array.isArray(options) && typeof options.remediation === "string") {
    error.remediation = options.remediation;
  }
  return {
    ok: false,
    error,
    meta: metaForTool(toolName),
  };
}

function parseHandlerResult(rawResult) {
  if (typeof rawResult !== "string") {
    return rawResult == null ? {} : rawResult;
  }

  try {
    return JSON.parse(rawResult);
  } catch {
    return { value: rawResult };
  }
}

function classifyDataError(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return null;
  }
  if (data.scope_decision === "blocked") {
    return ERROR_CODES.SCOPE_BLOCKED;
  }
  if (data.scope_decision === "auth_missing") {
    return ERROR_CODES.AUTH_MISSING;
  }
  if (typeof data.error !== "string") {
    return null;
  }
  if (/auth_profile .*not found|auth.*missing|missing auth/i.test(data.error)) {
    return ERROR_CODES.AUTH_MISSING;
  }
  if (data.success === false && data.fallback === "manual") {
    return null;
  }
  return ERROR_CODES.INTERNAL_ERROR;
}

function classifyException(error) {
  if (error && Object.values(ERROR_CODES).includes(error.code)) {
    return error.code;
  }

  const message = error && error.message ? error.message : String(error);
  if (/scope|out-of-scope|deny-listed|internal\/private|blocked/i.test(message)) {
    return ERROR_CODES.SCOPE_BLOCKED;
  }
  if (/auth_profile .*not found|auth.*missing|missing auth/i.test(message)) {
    return ERROR_CODES.AUTH_MISSING;
  }
  if (/missing .*:|not found|not found in|unknown .*id|missing assignment/i.test(message)) {
    return ERROR_CODES.NOT_FOUND;
  }
  if (/already|duplicate|pending_wave|requires phase|requires pending_wave|invalid phase transition|lock busy|state write failed|wave_number must equal/i.test(message)) {
    return ERROR_CODES.STATE_CONFLICT;
  }
  return ERROR_CODES.INTERNAL_ERROR;
}

module.exports = {
  ERROR_CODES,
  ToolError,
  classifyDataError,
  classifyException,
  errorEnvelope,
  okEnvelope,
  parseHandlerResult,
};
