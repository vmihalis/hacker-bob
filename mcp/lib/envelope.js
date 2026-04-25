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

class ToolError extends Error {
  constructor(code, message, details = null) {
    super(message);
    this.name = "ToolError";
    this.code = code;
    this.details = details;
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

function errorEnvelope(toolName, code, message, details = undefined) {
  const error = {
    code,
    message: message || code,
  };
  if (details !== undefined) {
    error.details = details;
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
  if (!data || typeof data !== "object" || Array.isArray(data) || typeof data.error !== "string") {
    return null;
  }
  if (data.scope_decision === "blocked") {
    return ERROR_CODES.SCOPE_BLOCKED;
  }
  if (data.scope_decision === "auth_missing") {
    return ERROR_CODES.AUTH_MISSING;
  }
  if (/auth_profile .*not found|auth.*missing|missing auth/i.test(data.error)) {
    return ERROR_CODES.AUTH_MISSING;
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
