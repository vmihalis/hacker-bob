"use strict";

const {
  validateHttpScanScope,
} = require("../scope.js");
const {
  authorizeToolCall,
  scopedUrlDriftError,
} = require("../session/session-authority.js");

function enforceToolPolicy(tool, args) {
  if (!tool) return null;

  const authority = authorizeToolCall(tool, args);
  if (!tool.scope_required) return authority;

  for (const field of tool.scope_url_fields || []) {
    const value = args[field];
    if (typeof value !== "string" || value.trim().length === 0) continue;
    try {
      validateHttpScanScope(value, args.target_domain);
    } catch (error) {
      throw scopedUrlDriftError(authority, field, error);
    }
  }
  return authority;
}

module.exports = {
  enforceToolPolicy,
};
