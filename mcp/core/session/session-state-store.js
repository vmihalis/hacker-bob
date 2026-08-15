"use strict";

const fs = require("fs");
const {
  assertBoolean,
  assertNonEmptyString,
} = require("../io/validation.js");
const {
  sessionDir,
  statePath,
} = require("../io/paths.js");
const {
  readJsonFile,
  writeFileAtomic,
} = require("../io/storage.js");
const {
  blockInternalHostsPolicyFields,
  composeSessionStateDocument,
  deriveBlockInternalHostsPolicy,
  normalizeSessionStateDocument,
} = require("./session-state-contracts.js");

function readSessionStateStrict(domain) {
  const normalizedDomain = assertNonEmptyString(domain, "target_domain");
  const filePath = statePath(normalizedDomain);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing session state: ${filePath}`);
  }

  let parsed;
  try {
    parsed = readJsonFile(filePath, { label: "state.json" });
  } catch (error) {
    throw new Error(`Malformed session state: ${filePath} (${error.message || String(error)})`);
  }

  try {
    return {
      dir: sessionDir(normalizedDomain),
      path: filePath,
      raw: parsed,
      state: normalizeSessionStateDocument(parsed, normalizedDomain),
    };
  } catch (error) {
    throw new Error(`Malformed session state: ${filePath} (${error.message || String(error)})`);
  }
}

// Caller-held session locks are part of this API's contract. This helper
// intentionally does not lock; mutating callers must hold withSessionLock().
function writeSessionStateDocument(domain, rawDocument, state) {
  const filePath = statePath(domain);
  const nextDocument = composeSessionStateDocument(rawDocument, state);
  writeFileAtomic(filePath, `${JSON.stringify(nextDocument, null, 2)}\n`);
  return nextDocument;
}

function sessionStateMissing(error) {
  return /Missing session state:/.test(error && error.message ? error.message : String(error));
}

function blockInternalHostsRequestPolicy(domain, args = {}, {
  allowMissingSession = false,
} = {}) {
  const explicitBlock = args.block_internal_hosts == null
    ? null
    : assertBoolean(args.block_internal_hosts, "block_internal_hosts");
  let sessionPolicy = null;
  try {
    sessionPolicy = blockInternalHostsPolicyFields(readSessionStateStrict(domain).state);
  } catch (error) {
    if (!allowMissingSession || !sessionStateMissing(error)) {
      throw error;
    }
  }

  if (sessionPolicy && sessionPolicy.block_internal_hosts === true) {
    return {
      ...sessionPolicy,
      block_internal_hosts_effective_source: "session",
    };
  }
  if (explicitBlock === true) {
    return {
      checkpoint_mode: sessionPolicy ? sessionPolicy.checkpoint_mode : "normal",
      block_internal_hosts: true,
      block_internal_hosts_source: "request_override",
      block_internal_hosts_effective_source: "request",
    };
  }
  const fallback = sessionPolicy || deriveBlockInternalHostsPolicy({ legacyDefault: true });
  return {
    ...fallback,
    block_internal_hosts_effective_source: sessionPolicy ? "session" : "legacy_default",
  };
}

module.exports = {
  blockInternalHostsRequestPolicy,
  readSessionStateStrict,
  sessionStateMissing,
  writeSessionStateDocument,
};
