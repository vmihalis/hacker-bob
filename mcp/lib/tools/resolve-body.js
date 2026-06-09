"use strict";

// Plane X Cycle X.7 — bob_resolve_body.
//
// Reads the FULL body of an artifact addressable by an X-D12 artifact_ref
// (`<prefix>:<ref_id>`). Per X-P9 every brief-surfaceable artifact ships a
// distilled summary at append-time; bodies are pull-only via this tool.
// Brief renderers inline summaries; agents (and the X.6 mechanical verifier)
// resolve bodies through this single sanctioned read surface.
//
// Per Do step 1 (X.7):
//   - Scope-checked: target_domain must match a session that this caller
//     can address (the path-derivation paths via paths.js already gate on
//     SAFE_NAME_PATTERN, refusing path traversal). The session path
//     resolution naturally bounds reads to the session root.
//   - Accepts artifact_ref from the X-D12 closed prefix set; anything
//     else returns `artifact_ref_unknown_prefix`.
//   - Returns the body up to 1MB; over → truncated with `truncated_at`
//     byte offset for paginated re-fetch via
//     `bob_resolve_body(target_domain, artifact_ref, offset)`.
//   - Allowed bundles: evaluator-shared, verifier, evidence (broad read,
//     bodies are scope-checked + no side effects). NOT orchestrator
//     (orchestrator delegates to evaluators; the brief renderer pulls
//     distilled summaries, not bodies).

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  assertSafeDomain,
} = require("../paths.js");
const {
  RESOLVER_PREFIXES,
  resolveArtifactBody,
} = require("../body-resolvers/index.js");
const {
  wrapUntrusted,
  FENCE_OVERHEAD_BUDGET,
} = require("../untrusted-envelope.js");

const BODY_RESPONSE_MAX_BYTES = 1024 * 1024; // 1MB per X.7 Do step 1.
const BODY_RESPONSE_UNTRUSTED_PAYLOAD_MAX_BYTES = BODY_RESPONSE_MAX_BYTES - FENCE_OVERHEAD_BUDGET;
const TRUSTED_BODY_PREFIX_VALUES = Object.freeze([]);
const TRUSTED_BODY_PREFIXES = new Set(TRUSTED_BODY_PREFIX_VALUES);

function structuredError(code, message, details) {
  const err = new Error(`${code}: ${message}`);
  err.code = code;
  if (details) err.details = details;
  return err;
}

function artifactRefPrefix(artifactRef) {
  const idx = typeof artifactRef === "string" ? artifactRef.indexOf(":") : -1;
  return idx > 0 ? artifactRef.slice(0, idx) : "";
}

function renderBodyForResponse(prefix, body) {
  if (body === "") return "";
  if (TRUSTED_BODY_PREFIXES.has(prefix)) return body;
  return wrapUntrusted(body, { label: prefix }).fenced;
}

function bodyPayloadMaxBytes(prefix) {
  if (TRUSTED_BODY_PREFIXES.has(prefix)) return BODY_RESPONSE_MAX_BYTES;
  return BODY_RESPONSE_UNTRUSTED_PAYLOAD_MAX_BYTES;
}

function handler(args) {
  const input = args || {};
  const domain = assertSafeDomain(
    assertNonEmptyString(input.target_domain, "target_domain"),
  );
  const artifactRef = assertNonEmptyString(input.artifact_ref, "artifact_ref");
  const offsetRaw = input.offset == null ? 0 : input.offset;
  if (typeof offsetRaw !== "number" || !Number.isInteger(offsetRaw) || offsetRaw < 0) {
    throw structuredError(
      "offset_invalid",
      "offset must be a non-negative integer",
      { offset: offsetRaw },
    );
  }

  let resolved;
  try {
    resolved = resolveArtifactBody(domain, artifactRef);
  } catch (error) {
    // The body-resolvers index throws structured errors for malformed
    // refs / unknown prefixes; preserve the error.code on the way out
    // so the MCP envelope surfaces the structured failure to the caller.
    if (error && error.code) throw error;
    throw structuredError(
      "body_resolution_failed",
      `failed to resolve ${artifactRef}: ${error.message || error}`,
      { artifact_ref: artifactRef },
    );
  }

  if (resolved == null) {
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      artifact_ref: artifactRef,
      found: false,
      body: null,
      content_hash: null,
      body_size_bytes: 0,
      offset: offsetRaw,
      truncated_at: null,
    });
  }

  const fullBody = resolved.body;
  const totalSize = resolved.body_size_bytes;
  const prefix = artifactRefPrefix(artifactRef);
  const payloadMaxBytes = bodyPayloadMaxBytes(prefix);
  if (offsetRaw >= totalSize) {
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      artifact_ref: artifactRef,
      found: true,
      body: renderBodyForResponse(prefix, ""),
      content_hash: resolved.content_hash,
      body_size_bytes: totalSize,
      offset: offsetRaw,
      truncated_at: null,
    });
  }

  // Slice from offset; truncate to 1MB if the remaining bytes exceed cap.
  const sliceBuffer = Buffer.isBuffer(fullBody)
    ? fullBody.subarray(offsetRaw)
    : Buffer.from(String(fullBody), "utf8").subarray(offsetRaw);
  let truncatedAt = null;
  let outBuffer = sliceBuffer;
  if (sliceBuffer.length > payloadMaxBytes) {
    outBuffer = sliceBuffer.subarray(0, payloadMaxBytes);
    truncatedAt = offsetRaw + payloadMaxBytes;
  }
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    artifact_ref: artifactRef,
    found: true,
    body: renderBodyForResponse(prefix, outBuffer.toString("utf8")),
    content_hash: resolved.content_hash,
    body_size_bytes: totalSize,
    offset: offsetRaw,
    truncated_at: truncatedAt,
  });
}

module.exports = Object.freeze({
  name: "bob_resolve_body",
  description:
    "Resolve the FULL body of an artifact addressable by an X-D12 artifact_ref "
    + "(prefix:ref_id). Per X-P9 brief renderers inline distilled summaries "
    + "at write-time; bodies are pull-only via this tool. Accepts artifact_ref "
    + `prefixes from the X-D12 closed set: ${RESOLVER_PREFIXES.join(", ")}. `
    + "Returns up to 1MB per call; over → truncated with truncated_at byte "
    + "offset for paginated re-fetch via offset. Scope-checked: target_domain "
    + "must address a valid session. Used by evaluator-shared, verifier, and "
    + "evidence bundles; NOT orchestrator (orchestrator delegates).",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      artifact_ref: {
        type: "string",
        description:
          `Artifact reference shaped <prefix>:<ref_id> with prefix in the X-D12 closed set (${RESOLVER_PREFIXES.join(", ")}).`,
      },
      offset: {
        type: "integer",
        minimum: 0,
        description: "Byte offset for paginated re-fetch when a prior call returned truncated_at.",
      },
    },
    required: ["target_domain", "artifact_ref"],
  },
  handler,
  // Per X.7 Do step 1: evaluator-shared, verifier, evidence — bodies are
  // scope-checked and read-only so the broad-read trade is documented in
  // X-R14. orchestrator is intentionally excluded (orchestrator delegates).
  role_bundles: ["evaluator-shared", "verifier", "evidence"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
  // The byte cap is exposed on the frozen module shape so tests can
  // assert on the truncation boundary without reaching into the
  // resolver-tool internals.
  BODY_RESPONSE_MAX_BYTES,
  BODY_RESPONSE_UNTRUSTED_PAYLOAD_MAX_BYTES,
  TRUSTED_BODY_PREFIX_VALUES,
  renderBodyForResponse,
});
