"use strict";

// Plane X Cycle X.7 — body resolver registry.
//
// One resolver per X-D12 closed artifact_ref prefix. Each resolver is a
// pure function `(target_domain, ref_id) → {body, content_hash, body_size_bytes} | null`
// where `body` is a Buffer or string carrying the FULL artifact body
// addressable by the summary's hash. The MCP tool `bob_resolve_body`
// (resolve-body.js) wraps the registry with the scope-check + 1MB
// truncation discipline; the X.6 mechanical verifier shares the same
// helpers via `resolveArtifactBody` so the on-disk path is the single
// source of truth (X.7 Do step 4).
//
// Resolvers return `null` when a ref_id is not found. Resolvers MUST NOT
// throw on missing records; the caller distinguishes "not found" from
// "scope violation" by composition. Resolvers MAY throw on malformed
// session paths or unreadable disks (the underlying fs.readFileSync
// error bubbles); the tool layer catches and surfaces a structured
// `body_resolution_failed` to the caller.

const httpRecordResolver = require("./http-record.js");
const evmCallResolver = require("./evm-call.js");
const repoCheckResolver = require("./repo-check.js");
const repoCommandRunResolver = require("./repo-command-run.js");
const findingResolver = require("./finding.js");
const evidencePackResolver = require("./evidence-pack.js");
const frontierEventResolver = require("./frontier-event.js");

// Registry shape matches the X-D12 closed prefix set. The keys are the
// canonical prefixes; the values are { resolve } so future cycles can add
// a `summary` emitter alongside without re-keying the registry.
const RESOLVERS = Object.freeze({
  http_record: Object.freeze({ resolve: httpRecordResolver }),
  evm_call: Object.freeze({ resolve: evmCallResolver }),
  repo_check: Object.freeze({ resolve: repoCheckResolver }),
  repo_command_run: Object.freeze({ resolve: repoCommandRunResolver }),
  finding: Object.freeze({ resolve: findingResolver }),
  evidence_pack: Object.freeze({ resolve: evidencePackResolver }),
  frontier_event: Object.freeze({ resolve: frontierEventResolver }),
});

const RESOLVER_PREFIXES = Object.freeze(Object.keys(RESOLVERS).sort());

// Internal helper shared by the X.7 MCP tool and the X.6 mechanical
// verifier. Returns the raw resolver output (body + content_hash +
// body_size_bytes) or null when the ref_id is unknown. Throws a
// structured Error when the prefix is outside the X-D12 closed set so
// the caller can surface `artifact_ref_unknown_prefix` consistently
// across the tool + verifier paths.
function resolveArtifactBody(targetDomain, artifactRef) {
  if (typeof artifactRef !== "string" || !artifactRef.trim()) {
    const err = new Error("artifact_ref must be a non-empty string");
    err.code = "artifact_ref_malformed";
    throw err;
  }
  const idx = artifactRef.indexOf(":");
  if (idx <= 0 || idx >= artifactRef.length - 1) {
    const err = new Error(`artifact_ref must be <prefix>:<ref_id>; got "${artifactRef}"`);
    err.code = "artifact_ref_malformed";
    err.details = { artifact_ref: artifactRef };
    throw err;
  }
  const prefix = artifactRef.slice(0, idx);
  const refId = artifactRef.slice(idx + 1);
  const entry = RESOLVERS[prefix];
  if (!entry) {
    const err = new Error(
      `artifact_ref prefix "${prefix}" is not in the X-D12 closed set (${RESOLVER_PREFIXES.join(", ")})`,
    );
    err.code = "artifact_ref_unknown_prefix";
    err.details = {
      prefix,
      artifact_ref: artifactRef,
      allowed_prefixes: RESOLVER_PREFIXES.slice(),
    };
    throw err;
  }
  return entry.resolve(targetDomain, refId);
}

module.exports = {
  RESOLVERS,
  RESOLVER_PREFIXES,
  resolveArtifactBody,
};
