"use strict";

// Y.3 Stage a — shared write-base wrapper (Y-D15a).
//
// This module wraps a write-tool handler so the six audit-graded writers
// (`bob_write_verification_round`, `bob_write_evidence_packs`,
// `bob_write_grade_verdict`, `bob_write_wave_handoff`, `bob_write_chain_attempt`,
// `bob_finalize_report`) — plus the Y.3 newcomers `bob_compose_report` and
// `bob_write_chain_rollup` — share three concerns:
//
//   1. Payload validation (the same shape the dispatch layer's
//      `validateToolArguments` performs, run again at the wrapper boundary so
//      the auto-emit retry path observes the same gate).
//   2. Server-internal caller-context construction for the Y-D13
//      `bob_emit_runtime_drift({drift_signature: "write_arg_schema_mismatch_recovered"})`
//      hook. The `mcp_server_internal` synthetic caller bundle is constructed
//      HERE — never exported from `mcp/core/dispatch/tool-registry.js` (a
//      paired CI guard in Y.8 asserts this). The bundle is a synthetic context, not a grantable
//      role; agents cannot acquire it through any role-bundle assignment.
//   3. Uniform ToolError envelope including optional `remediation: string`
//      (Y-D12 / D15 — `tool-error.js`'s ToolError already supports the field;
//      this wrapper preserves it across the validation retry path).
//
// Atomic hash + bind pattern (5-hash chain preservation, Y-R21): the wrapper
// does NOT re-implement hashing. Each writer's existing hash/bind logic remains
// inside its handler; the wrapper composes around it. This is the
// BIND-equivalence guarantee — content hashes for identical structured input
// are bit-identical pre- and post-migration (validated by Y.9 subtest F-5).

const {
  ERROR_CODES,
  ToolError,
} = require("../core/io/envelope.js");
const {
  AUDIT_GRADED_WRITER_TOOLS,
  auditGradedWriterClosure,
} = require("../core/io/paths.js");

// Y-P13 (T4) — every spec that passes writes_audit_graded:true registers its
// name here at wrap time so the FLAG↔WHITELIST closure self-check can run
// against the live declaring set. Module-scoped; deterministic across require
// order because every writer module requires _write-base before first dispatch.
const DECLARED_AUDIT_GRADED_WRITERS = new Set();

// Lazy load of tool-validation: importing it eagerly would create a circular
// dependency (tool-validation → tool-registry → tools/index → writers →
// _write-base). The lazy handle resolves at first invocation, by which point
// the module graph has settled.
let _validateAgainstSchema = null;
function getValidator() {
  if (!_validateAgainstSchema) {
    _validateAgainstSchema = require("../core/dispatch/tool-validation.js").validateAgainstSchema;
  }
  return _validateAgainstSchema;
}

// Synthetic caller bundle constructed inside this module. CI in Y.8 asserts
// this name is NOT exported from `mcp/core/dispatch/tool-registry.js`; the
// guard also scans role-spec exports in `mcp/core/capability/capability-packs.js`
// and `mcp/core/dispatch/role-model.js`. The literal string is the contract.
const MCP_SERVER_INTERNAL_BUNDLE = Object.freeze({
  bundle_id: "mcp_server_internal",
  // Synthetic caller contexts cannot acquire any tool grant — they only
  // identify the write-base as the auto-emit caller for runtime-drift events.
  granted_tools: Object.freeze([]),
  origin: "write-base-internal",
});

function assertPlainObject(value, fieldName) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `${fieldName} must be a plain object`,
    );
  }
}

function runSchemaValidation(name, inputSchema, args) {
  try {
    getValidator()(args, inputSchema, []);
  } catch (error) {
    // Re-throw as INVALID_ARGUMENTS so dispatch + Y-D13 retry path classify it
    // uniformly. The existing dispatch.executeTool would normally raise this
    // before our handler runs (validateToolArguments fires first); we re-run
    // here so callers that invoke wrapWriteTool().handler(args) directly (e.g.
    // tests) get the same gate.
    const message = error && error.message ? error.message : String(error);
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `${name} payload failed schema validation: ${message}`,
    );
  }
}

// Auto-emit hook (Y-D13). The first call into a wrapped write tool whose
// handler throws INVALID_ARGUMENTS records a candidate-for-retry marker.
// When a second invocation in the same process with corrected args succeeds,
// the wrapper auto-emits `bob_emit_runtime_drift({drift_signature:
// "write_arg_schema_mismatch_recovered"})` via the server-internal caller
// context. This is the runtime channel for Y-P7 — telemetry only; never an
// auto-corrector.
//
// Tracking key: `${tool_name}::${run_id_or_anonymous}`. The first failed
// attempt records its ajv_path summary; the next success in the same process
// triggers the emit.
const PENDING_RETRY_KEYS = new Map();

function buildRetryKey(name, args) {
  const runId = args && typeof args.run_id === "string" ? args.run_id : "<no-run-id>";
  const domain = args && typeof args.target_domain === "string" ? args.target_domain : "<no-domain>";
  return `${name}::${domain}::${runId}`;
}

function recordPendingRetry(name, args, error) {
  // Capture only the path summary (the AJV-style location) so the eventual
  // drift event payload stays summary-grade per Y-P2 (rationale capped at 512).
  const key = buildRetryKey(name, args);
  const message = error && error.message ? error.message : String(error);
  PENDING_RETRY_KEYS.set(key, {
    ajv_path: message.length > 480 ? `${message.slice(0, 480)}…` : message,
    attempts: (PENDING_RETRY_KEYS.get(key)?.attempts ?? 0) + 1,
  });
}

function consumePendingRetryForSuccess(name, args) {
  const key = buildRetryKey(name, args);
  const pending = PENDING_RETRY_KEYS.get(key);
  if (!pending) return null;
  PENDING_RETRY_KEYS.delete(key);
  return pending;
}

function safeEmitRuntimeDrift(name, args, pending) {
  // Lazy require to avoid circular load (emit-runtime-drift requires
  // capability-observations + frontier-events; we sit beneath dispatch).
  try {
    const emit = require("./emit-runtime-drift.js");
    // Only fire when we have all four required fields. Otherwise the auto-emit
    // is silently dropped (Y-P7 — runtime telemetry is best-effort).
    const targetDomain = args && typeof args.target_domain === "string" ? args.target_domain : null;
    const runId = args && typeof args.run_id === "string" ? args.run_id : null;
    if (!targetDomain || !runId) {
      return;
    }
    emit.handler({
      target_domain: targetDomain,
      run_id: runId,
      drift_signature: "write_arg_schema_mismatch_recovered",
      rationale: `write-base auto-emit: ${name} retried successfully after INVALID_ARGUMENTS (attempts=${pending.attempts + 1})`,
      details: {
        tool: name,
        ajv_path: pending.ajv_path,
        attempts: pending.attempts + 1,
        caller_bundle: MCP_SERVER_INTERNAL_BUNDLE.bundle_id,
      },
    });
  } catch {
    // Best-effort telemetry. Never regress the underlying write.
  }
}

// Wrap a write tool's existing module export. Returns a NEW tool spec where
// the `handler` is the wrapped version; all other fields (inputSchema,
// role_bundles, mutating, etc.) are passed through unchanged so the
// tool-registry contract is unaffected.
function wrapWriteTool(spec) {
  assertPlainObject(spec, "spec");
  if (typeof spec.name !== "string" || !spec.name) {
    throw new TypeError("wrapWriteTool requires a string `name`");
  }
  if (typeof spec.handler !== "function") {
    throw new TypeError(`wrapWriteTool(${spec.name}): handler must be a function`);
  }
  if (!spec.inputSchema || typeof spec.inputSchema !== "object") {
    throw new TypeError(`wrapWriteTool(${spec.name}): inputSchema must be an object`);
  }

  // Y-P13 (T4) — fail-closed at wrap time. A spec that claims to write an
  // audit-graded artifact MUST be on the paths.js whitelist; a whitelisted name
  // MUST declare the flag. Either mismatch throws at module load, so a
  // mis-registered composer can never reach dispatch. This drives the
  // FLAG↔WHITELIST closure leg; it does NOT gate the harness write syscall.
  const writesAuditGraded = spec.writes_audit_graded === true;
  if (writesAuditGraded) {
    if (!AUDIT_GRADED_WRITER_TOOLS.includes(spec.name)) {
      throw new TypeError(
        `wrapWriteTool(${spec.name}): declares writes_audit_graded but is not in ` +
        `paths.js AUDIT_GRADED_WRITER_TOOLS (Y-P13 whitelist drift)`,
      );
    }
    DECLARED_AUDIT_GRADED_WRITERS.add(spec.name);
  } else if (AUDIT_GRADED_WRITER_TOOLS.includes(spec.name)) {
    throw new TypeError(
      `wrapWriteTool(${spec.name}): is whitelisted in AUDIT_GRADED_WRITER_TOOLS but ` +
      `does not set writes_audit_graded:true (Y-P13 missing declaration)`,
    );
  }

  const innerHandler = spec.handler;
  const inputSchema = spec.inputSchema;
  const toolName = spec.name;

  function wrappedHandler(args) {
    const safeArgs = args == null ? {} : args;
    try {
      runSchemaValidation(toolName, inputSchema, safeArgs);
    } catch (error) {
      recordPendingRetry(toolName, safeArgs, error);
      throw error;
    }

    let result;
    try {
      result = innerHandler(safeArgs);
    } catch (error) {
      // Inner handler INVALID_ARGUMENTS still feed the retry tracker.
      if (error && error.code === ERROR_CODES.INVALID_ARGUMENTS) {
        recordPendingRetry(toolName, safeArgs, error);
      }
      throw error;
    }

    const pending = consumePendingRetryForSuccess(toolName, safeArgs);
    if (pending) {
      safeEmitRuntimeDrift(toolName, safeArgs, pending);
    }
    return result;
  }

  return Object.freeze({
    ...spec,
    handler: wrappedHandler,
    writes_audit_graded: writesAuditGraded,
  });
}

// Y-P13 (T4) — FLAG↔WHITELIST closure self-check. Run on demand (CI + tests)
// against the live declaring set built up by wrapWriteTool. Surfaced as an
// export so the closure can be asserted AFTER every writer module is required
// (all-loaded snapshot), not racily at first-wrap.
function assertAuditGradedWriterClosure() {
  const result = auditGradedWriterClosure([...DECLARED_AUDIT_GRADED_WRITERS]);
  if (!result.ok) {
    throw new Error(
      `Y-P13 audit-graded writer closure violation: ` +
      `orphans=[${result.orphans.join(",")}] undeclared=[${result.undeclared.join(",")}]`,
    );
  }
  return result;
}

module.exports = Object.freeze({
  wrapWriteTool,
  MCP_SERVER_INTERNAL_BUNDLE,
  assertAuditGradedWriterClosure,
  // Exposed for testing only — production callers go through wrapWriteTool.
  _internals: Object.freeze({
    PENDING_RETRY_KEYS,
    buildRetryKey,
    DECLARED_AUDIT_GRADED_WRITERS,
  }),
});
