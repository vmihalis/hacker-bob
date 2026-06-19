"use strict";

// Plane Y Cycle Y.4 — Caller-side friction selector.
//
// `selectRelevantFrictions(allFrictions, node, options)` returns the bounded
// `friction_history` slice that the Y.5 wave scheduler threads into
// `derivePackForNode`. The selector lives in its own module — and the
// X-P4 lint scope is extended to cover it (Y.4 Do step 6) — so the
// derivation function stays pure: the work of pulling recent frictions
// from session storage, applying any operator-supplied filters, and
// capping the list happens HERE, in the caller side.
//
// PURE per Y-P4 — the function takes everything it needs as arguments,
// returns a fresh array, and reads no clock / random / env / I/O.
//
// Selection rules (closed):
//   1. Only frictions whose `surface_id` matches a `surface_ref` of the
//      dispatched node are included (wave-scoped, Y-P5).
//   2. Records are de-duped by the Y-P3 5-tuple
//      (run_id, node_id, wanted_tool, friction_kind, detected_by).
//   3. `tool_inadequate` frictions are EXCLUDED unless
//      `options.include_inadequacy === true` (Y-P11 voluntary +
//      synthetic quarantine — operator must opt in).
//   4. Result is hard-capped at `options.limit` (default 32 per Y-P4
//      bounded input).

// ─── Pure friction selection ────────────────────────────────────────────
//
// Everything below the divider is the body the load-time purity guard
// inspects. Keep clock / random / env reads OUT of this section.

const DEFAULT_LIMIT = 32;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function asStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((entry) => typeof entry === "string" && entry.length > 0);
}

function frictionKeyForDedupe(record) {
  // Y-P3 5-tuple. Anything missing collapses to empty string so the key
  // is stable; the validator at Y.2 emit time guarantees the 5 fields
  // populate when the record was appended through bob_log_capability_friction.
  return [
    typeof record.run_id === "string" ? record.run_id : "",
    typeof record.node_id === "string" ? record.node_id : "",
    typeof record.wanted_tool === "string" ? record.wanted_tool : "",
    typeof record.friction_kind === "string" ? record.friction_kind : "",
    typeof record.detected_by === "string" ? record.detected_by : "",
  ].join("|");
}

function selectRelevantFrictions(allFrictions, node, options) {
  if (!Array.isArray(allFrictions)) return [];
  if (!isPlainObject(node)) {
    throw new Error("selectRelevantFrictions: node must be an object");
  }
  const opts = isPlainObject(options) ? options : {};
  const includeInadequacy = opts.include_inadequacy === true;
  // limit is bounded by construction — caller-supplied values are clamped
  // to [1, DEFAULT_LIMIT] so a stray operator-set big number can't blow the
  // Y-P4 bound.
  let limit = Number.isInteger(opts.limit) ? opts.limit : DEFAULT_LIMIT;
  if (limit < 1) limit = 1;
  if (limit > DEFAULT_LIMIT) limit = DEFAULT_LIMIT;

  const surfaceRefs = new Set(asStringArray(node.surface_refs));
  const seen = new Set();
  const out = [];
  for (const record of allFrictions) {
    if (!isPlainObject(record)) continue;
    // Rule 3: tool_inadequate quarantine.
    if (record.friction_kind === "tool_inadequate" && !includeInadequacy) {
      continue;
    }
    // Rule 1: wave-scoped surface match. A friction without a surface_id
    // is excluded (it can't be wave-scoped). Surface refs is a Set so the
    // membership test is O(1).
    if (typeof record.surface_id !== "string" || !surfaceRefs.has(record.surface_id)) {
      continue;
    }
    // Rule 2: 5-tuple dedupe.
    const key = frictionKeyForDedupe(record);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(record);
    if (out.length >= limit) break;
  }
  return out;
}

// Module-load-time lint guard. The friction-selection body MUST stay pure
// per Y-P4 (X-P4 lint scope extended in Y.4 Do step 6). Same shape as the
// X.5 guard in capability-pack-derivation.js.
(function lintPureFrictionSelection() {
  const fs = require("fs");
  const path = require("path");
  let source;
  try {
    source = fs.readFileSync(__filename, "utf8");
  } catch {
    return;
  }
  const divider = "─── Pure friction selection ───";
  const dividerIdx = source.indexOf(divider);
  const body = dividerIdx >= 0 ? source.slice(dividerIdx) : source;
  const stripped = body
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/`(?:\\.|[^`\\])*`/g, "``")
    .replace(/([=(,:&|!])\s*\/(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\])+\/[a-z]*/g, "$1 /__re__/");
  const forbidden = [
    { re: new RegExp("\\b" + "Date" + "\\s*\\."), label: ["Date", "."].join("") },
    { re: new RegExp("\\b" + "Date" + "\\s*\\("), label: ["Date", "()"].join("") },
    { re: new RegExp("\\bnew\\s+" + "Date" + "\\b"), label: ["new ", "Date"].join("") },
    { re: new RegExp("\\b" + "Math" + "\\.random\\b"), label: ["Math", ".random"].join("") },
    { re: new RegExp("\\b" + "process" + "\\.env\\b"), label: ["process", ".env"].join("") },
    { re: new RegExp("\\b" + "performance" + "\\.now\\b"), label: ["performance", ".now"].join("") },
  ];
  for (const { re, label } of forbidden) {
    if (re.test(stripped)) {
      throw new Error(
        `friction-selection purity lint: forbidden pattern \`${label}\` `
        + "found in selection body — Y-P4 requires pure inputs only "
        + "(no clock, no random, no env reads). Move the side effect into "
        + "the Y.5 wave-scheduler caller.",
      );
    }
  }
  if (!__filename.endsWith(path.sep + "friction-selection.js")) {
    throw new Error(
      `friction-selection purity lint: unexpected filename ${__filename}; `
      + "the lint guard expects this module to live at mcp/lib/friction-selection.js.",
    );
  }
})();

module.exports = {
  DEFAULT_LIMIT,
  selectRelevantFrictions,
};
