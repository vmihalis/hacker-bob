"use strict";

// Plane Y Cycle Y.4 (rev 4 — O5 absorbed) — Auxiliary tools per target_class.
//
// `deriveAuxiliaryToolsForTargetClass(target_class)` returns an immutable
// list of MCP tool names to UNION into `allowed_tools_for_node[]` for the
// given `target_class`. PURE per Y-P4 — the function reads only its single
// closed-enum argument; no clock, no random, no env, no I/O.
//
// Target-class auxiliary tools (closed by construction):
//   - `phishing_fraud`     → public-intel + 3 browser tools so a phishing
//                            kit triage flow surfaces OSINT + DOM/console
//                            capture mechanically.
//   - `smart_contract`     → empty array. Per-stack tools come from the
//                            existing capability-pack derivation (web /
//                            evm / svm / aptos / sui / substrate /
//                            cosmwasm), not from the target_class axis.
//   - `web_application`    → empty array. Web tools already flow through
//                            the per-Surface `web` capability pack; the
//                            target_class axis does NOT auto-include
//                            phishing-specific tools for plain web apps.
//   - `mobile_app`         → empty array (no mobile auxiliary at this rev).
//   - `infrastructure`     → empty array.
//   - `other`              → empty array.
//
// The Y.5 wave scheduler is the sole caller-site (Y-P4: target_class is
// caller-side; the pure derivation just consumes the bounded enum).

const { TARGET_CLASS_VALUES, assertTargetClass } = require("./target-classes.js");

// ─── Pure target-class derivation ───────────────────────────────────────
//
// Everything below the divider is the body the load-time purity guard
// inspects. Keep clock / random / env reads OUT of this section.

// Frozen per-target_class auxiliary tool lists. Phishing fraud is the only
// non-empty entry at this rev; the other target_class values get an empty
// frozen array so callers can iterate without special-casing.
const AUXILIARY_TOOLS_BY_TARGET_CLASS = Object.freeze({
  phishing_fraud: Object.freeze([
    "bob_public_intel",
    "bob_browser_evaluate",
    "bob_browser_take_screenshot",
    "bob_browser_console_messages",
  ]),
  smart_contract: Object.freeze([]),
  web_application: Object.freeze([]),
  mobile_app: Object.freeze([]),
  infrastructure: Object.freeze([]),
  other: Object.freeze([]),
});

function deriveAuxiliaryToolsForTargetClass(target_class) {
  // Throws on unknown — Y.4 Reviewer bullet 4 ("unknown target_class
  // rejected"). The validator lives in target-classes.js so the same
  // assertion runs on derivePackForNode's input path and here.
  assertTargetClass(target_class);
  const tools = AUXILIARY_TOOLS_BY_TARGET_CLASS[target_class];
  // Defensive: every closed-enum value must have a frozen entry. If a new
  // TARGET_CLASS_VALUES member ever lands without a matching auxiliary
  // entry the function returns an empty list rather than `undefined`.
  if (!Array.isArray(tools)) return Object.freeze([]);
  return tools;
}

// Module-load-time lint guard: the body of this file MUST stay pure per
// Y-P4 (X-P4 lint scope extended in Y.4). Same shape as the X.5 guard in
// capability-pack-derivation.js — read own source below the divider,
// strip comments + string literals + regex literals, then assert no
// `Date.`, `Date(`, `new Date`, `Math.random`, `process.env`,
// `performance.now`.
(function lintPureTargetClassDerivation() {
  const fs = require("fs");
  const path = require("path");
  let source;
  try {
    source = fs.readFileSync(__filename, "utf8");
  } catch {
    return;
  }
  const divider = "─── Pure target-class derivation ───";
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
        `target-class-pack-derivation purity lint: forbidden pattern \`${label}\` `
        + "found in derivation body — Y-P4 requires pure inputs only "
        + "(no clock, no random, no env reads). Move the side effect into "
        + "the Y.5 wave-scheduler caller.",
      );
    }
  }
  if (!__filename.endsWith(path.sep + "target-class-pack-derivation.js")) {
    throw new Error(
      `target-class-pack-derivation purity lint: unexpected filename ${__filename}; `
      + "the lint guard expects this module to live at mcp/lib/target-class-pack-derivation.js.",
    );
  }
})();

module.exports = {
  AUXILIARY_TOOLS_BY_TARGET_CLASS,
  TARGET_CLASS_VALUES,
  deriveAuxiliaryToolsForTargetClass,
};
