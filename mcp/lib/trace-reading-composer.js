"use strict";

// Plane Y Cycle Y.5 (rev 4.1 W1) — Trace-reading expectations composer.
//
// The wave-scheduler brief renderer (mcp/lib/assignment-brief.js
// readAssignmentBrief) and any other per-role brief composer reads through
// this helper to produce the role-specific "trace-reading expectations"
// section per Y-P14d. The output is the structured, telemetry-attributable
// projection of FRICTION_PROMPT_FRAGMENTS (Y.2 ledger of canonical
// fragments) joined to ROLE_TRACE_EXPECTATIONS (Y.6 ledger of which
// fragments + producer ids each role consumes at which decision
// boundaries).
//
// Y.5 ships the COMPOSER; Y.6 lands the ROLE_TRACE_EXPECTATIONS registry.
// Per the Y.5 → Y.6 dependency edge in the rev-4.1 DAG the composer MUST
// degrade gracefully when the Y.6 module is absent: it returns null so
// the brief renderer can drop the slice entirely (mirrors the
// drop-empty-keys discipline in WEB_BRIEF_SLICE_REGISTRY).
//
// Output shape (when role-trace-expectations.js exists and the role has
// at least one mapped fragment):
//
//   {
//     role: "<role-id>",
//     fragments: [
//       {
//         fragment_id: "<id from FRICTION_PROMPT_FRAGMENTS>",
//         decision_boundary: "<closed-enum>",
//         producer_id: "<id from STIGMERGIC_PRODUCERS — Y.6>",
//         fragment_text: "<body from FRICTION_PROMPT_FRAGMENTS>"
//       },
//       ...
//     ]
//   }
//
// When the Y.6 registry is absent, or the role is not mapped, or all
// referenced fragment_ids are absent from FRICTION_PROMPT_FRAGMENTS, the
// composer returns null and the brief renderer drops the slice.
//
// Telemetry attribution per Y-P14d: fragment_id is the canonical handle so
// the brief metadata can carry it through to the dispatched subagent for
// later cross-reference at handoff inspection.

const path = require("path");
const fs = require("fs");

const {
  FRICTION_PROMPT_FRAGMENTS,
  isKnownFragmentId,
} = require("./friction-prompt-fragments.js");

// Module path is resolved relative to this file so the existence check is
// portable across installed copies + sandboxed test trees.
const ROLE_TRACE_EXPECTATIONS_PATH = path.resolve(
  __dirname,
  "role-trace-expectations.js",
);

function loadRoleTraceExpectationsIfPresent() {
  if (!fs.existsSync(ROLE_TRACE_EXPECTATIONS_PATH)) return null;
  // eslint-disable-next-line global-require
  const mod = require(ROLE_TRACE_EXPECTATIONS_PATH);
  if (!mod || typeof mod !== "object") return null;
  const registry = mod.ROLE_TRACE_EXPECTATIONS;
  if (!registry || typeof registry !== "object" || Array.isArray(registry)) return null;
  return registry;
}

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function composeTraceReadingExpectationsForRole(roleId) {
  if (typeof roleId !== "string" || roleId.length === 0) return null;

  const registry = loadRoleTraceExpectationsIfPresent();
  if (registry == null) return null;

  const entries = registry[roleId];
  if (!Array.isArray(entries) || entries.length === 0) return null;

  const fragments = [];
  for (const entry of entries) {
    if (!isPlainObject(entry)) continue;
    const { fragment_id, decision_boundary, producer_id } = entry;
    if (typeof fragment_id !== "string" || !isKnownFragmentId(fragment_id)) {
      // Forward-compat: skip a Y.6 entry whose fragment_id is not yet in
      // the Y.2 ledger. Y.6's own shape test asserts the cross-reference,
      // so a green-Y.6 + green-Y.2 tree never hits this branch.
      continue;
    }
    if (typeof decision_boundary !== "string" || decision_boundary.length === 0) continue;
    if (typeof producer_id !== "string" || producer_id.length === 0) continue;
    fragments.push({
      fragment_id,
      decision_boundary,
      producer_id,
      fragment_text: FRICTION_PROMPT_FRAGMENTS[fragment_id],
    });
  }

  if (fragments.length === 0) return null;

  return Object.freeze({
    role: roleId,
    fragments: Object.freeze(fragments.map((entry) => Object.freeze(entry))),
  });
}

module.exports = {
  ROLE_TRACE_EXPECTATIONS_PATH,
  composeTraceReadingExpectationsForRole,
};
