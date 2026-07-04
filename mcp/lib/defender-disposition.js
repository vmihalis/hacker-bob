"use strict";

// Pure defender RELENS of the deterministic grade verdict. The customer-facing
// surface (hosted-bob, /r reports) speaks DEFENDER, not BOUNTY: it must not
// render SUBMIT/HOLD/SKIP or any EV/triager prose. This module is the single
// projection from the SAME numbers the grade verdict already settles
// (final severity x reachability x rubric score x reportable bit) onto four
// defender words:
//
//   fix_now      a reportable, SUBMIT-eligible finding that lands severe.
//   worth_fixing a reportable, SUBMIT-eligible finding below the severe band.
//   watch        a reportable finding that clears HOLD but not SUBMIT.
//   held         not reportable, or below the HOLD floor — bob holds it.
//
// The verdict math is NOT re-derived here, it is REUSED:
//   - the SUBMIT/HOLD/SKIP thresholds are grade-verdict-store's
//     GRADE_SUBMIT_MIN_SCORE (40) and GRADE_HOLD_MIN_SCORE (20), imported
//     from constants.js so the two surfaces never drift;
//   - the graded severity is the reachability-CEILING'd severity
//     (reachability-ceiling.computeReachabilityDisposition's graded_severity),
//     i.e. what the engine actually grades on after capping/lifting — never
//     the raw recorded severity when reachability has moved it;
//   - the reportable bit is the final verification round's reportable flag,
//     the same bit requireFinalReportableSeveritySet gates SUBMIT on.
//
// I/O-free and schema-free: a projection over fields already on grade.json +
// the final-round results the caller has already loaded. No persistence, no
// new table, parallel-safe. The caller passes the resolved numbers; this file
// owns only the mapping from numbers to defender words.

const {
  GRADE_HOLD_MIN_SCORE,
  GRADE_SUBMIT_MIN_SCORE,
} = require("./constants.js");

const DEFENDER_DISPOSITION_VALUES = Object.freeze([
  "fix_now",
  "worth_fixing",
  "watch",
  "held",
]);

// The severe band the customer surface is allowed to mark with --signal-warn:
// recognition has COST. high/critical only — mirrors the Witness CVSS-cell
// idiom (severity is weight, with the lone ember reserved for the top bands).
const SEVERE_BANDS = Object.freeze(["high", "critical"]);

// medium-or-higher is the reportable-severity floor the grade verdict enforces
// (grade-verdict-store.isMediumOrHigher). A finding reported below medium is
// not reportable in the verdict sense and reads as held.
const REPORTABLE_SEVERITY_BANDS = Object.freeze(["medium", "high", "critical"]);

// Resolve the severity the disposition is read against. The reachability
// disposition's graded_severity is authoritative when reachability has spoken
// (capped/lifted/unchanged) — that is the severity the engine grades on. Only
// when reachability is unknown/absent do we fall back to the final round's
// recorded severity. Never invent above what the verified round recorded.
function resolveGradedSeverity({ finalSeverity, graded_severity, disposition }) {
  // When reachability has spoken, its graded severity is authoritative. If that
  // value is present but unusable, fail CLOSED (null -> held) — never fall back to
  // the UNCAPPED recorded severity, which would defeat the very cap reachability
  // applied and over-state a capped finding.
  if (disposition && disposition !== "unknown") {
    return isSeverity(graded_severity) ? graded_severity : null;
  }
  if (isSeverity(finalSeverity)) return finalSeverity;
  if (isSeverity(graded_severity)) return graded_severity;
  return null;
}

function isSeverity(value) {
  return typeof value === "string"
    && (REPORTABLE_SEVERITY_BANDS.includes(value) || value === "low" || value === "info");
}

// Pure projection: (final severity x reachability x score x reportable) -> word.
//
// The branch order is the verdict math, relit. A finding that is not reportable,
// or scores below the HOLD floor, is HELD (the SKIP arm). Above the HOLD floor
// but below SUBMIT is WATCH (the HOLD arm). At or above SUBMIT it is worth
// fixing — and if the graded severity lands in the severe band, it is FIX NOW
// (the only arm the surface may render with --signal/--signal-warn, because
// only here has recognition genuine cost).
function computeDefenderDisposition({
  finalSeverity = null,
  graded_severity = null,
  disposition = null,
  total_score = null,
  reportable = false,
} = {}) {
  const score = Number.isFinite(total_score) ? Math.trunc(total_score) : 0;
  const severity = resolveGradedSeverity({ finalSeverity, graded_severity, disposition });
  const reportableMedium = reportable === true
    && severity != null
    && REPORTABLE_SEVERITY_BANDS.includes(severity);

  // SKIP arm: bob holds it. Not reportable at medium+, or below the HOLD floor.
  if (!reportableMedium || score < GRADE_HOLD_MIN_SCORE) {
    return "held";
  }

  // HOLD arm: cleared the floor, not yet a submit. Watch it.
  if (score < GRADE_SUBMIT_MIN_SCORE) {
    return "watch";
  }

  // SUBMIT arm: worth fixing. Severe graded severity is the one terminus that
  // carries cost — fix now.
  if (SEVERE_BANDS.includes(severity)) {
    return "fix_now";
  }
  return "worth_fixing";
}

module.exports = {
  DEFENDER_DISPOSITION_VALUES,
  computeDefenderDisposition,
};
