"use strict";

// Lock the pure defender relens of the grade verdict. computeDefenderDisposition
// projects (final severity × reachability × per-finding score × reportable) onto
// exactly one of {fix_now, worth_fixing, watch, held}, reusing the SAME
// SUBMIT/HOLD thresholds the grade verdict enforces (constants.js). The grade math
// is never re-derived here; this only maps the settled numbers to defender words.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  computeDefenderDisposition,
  DEFENDER_DISPOSITION_VALUES,
} = require("../mcp/core/defender-disposition.js");
const {
  GRADE_HOLD_MIN_SCORE,
  GRADE_SUBMIT_MIN_SCORE,
} = require("../mcp/lib/constants.js");

test("the four defender words are exactly the allowed vocabulary", () => {
  assert.deepEqual(DEFENDER_DISPOSITION_VALUES, ["fix_now", "worth_fixing", "watch", "held"]);
});

test("fix_now: reportable, severe band, scored to submit", () => {
  assert.equal(computeDefenderDisposition({ finalSeverity: "high", total_score: 50, reportable: true }), "fix_now");
  assert.equal(computeDefenderDisposition({ finalSeverity: "critical", total_score: GRADE_SUBMIT_MIN_SCORE, reportable: true }), "fix_now");
});

test("worth_fixing: reportable at submit score but below the severe band", () => {
  assert.equal(computeDefenderDisposition({ finalSeverity: "medium", total_score: GRADE_SUBMIT_MIN_SCORE, reportable: true }), "worth_fixing");
  assert.equal(computeDefenderDisposition({ finalSeverity: "medium", total_score: 99, reportable: true }), "worth_fixing");
});

test("watch: reportable, cleared the hold floor but not the submit floor", () => {
  assert.equal(computeDefenderDisposition({ finalSeverity: "medium", total_score: GRADE_HOLD_MIN_SCORE, reportable: true }), "watch");
  assert.equal(computeDefenderDisposition({ finalSeverity: "high", total_score: GRADE_SUBMIT_MIN_SCORE - 1, reportable: true }), "watch");
});

test("held: not reportable, below the hold floor, below-medium severity, or no severity", () => {
  // Not reportable — bob holds it even at a submit score / severe band.
  assert.equal(computeDefenderDisposition({ finalSeverity: "high", total_score: 50, reportable: false }), "held");
  // Below the hold floor.
  assert.equal(computeDefenderDisposition({ finalSeverity: "high", total_score: GRADE_HOLD_MIN_SCORE - 1, reportable: true }), "held");
  // Below the reportable-severity floor (low/info are not reportable in the verdict sense).
  assert.equal(computeDefenderDisposition({ finalSeverity: "low", total_score: 50, reportable: true }), "held");
  assert.equal(computeDefenderDisposition({ finalSeverity: "info", total_score: 50, reportable: true }), "held");
  // No severity at all.
  assert.equal(computeDefenderDisposition({ finalSeverity: null, total_score: 50, reportable: true }), "held");
  // Empty input is held (score coerces to 0, no severity).
  assert.equal(computeDefenderDisposition({}), "held");
  assert.equal(computeDefenderDisposition(), "held");
});

test("reachability is authoritative when it has spoken — a capped severity is graded, not the raw recorded one", () => {
  // A high recorded finding capped to low by reachability reads as held, even at a
  // submit score: the customer sees the graded-on truth, not the raw severity.
  assert.equal(computeDefenderDisposition({
    finalSeverity: "high", graded_severity: "low", disposition: "capped", total_score: 50, reportable: true,
  }), "held");
  // A medium recorded finding LIFTED to high by reachability is fix_now at a submit score.
  assert.equal(computeDefenderDisposition({
    finalSeverity: "medium", graded_severity: "high", disposition: "lifted", total_score: 50, reportable: true,
  }), "fix_now");
});

test("reachability spoke but the graded severity is malformed — fail CLOSED (held), never the uncapped recorded severity", () => {
  // A capped finding whose graded_severity is unusable must NOT fall back to the
  // recorded high (that would defeat the cap). It reads held, not fix_now.
  assert.equal(computeDefenderDisposition({
    finalSeverity: "high", graded_severity: "garbage", disposition: "capped", total_score: 90, reportable: true,
  }), "held");
  assert.equal(computeDefenderDisposition({
    finalSeverity: "critical", graded_severity: null, disposition: "capped", total_score: 90, reportable: true,
  }), "held");
});

test("an unknown reachability disposition falls back to the recorded final severity (never the ignored graded value)", () => {
  // disposition === "unknown" means reachability has NOT spoken; graded_severity is
  // ignored and the recorded high severity drives the word.
  assert.equal(computeDefenderDisposition({
    finalSeverity: "high", graded_severity: "low", disposition: "unknown", total_score: 50, reportable: true,
  }), "fix_now");
});

test("score boundaries are inclusive at the floors and truncated", () => {
  // Exactly at HOLD floor with a reportable medium is watch (>= floor).
  assert.equal(computeDefenderDisposition({ finalSeverity: "medium", total_score: GRADE_HOLD_MIN_SCORE, reportable: true }), "watch");
  // One below the HOLD floor is held.
  assert.equal(computeDefenderDisposition({ finalSeverity: "medium", total_score: GRADE_HOLD_MIN_SCORE - 1, reportable: true }), "held");
  // Fractional scores truncate (39.9 -> 39 -> watch, not worth_fixing).
  assert.equal(computeDefenderDisposition({ finalSeverity: "medium", total_score: 39.9, reportable: true }), "watch");
  // Non-finite score coerces to 0 -> held.
  assert.equal(computeDefenderDisposition({ finalSeverity: "high", total_score: NaN, reportable: true }), "held");
});

test("every result is a member of the sanctioned vocabulary", () => {
  const cases = [
    { finalSeverity: "critical", total_score: 80, reportable: true },
    { finalSeverity: "medium", total_score: 45, reportable: true },
    { finalSeverity: "medium", total_score: 25, reportable: true },
    { finalSeverity: "low", total_score: 10, reportable: false },
  ];
  for (const input of cases) {
    assert.ok(DEFENDER_DISPOSITION_VALUES.includes(computeDefenderDisposition(input)), `unexpected word for ${JSON.stringify(input)}`);
  }
});
