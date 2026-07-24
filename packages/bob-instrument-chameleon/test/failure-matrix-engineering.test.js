"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const plan = require("../../../test/manual/chameleon-failure-matrix.js");
const engineering = require("../lib/failure-matrix-engineering.js");

const {
  ENGINEERING_FAILURE_MATRIX_DIGEST,
  ENGINEERING_FAILURE_MATRIX_EXPECTED_CASE_COUNT,
  ENGINEERING_FAILURE_MATRIX_EXPECTED_EXTERNAL_READER_CASE_COUNT,
  ENGINEERING_FAILURE_MATRIX_EXPECTED_MAINTENANCE_CASE_COUNT,
  ENGINEERING_FAILURE_MATRIX_EXPECTED_PARITY_CASE_COUNT,
  executeChameleonFailureMatrixEngineering,
  projectChameleonFailureMatrixEngineeringSummary,
  verifyChameleonFailureMatrixEngineeringLedger,
} = engineering;

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value != null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function digest(value) {
  return crypto.createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex");
}

function authenticateMatrix(matrix) {
  const body = { ...matrix };
  delete body.matrix_digest;
  matrix.matrix_digest = digest(body);
  return matrix;
}

function authenticateLedger(ledger) {
  ledger.entries_digest = digest(ledger.entries);
  const body = { ...ledger };
  delete body.ledger_digest;
  ledger.ledger_digest = digest(body);
  return ledger;
}

function fixture() {
  const matrix = plan.buildFailureMatrix();
  const ledger = executeChameleonFailureMatrixEngineering(matrix);
  return {
    matrix,
    ledger,
    summary: projectChameleonFailureMatrixEngineeringSummary(matrix, ledger),
  };
}

test("PH-X5 engineering executor deterministically classifies all 734 reviewed cases", () => {
  const { matrix, ledger, summary } = fixture();
  assert.equal(matrix.matrix_digest, ENGINEERING_FAILURE_MATRIX_DIGEST);
  assert.equal(ENGINEERING_FAILURE_MATRIX_EXPECTED_CASE_COUNT, 734);
  assert.equal(ledger.case_count, 734);
  assert.equal(ledger.entries.length, 734);
  assert.equal(ledger.terminal_classification_count, 734);
  assert.equal(ledger.zero_active_effects_case_count, 734);
  assert.equal(ledger.missing_case_count, 0);
  assert.equal(ledger.verified_success_count, 0);
  assert.deepEqual({ ...ledger.terminal_counts }, {
    irreversible_authorized: 4,
    quarantined: 92,
    rejected_no_effect: 475,
    restored: 87,
    unknown_effect: 76,
  });
  assert.equal(ledger.ledger_digest,
    "e42ca71ef064841b9f7469f323ec50c12537402ee09fcf8b2889cc6d6daf234f");
  assert.equal(summary.summary_digest,
    "9b541369aa41a1be18e251822f1d6a791a53d1403498b1ad9e82862cb2b6d8f3");
  assert.equal(verifyChameleonFailureMatrixEngineeringLedger(matrix, ledger), ledger);
  assert.equal(Object.isFrozen(ledger), true);
  assert.equal(Object.isFrozen(ledger.entries), true);
  assert.equal(Object.isFrozen(ledger.entries[0]), true);

  const fromPlainCopy = executeChameleonFailureMatrixEngineering(
    JSON.parse(JSON.stringify(matrix)),
  );
  assert.deepEqual(fromPlainCopy, ledger);
});

test("every engineering entry has one terminal, zero active effects, and no success verdict", () => {
  const { ledger } = fixture();
  const ids = new Set();
  for (let index = 0; index < ledger.entries.length; index += 1) {
    const entry = ledger.entries[index];
    assert.equal(entry.sequence, index + 1);
    assert.equal(entry.terminal_classification_count, 1);
    assert.equal(entry.zero_active_effects, true);
    assert.equal(entry.verified_success, false);
    assert.equal(entry.engineering_only, true);
    assert.equal(entry.production_ready, false);
    assert.equal(entry.live_hil_evidence_present, false);
    assert.match(entry.case_digest, /^[a-f0-9]{64}$/u);
    assert.match(entry.observation_digest, /^[a-f0-9]{64}$/u);
    assert.match(entry.decision_digest, /^[a-f0-9]{64}$/u);
    assert.match(entry.cleanup_digest, /^[a-f0-9]{64}$/u);
    assert.equal(ids.has(entry.case_id), false);
    ids.add(entry.case_id);
  }
  assert.equal(ids.size, 734);
  assert.equal(Object.values(ledger.terminal_counts).reduce((sum, count) => sum + count, 0), 734);
  assert.deepEqual(Object.keys(ledger.stage_counts).sort(), [
    "cross_plane",
    "owned_maintenance_fixture",
    "owned_media",
    "rf_off",
    "shielded_active",
  ]);
});

test("USB/BLE parity covers each enabled transport-independent effect family symmetrically", () => {
  const { matrix, ledger } = fixture();
  assert.equal(ENGINEERING_FAILURE_MATRIX_EXPECTED_PARITY_CASE_COUNT, 93);
  assert.equal(ledger.transport_parity_case_count, 93);
  assert.deepEqual({ ...ledger.transport_parity_effect_family_counts }, {
    "instrument.transmit": 1,
    "target.destroy": 6,
    "target.mutate": 19,
    "target.present": 31,
    "target.transmit": 36,
  });
  const scenarios = new Map(matrix.scenarios.map((scenario) => [scenario.scenario_id, scenario]));
  const parityCases = matrix.failure_cases.filter((failureCase) => (
    failureCase.transport_pair_id != null
      || scenarios.get(failureCase.scenario_id)
        .evidence_requirements.same_operation_transport_parity_required
  ));
  assert.equal(parityCases.length, 93);
  for (const failureCase of parityCases) {
    const kinds = failureCase.required_evidence_contract_refs.map((row) => row.contract_kind);
    assert.equal(kinds.includes("transport_attempt_receipt_ble"), true);
    assert.equal(kinds.includes("transport_attempt_receipt_usb"), true);
    assert.equal(kinds.includes("transport_pair_comparison_verdict"), true);
    const entry = ledger.entries.find((row) => row.case_id === failureCase.case_id);
    assert.match(entry.transport_parity_digest, /^[a-f0-9]{64}$/u);
  }
});

test("maintenance and write-only cases retain invalidation and independent-reader obligations", () => {
  const { matrix, ledger } = fixture();
  const scenarios = new Map(matrix.scenarios.map((scenario) => [scenario.scenario_id, scenario]));
  const maintenance = matrix.failure_cases.filter((failureCase) => (
    scenarios.get(failureCase.scenario_id).stage === "owned_maintenance_fixture"
  ));
  const external = matrix.failure_cases.filter((failureCase) => (
    scenarios.get(failureCase.scenario_id).evidence_requirements.external_reader_required
  ));
  assert.equal(maintenance.length, ENGINEERING_FAILURE_MATRIX_EXPECTED_MAINTENANCE_CASE_COUNT);
  assert.equal(external.length, ENGINEERING_FAILURE_MATRIX_EXPECTED_EXTERNAL_READER_CASE_COUNT);
  assert.equal(ledger.maintenance_case_count, 12);
  assert.equal(ledger.external_reader_case_count, 9);
  for (const failureCase of maintenance) {
    assert.deepEqual(
      failureCase.required_evidence_contract_refs.map((row) => row.contract_kind).sort(),
      ["assurance_invalidation", "backup", "exact_delta", "post_operation_inventory",
        "pre_state_snapshot", "recovery_or_quarantine"],
    );
    const entry = ledger.entries.find((row) => row.case_id === failureCase.case_id);
    assert.match(entry.maintenance_invalidation_digest, /^[a-f0-9]{64}$/u);
  }
  for (const failureCase of external) {
    assert.equal(failureCase.required_evidence_contract_refs.some(
      (row) => row.contract_kind === "external_reader_verdict",
    ), true);
    const entry = ledger.entries.find((row) => row.case_id === failureCase.case_id);
    assert.match(entry.external_reader_requirement_digest, /^[a-f0-9]{64}$/u);
  }
});

test("digest-only summary cannot be mistaken for live, HIL, production, or evidence authority", () => {
  const { summary } = fixture();
  assert.equal(summary.engineering_gate_passed, true);
  assert.equal(summary.engineering_only, true);
  assert.equal(summary.hil_gate_passed, false);
  assert.equal(summary.live_hil_evidence_present, false);
  assert.equal(summary.production_ready, false);
  assert.equal(summary.hardware_access_authorized, false);
  assert.equal(summary.evidence_authority, false);
  assert.equal(summary.verified_success_count, 0);
  const printed = JSON.stringify(summary);
  assert.doesNotMatch(printed, /hil-case:|scenario_id|fixture_ref|principal_ref|contract_ref|evidence_key/u);
  assert.doesNotMatch(printed, /effect_started|baseline_restoration|independent_effect_observation/u);
});

test("reviewed matrix binding rejects omissions, substitutions, authority drift, and executable data", () => {
  const original = plan.buildFailureMatrix();
  const production = JSON.parse(JSON.stringify(original));
  production.execution_policy.production_ready = true;
  authenticateMatrix(production);
  assert.throws(
    () => executeChameleonFailureMatrixEngineering(production),
    /unreviewed matrix digest/u,
  );

  const omitted = JSON.parse(JSON.stringify(original));
  omitted.failure_cases.pop();
  omitted.failure_case_count -= 1;
  omitted.failure_case_registry_sha256 = digest(omitted.failure_cases);
  authenticateMatrix(omitted);
  assert.throws(
    () => executeChameleonFailureMatrixEngineering(omitted),
    /unreviewed matrix digest/u,
  );

  assert.throws(
    () => executeChameleonFailureMatrixEngineering(new Proxy(original, {})),
    /proxy/u,
  );
  const nestedProxy = JSON.parse(JSON.stringify(original));
  nestedProxy.failure_cases[0] = new Proxy(nestedProxy.failure_cases[0], {});
  assert.throws(() => executeChameleonFailureMatrixEngineering(nestedProxy), /proxy/u);

  const accessor = JSON.parse(JSON.stringify(original));
  let getterCalled = false;
  Object.defineProperty(accessor.scenarios[0], "scenario_id", {
    enumerable: true,
    get() {
      getterCalled = true;
      return "substituted";
    },
  });
  assert.throws(() => executeChameleonFailureMatrixEngineering(accessor), /passive data/u);
  assert.equal(getterCalled, false);
});

test("ledger verification and summary projection reject stale and reauthenticated tampering", () => {
  const { matrix, ledger } = fixture();
  const stale = structuredClone(ledger);
  stale.entries[0].terminal_state = "unknown_effect";
  assert.throws(
    () => verifyChameleonFailureMatrixEngineeringLedger(matrix, stale),
    /not the deterministic reviewed execution/u,
  );
  assert.throws(
    () => projectChameleonFailureMatrixEngineeringSummary(matrix, stale),
    /not the deterministic reviewed execution/u,
  );

  const weakened = structuredClone(ledger);
  weakened.entries[0].verified_success = true;
  authenticateLedger(weakened);
  assert.throws(
    () => projectChameleonFailureMatrixEngineeringSummary(matrix, weakened),
    /not the deterministic reviewed execution/u,
  );
});

test("engineering executor source has no hardware, transport, persistence, clock, or callback port", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "lib",
    "failure-matrix-engineering.js"), "utf8");
  const imports = [...source.matchAll(/require\("([^"]+)"\)/gu)].map((match) => match[1]);
  assert.deepEqual(imports, ["node:crypto", "node:util"]);
  for (const forbidden of [
    "node:fs", "node:net", "node:http", "node:https", "node:dgram", "node:child_process",
    "node:worker_threads", "serialport", "usb-detection", "CoreBluetooth", "WebSocket",
    "globalThis.fetch", "process.env", "Date.now", "setTimeout", "setInterval", "Math.random",
  ]) {
    assert.equal(source.includes(forbidden), false, `forbidden executor primitive: ${forbidden}`);
  }
  assert.equal(executeChameleonFailureMatrixEngineering.length, 1);
  assert.equal(projectChameleonFailureMatrixEngineeringSummary.length, 2);
  assert.equal(verifyChameleonFailureMatrixEngineeringLedger.length, 2);
  let invoked = false;
  executeChameleonFailureMatrixEngineering(plan.buildFailureMatrix(), () => {
    invoked = true;
    throw new Error("executor invoked an undeclared callback");
  });
  assert.equal(invoked, false);
});
