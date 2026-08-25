"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendCandidateClaim } = require("../mcp/core/claims/claims.js");
const {
  beliefModelInfoPath,
  gradeArtifactPaths,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/core/io/paths.js");
const {
  _internals,
  LEARNED_MEASUREMENT_ADMITTED,
  LEARNED_MEASUREMENT_HOLD_SOFT_SOURCE,
  LEARNED_MEASUREMENT_HOLD_UNKNOWN_CLASS,
  LEARNED_MEASUREMENT_HOLD_UNSIGNED_CAPTURE,
  LEARNED_MEASUREMENT_NEVER_CLOSES,
  buildLearnedSemanticMeasurement,
  readBeliefModelInfo,
  trainBeliefModel,
} = require("../mcp/core/belief/model.js");
const trainBeliefModelTool = require("../mcp/tools/train-belief-model.js");
const readBeliefModelInfoTool = require("../mcp/tools/read-belief-model-info.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-belief-model-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function hex(ch) {
  return ch.repeat(64);
}

function learnedMeasurementInput(overrides = {}) {
  return {
    target_domain: "learned-measurement.example.com",
    class_id: "harmful_uplift",
    source_authority: "instrument",
    captured_output: {
      artifact_ref: "captures/output-1.json",
      content_hash: hex("a"),
      row_mac_verified: true,
    },
    judge: {
      judge_id: "t2-harm-judge",
      version: "2026-08-23.1",
      model_digest: hex("b"),
      runtime_digest: hex("c"),
      config_digest: hex("d"),
    },
    calibration: {
      issuer: "independent-labeling-board",
      certificate_digest: hex("e"),
      labels_digest: hex("f"),
      independent_labels: true,
      coverage_class_ids: ["harmful_uplift"],
      valid_from: "2026-08-01T00:00:00.000Z",
      valid_until: "2026-09-01T00:00:00.000Z",
      ood_adversarial_passed: true,
      drift_check_passed: true,
    },
    invocation: {
      observed_at: "2026-08-23T00:00:00.000Z",
      context_digest: hex("1"),
    },
    result: {
      score: 0.97,
      label: "harmful",
      abstain: false,
      ood: false,
      shifted: false,
    },
    ...overrides,
  };
}

function seedLabeledDomain({ domain, findingId, label, causalSupport }) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  appendCandidateClaim({
    target_domain: domain,
    claim_id: `claim-${findingId}`,
    title: `Claim ${findingId}`,
    summary: `Sanitized summary ${findingId}`,
    severity: label === 1 ? "high" : "low",
    evidence_refs: [
      {
        kind: "finding",
        finding_id: findingId,
      },
    ],
    payload: {
      causal_support: causalSupport,
      proof_of_concept: "sanitized proof text that should not appear in model output",
    },
  });
  writeJson(verificationRoundPaths(domain, "final").json, {
    results: [
      {
        finding_id: findingId,
        disposition: label === 1 ? "confirmed" : "denied",
        reportable: label === 1,
        confidence: label === 1 ? "high" : "low",
        confidence_reasons: label === 1
          ? ["fresh_replay_passed"]
          : ["missing_control", "unruled_confounder"],
      },
    ],
  });
  writeJson(gradeArtifactPaths(domain).json, {
    verdict: label === 1 ? "SUBMIT" : "SKIP",
    total_score: label === 1 ? 75 : 0,
    findings: [
      {
        finding_id: findingId,
        total_score: label === 1 ? 75 : 0,
      },
    ],
  });
  fs.writeFileSync(
    path.join(sessionDir(domain), "report.md"),
    "Authorization: Bearer REPORT_SECRET_SHOULD_NOT_APPEAR_IN_MODEL\n",
  );
}

test("belief model trainer writes inspectable advisory metadata from sanitized labels", () => {
  assert.equal(trainBeliefModelTool.mutating, true);
  assert.equal(trainBeliefModelTool.network_access, false);
  assert.deepEqual(trainBeliefModelTool.session_artifacts_written, ["belief-scratch/belief-model-info.json"]);
  assert.equal(readBeliefModelInfoTool.mutating, false);

  withTempHome(() => {
    const positive = "belief-model-positive.example.com";
    const negative = "belief-model-negative.example.com";
    const target = "belief-model-target.example.com";
    seedLabeledDomain({
      domain: positive,
      findingId: "F-POS",
      label: 1,
      causalSupport: {
        mechanism_id: "object_authorization",
        controls_run: ["victim-auth-denied", "attacker-auth-denied"],
        confounders_ruled_out: ["cache", "stale_role"],
      },
    });
    seedLabeledDomain({
      domain: negative,
      findingId: "F-NEG",
      label: 0,
      causalSupport: {
        mechanism_id: "object_authorization",
        controls_run: [],
        confounders_ruled_out: [],
      },
    });

    const model = trainBeliefModel({
      target_domain: target,
      training_domains: [positive, negative],
      holdout_domains: [positive, negative],
    });
    assert.equal(fs.existsSync(beliefModelInfoPath(target)), true);
    assert.equal(model.model_version, "belief-calibrated-factors.v1");
    assert.equal(model.training_summary.example_count, 2);
    assert.equal(model.calibration_report.held_out, true);
    assert.equal(model.calibration_report.example_count, 2);
    assert.equal(typeof model.calibration_report.brier_improvement, "number");
    assert.ok(Array.isArray(model.calibration_report.reliability_curve));
    assert.equal(model.raw_predictor, "hand_score");
    // honest data-starvation: 2 pooled labels cannot fit a recalibration -> identity map
    assert.equal(model.recalibration_map.kind, "identity");
    assert.equal(model.calibration_report.needs_more_data, true);
    assert.equal(model.advisory, true);
    assert.equal(model.claim_authority, false);
    assert.equal(model.dispatch_authority, false);
    assert.equal(model.default_enablement_ready, false);

    const serialized = JSON.stringify(model);
    assert.doesNotMatch(serialized, /sanitized proof text/);
    assert.doesNotMatch(serialized, /REPORT_SECRET/);

    const read = readBeliefModelInfo({ target_domain: target });
    assert.equal(read.exists, true);
    assert.equal(read.model.model_hash, model.model_hash);
  });
});

test("belief model info reader reports missing model without creating artifacts", () => {
  withTempHome(() => {
    const domain = "belief-model-missing.example.com";
    const read = readBeliefModelInfo({ target_domain: domain });
    assert.equal(read.exists, false);
    assert.equal(fs.existsSync(sessionDir(domain)), false);
  });
});

test("belief model labels prefer per-finding grade scores and model ids are bounded", () => {
  assert.equal(
    _internals.labelFor({
      finalResult: { disposition: "confirmed", reportable: true },
      gradeResult: { total_score: 0 },
      gradeVerdict: "SUBMIT",
    }),
    0,
  );
  assert.equal(_internals.normalizeOptionalModelId("BM-local_1:v1"), "BM-local_1:v1");
  assert.throws(
    () => _internals.normalizeOptionalModelId("Authorization: Bearer secret"),
    /model_id must be 1-80 chars/,
  );
});

test("learned semantic judge emits only a digest-bound advisory measurement row", () => {
  const row = buildLearnedSemanticMeasurement(learnedMeasurementInput());

  assert.equal(row.kind, "learned_semantic_measurement");
  assert.equal(row.measurement_version, "learned-semantic-measurement.v1");
  assert.equal(row.proof_mode, "learned_measurement_advisory_v1");
  assert.equal(row.admission.admissible, true);
  assert.equal(row.admission.reason, LEARNED_MEASUREMENT_ADMITTED);
  assert.equal(row.closure_decision.close, false);
  assert.equal(row.closure_decision.disposition, "HOLD");
  assert.equal(row.closure_decision.reason, LEARNED_MEASUREMENT_NEVER_CLOSES);
  assert.equal(row.closure_decision.independent_registered_proof_required, true);
  assert.equal(row.advisory, true);
  assert.equal(row.claim_authority, false);
  assert.equal(row.verification_authority, false);
  assert.equal(row.grade_authority, false);
  assert.equal(row.dispatch_authority, false);
  assert.equal(row.closure_authority, false);
  assert.match(row.signature_context_hash, /^[0-9a-f]{64}$/);
  assert.match(row.measurement_hash, /^[0-9a-f]{64}$/);
  assert.equal(Object.prototype.hasOwnProperty.call(row.captured_output_ref, "text"), false);
});

test("forged soft unknown learned measurement fails closed to HOLD", () => {
  const row = buildLearnedSemanticMeasurement(learnedMeasurementInput({
    class_id: "novel_autonomous_class",
    source_authority: "generated_hypothesis",
    captured_output: {
      artifact_ref: "captures/forged-output.json",
      content_hash: hex("2"),
      row_mac_verified: false,
      text: "raw target output must not enter the row",
    },
    calibration: {
      issuer: "independent-labeling-board",
      certificate_digest: hex("3"),
      labels_digest: hex("4"),
      independent_labels: true,
      coverage_class_ids: ["harmful_uplift"],
      valid_from: "2026-08-01T00:00:00.000Z",
      valid_until: "2026-09-01T00:00:00.000Z",
      ood_adversarial_passed: true,
      drift_check_passed: true,
    },
    result: {
      score: 0.99,
      label: "harmful",
      abstain: false,
      ood: false,
      shifted: false,
    },
  }));

  assert.equal(row.admission.admissible, false);
  assert.equal(row.admission.reason, LEARNED_MEASUREMENT_HOLD_UNKNOWN_CLASS);
  assert.ok(row.admission.hold_reasons.includes(LEARNED_MEASUREMENT_HOLD_UNKNOWN_CLASS));
  assert.ok(row.admission.hold_reasons.includes(LEARNED_MEASUREMENT_HOLD_SOFT_SOURCE));
  assert.ok(row.admission.hold_reasons.includes(LEARNED_MEASUREMENT_HOLD_UNSIGNED_CAPTURE));
  assert.equal(row.closure_decision.close, false);
  assert.equal(row.closure_decision.disposition, "HOLD");
  assert.equal(row.closure_authority, false);
  assert.equal(JSON.stringify(row).includes("raw target output"), false);
});
