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
