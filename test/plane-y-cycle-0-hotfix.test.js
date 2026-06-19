"use strict";

// Plane Y cycle Y.0 — pre-cycle hotfix bundle (Y-D20 extended per rev 4.1).
// Three hotfix sub-deliverables ship as the Y.0 cycle:
//   1. O2 — bob_record_candidate_claim per-field cap raise + secret_detection_bypass.
//   2. O3 — bob_write_verification_round artifact_hashes regex accepts md5 + sha256.
//   3. Y-D18 — test/fixtures/ directory + benchmark-baseline.json seed for Y-R17 budget.
// Each sub-deliverable carries a regression test against the failure mode that
// motivated the hotfix; the test imports live caps and constants from source
// so future cap changes propagate without duplicated literals.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const writeVerificationRoundTool = require("../mcp/lib/tools/write-verification-round.js");
const {
  CLAIM_TEXT_LIMITS,
  SECRET_DETECTION_BYPASS_FIELDS,
} = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");
const {
  fieldObservedPayload,
} = require("./fixtures/o2-field-observed-payload.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-plane-y-y0-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetMaterializationDebounce();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Field-observed payload retained from the O2 ticket lives in
// test/fixtures/o2-field-observed-payload.js so the Y.1 capability-observation
// shape test can re-use the exact same payload without duplicating literals
// (Y.1 EXTEND deliverable per plane-y-hypergraph rev 4.1).

test("Y.0 hotfix 1 (O2): record-candidate-claim caps live in source and accept the field-observed payload", () => {
  // Caps are imported from source — no duplicated literals.
  assert.ok(CLAIM_TEXT_LIMITS.description >= 16000, "description cap must be >= 16000 to accommodate field-observed payloads");
  assert.ok(CLAIM_TEXT_LIMITS.proof_of_concept >= 16000, "proof_of_concept cap must be >= 16000");
  assert.ok(CLAIM_TEXT_LIMITS.response_evidence >= 16000, "response_evidence cap must be >= 16000");
  assert.ok(CLAIM_TEXT_LIMITS.impact >= 8000, "impact cap must be >= 8000");

  withTempHome(() => {
    const domain = "y0-hotfix-1.example.com";
    const payload = fieldObservedPayload(domain);
    // Pre-bypass call must fail because the PoC narrative inlines a bearer token.
    assert.throws(
      () => recordCandidateClaimTool.handler(payload),
      /appears to contain secrets|authorization|cookies|tokens/i,
      "raw payload must trip the sensitive-material validator before bypass is wired",
    );

    // After declaring the bypass on the affected fields, the call must succeed.
    const bypassed = {
      ...payload,
      secret_detection_bypass: [
        { field: "description", rationale: "victim bearer surfaced inline in repro narrative; not a Bob-side credential" },
        { field: "proof_of_concept", rationale: "victim bearer surfaced inline in repro narrative; not a Bob-side credential" },
      ],
    };
    const response = JSON.parse(recordCandidateClaimTool.handler(bypassed));
    assert.equal(response.recorded, true, "post-bypass call must record the candidate claim");
    assert.match(response.finding_id, /^F-\d+$/);
    assert.match(response.claim_id, /^CL-/);
    assert.ok(response.written_jsonl.endsWith("claims.jsonl"));
  });
});

test("Y.0 hotfix 1 (O2): secret_detection_bypass rejects unknown fields + missing rationale", () => {
  withTempHome(() => {
    const domain = "y0-hotfix-1b.example.com";
    const payload = fieldObservedPayload(domain);

    assert.throws(
      () => recordCandidateClaimTool.handler({
        ...payload,
        secret_detection_bypass: [{ field: "title", rationale: "unsupported field" }],
      }),
      /secret_detection_bypass\.field must be one of/,
    );

    assert.throws(
      () => recordCandidateClaimTool.handler({
        ...payload,
        secret_detection_bypass: [{ field: "description" }],
      }),
      /secret_detection_bypass\.rationale/,
    );

    // Field set exported from source; tests reference live enum.
    assert.deepEqual(
      Array.from(SECRET_DETECTION_BYPASS_FIELDS).sort(),
      ["description", "impact", "proof_of_concept", "response_evidence"],
    );
  });
});

test("Y.0 hotfix 1 (O2): bypass does NOT disable length cap on the affected field", () => {
  withTempHome(() => {
    const domain = "y0-hotfix-1c.example.com";
    const oversize = "X".repeat(CLAIM_TEXT_LIMITS.description + 1);
    const payload = {
      ...fieldObservedPayload(domain),
      description: oversize,
      proof_of_concept: "short normal repro",
      secret_detection_bypass: [{ field: "description", rationale: "test cap retention under bypass" }],
    };
    assert.throws(
      () => recordCandidateClaimTool.handler(payload),
      /description is too large/,
    );
  });
});

test("Y.0 hotfix 1 (O2): inputSchema declares secret_detection_bypass with closed-enum field", () => {
  const schema = recordCandidateClaimTool.inputSchema;
  assert.ok(schema.properties.secret_detection_bypass, "inputSchema must declare secret_detection_bypass");
  const itemSchema = schema.properties.secret_detection_bypass.items;
  assert.deepEqual(itemSchema.properties.field.enum.sort(), [
    "description",
    "impact",
    "proof_of_concept",
    "response_evidence",
  ]);
  assert.ok(itemSchema.required.includes("field"));
  assert.ok(itemSchema.required.includes("rationale"));
});

test("Y.0 hotfix 2 (O3): write-verification-round inputSchema artifact_hashes pattern accepts md5 (32 hex) and sha256 (64 hex)", () => {
  const schema = writeVerificationRoundTool.inputSchema;
  const valuePattern = schema.properties.results.items.properties.artifact_hashes.additionalProperties.pattern;
  const re = new RegExp(valuePattern);

  const md5 = "a".repeat(32);
  const sha256 = "b".repeat(64);
  const uppercaseSha256 = "A".repeat(64);
  const tooShort = "a".repeat(31);
  const tooLong = "a".repeat(65);
  const odd = "a".repeat(40);

  assert.ok(re.test(md5), "md5 (32 lowercase hex) must match");
  assert.ok(re.test(sha256), "sha256 (64 lowercase hex) must match (back-compat)");
  assert.equal(re.test(uppercaseSha256), false, "uppercase hex must be rejected (canonical lowercase)");
  assert.equal(re.test(tooShort), false, "31 hex chars must be rejected");
  assert.equal(re.test(tooLong), false, "65 hex chars must be rejected");
  assert.equal(re.test(odd), false, "40 hex chars (neither md5 nor sha256) must be rejected");
});

test("Y.0 hotfix 2 (O3): normalizeArtifactHashes accepts md5 and sha256, rejects non-canonical hashes", () => {
  // Validate at the store layer (the wrapWriteTool surface) so the round-trip
  // works end-to-end; the round-store enforces the same regex.
  const { normalizeVerificationRoundDocument } = require("../mcp/lib/verification-round-store.js");
  const findingIdSet = new Set(["F-1"]);
  const md5 = "a".repeat(32);
  const sha256 = "b".repeat(64);

  const acceptedDoc = normalizeVerificationRoundDocument({
    version: 2,
    target_domain: "y0-hotfix-2.example.com",
    round: "brutalist",
    notes: null,
    verification_attempt_id: "VA-y0-1",
    verification_snapshot_hash: "c".repeat(64),
    round_profile: "brutalist-default",
    results: [
      {
        finding_id: "F-1",
        disposition: "confirmed",
        severity: "high",
        reportable: true,
        reasoning: "Fresh replay confirmed the finding.",
        confidence: "high",
        confidence_reasons: ["fresh_replay_passed"],
        state_sensitive: false,
        artifact_hashes: { "md5-artifact": md5, "sha256-artifact": sha256 },
        inherited_confidence_reasons: [],
        resolved_confidence_reasons: [],
      },
    ],
  }, { expectedDomain: "y0-hotfix-2.example.com", expectedRound: "brutalist", findingIdSet });
  assert.equal(acceptedDoc.results[0].artifact_hashes["md5-artifact"], md5);
  assert.equal(acceptedDoc.results[0].artifact_hashes["sha256-artifact"], sha256);

  assert.throws(
    () => normalizeVerificationRoundDocument({
      version: 2,
      target_domain: "y0-hotfix-2.example.com",
      round: "brutalist",
      notes: null,
      verification_attempt_id: "VA-y0-1",
      verification_snapshot_hash: "c".repeat(64),
      round_profile: "brutalist-default",
      results: [{
        finding_id: "F-1",
        disposition: "confirmed",
        severity: "high",
        reportable: true,
        reasoning: "Fresh replay confirmed the finding.",
        confidence: "high",
        confidence_reasons: ["fresh_replay_passed"],
        state_sensitive: false,
        artifact_hashes: { bad: "a".repeat(40) },
        inherited_confidence_reasons: [],
        resolved_confidence_reasons: [],
      }],
    }, { expectedDomain: "y0-hotfix-2.example.com", expectedRound: "brutalist", findingIdSet }),
    /must be a lower-case md5 \(32 hex\) or sha256 \(64 hex\) hash/,
  );
});

test("Y.0 hotfix 3 (Y-D18): test/fixtures/benchmark-baseline.json carries measured wall-time + commit + timestamp + platform", () => {
  const baselinePath = path.join(__dirname, "fixtures", "benchmark-baseline.json");
  assert.ok(fs.existsSync(baselinePath), "test/fixtures/benchmark-baseline.json must exist on disk");

  const parsed = JSON.parse(fs.readFileSync(baselinePath, "utf8"));
  assert.equal(typeof parsed.npm_test_wall_time_seconds, "number");
  assert.ok(parsed.npm_test_wall_time_seconds > 0, "wall-time must be a positive number");
  assert.match(parsed.captured_at_commit, /^[a-f0-9]{40}$/, "captured_at_commit must be a 40-char git sha");
  assert.match(parsed.captured_at_iso, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, "captured_at_iso must be RFC3339 UTC");
  assert.ok(typeof parsed.platform === "string" && parsed.platform.length > 0, "platform must be a non-empty string");
  assert.match(parsed.budget_formula, /MAX/, "budget_formula must document the Y-R17 budget");

  // Y-R17 budget formula = MAX(seeded + 25%, 100s).
  const budget = Math.max(parsed.npm_test_wall_time_seconds * 1.25, 100);
  assert.ok(budget >= 100, "budget must be at least 100s");
});
