"use strict";

// Y.10 — skill-scheduler-coherence tests.
//
// Subtests:
//   1. CI marker check passes on the real rendered surface.
//   2. CI marker check catches unknown @precondition tokens (negative).
//   3. CI marker check catches unreferenced preconditions (negative).
//   4. Runtime gate refuses OPEN_FRONTIER -> CLAIM_FREEZE while partial
//      surfaces remain in the latest merged wave snapshot.
//   5. Runtime gate allows the transition when an operator acknowledgement
//      covers each partial surface.
//   6. ToolError remediation propagates with the partial_surfaces_remaining
//      payload.
//   7. The deleted bob_acknowledge_partial_surfaces tool is not registered.
//   8. queue-policy schema accepts and normalizes the new
//      partial_surface_advance_acknowledgements array.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  runCheck,
  checkDocument,
} = require("../scripts/check-skill-scheduler-coherence.js");
const {
  parseSkillText,
} = require("../scripts/lib/skill-parser.js");
const {
  evaluateLifecycleTransition,
  TRANSITION_GATES,
} = require("../mcp/lib/lifecycle-gates.js");
const {
  normalizeQueuePolicy,
  writeQueuePolicy,
} = require("../mcp/lib/queue-policy.js");
const {
  waveMergeSnapshotPath,
  waveHandoffsSnapshotDir,
} = require("../mcp/lib/wave-handoff-store.js");
const {
  TOOL_REGISTRY,
} = require("../mcp/lib/tool-registry.js");
const {
  ToolError,
  ERROR_CODES,
} = require("../mcp/lib/envelope.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sched-coh-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function seedMergeSnapshot(domain, waveNumber, partialSurfaceIds) {
  fs.mkdirSync(waveHandoffsSnapshotDir(domain), { recursive: true });
  fs.writeFileSync(waveMergeSnapshotPath(domain, waveNumber), JSON.stringify({
    wave_number: waveNumber,
    merged_at_iso: new Date().toISOString(),
    partial_surface_ids: partialSurfaceIds,
  }));
}

test("check:skill-scheduler-coherence passes on the rendered surface", () => {
  const result = runCheck();
  assert.equal(result.violations.length, 0, `unexpected violations: ${JSON.stringify(result.violations, null, 2)}`);
  assert.ok(result.seen_preconditions.includes("partial_surfaces_drained"));
});

test("checkDocument flags an unknown @precondition token (S2)", () => {
  const text = [
    "## STATE: OPEN_FRONTIER",
    "<!-- @precondition: not_a_real_precondition -->",
    "Body text.",
  ].join("\n");
  const document = parseSkillText(text, { filePath: "/fake/skill.md" });
  const { violations } = checkDocument(document);
  assert.ok(violations.some((v) => v.dimension === "S2_unknown_precondition"
    && v.token === "not_a_real_precondition"));
});

test("runCheck flags an unreferenced precondition (S1) when extra value injected", () => {
  // Simulate an unreferenced precondition by feeding a synthetic in-memory
  // file set lacking any @precondition marker for partial_surfaces_drained.
  // We exercise the same code path by pointing runCheck at a tempdir that
  // contains only an empty SKILL.md.
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-sched-empty-"));
  try {
    fs.mkdirSync(path.join(tmpRoot, ".claude", "skills", "empty"), { recursive: true });
    fs.writeFileSync(path.join(tmpRoot, ".claude", "skills", "empty", "SKILL.md"),
      "## STATE: NOTHING\nNo preconditions here.\n");
    const result = runCheck({ root: tmpRoot });
    assert.ok(result.violations.some((v) => v.dimension === "S1_unreferenced_precondition"
      && v.token === "partial_surfaces_drained"));
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("runtime gate: OPEN_FRONTIER -> CLAIM_FREEZE registered", () => {
  assert.equal(typeof TRANSITION_GATES["OPEN_FRONTIER->CLAIM_FREEZE"], "function");
});

test("runtime gate refuses OPEN_FRONTIER -> CLAIM_FREEZE when partial surfaces remain", () => {
  withTempHome(() => {
    const domain = "gate-block.com";
    seedMergeSnapshot(domain, 1, ["surface-partial-x", "surface-partial-y"]);
    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
      nucleus: { lifecycle_state: "OPEN_FRONTIER" },
    });
    assert.equal(evaluation.blockers.length, 1);
    const first = evaluation.blockers[0];
    assert.equal(first.code, "partial_surfaces_remaining");
    assert.deepEqual(first.surfaces, ["surface-partial-x", "surface-partial-y"]);
    assert.match(first.remediation, /partial_surface_advance_acknowledgements/);
    assert.match(first.remediation, /bob_start_next_wave/);
  });
});

test("runtime gate allows the transition once each partial surface is acknowledged", () => {
  withTempHome(() => {
    const domain = "gate-ack.com";
    seedMergeSnapshot(domain, 1, ["surface-partial-x"]);
    // Operator pre-acknowledges surface-partial-x via queue-policy.
    writeQueuePolicy(domain, normalizeQueuePolicy({
      partial_surface_advance_acknowledgements: [
        { surface_id: "surface-partial-x", attestation_token: "operator-nonce-12345" },
      ],
    }));
    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
      nucleus: { lifecycle_state: "OPEN_FRONTIER" },
    });
    assert.deepEqual(evaluation.blockers, []);
  });
});

test("runtime gate partial-acknowledgement still blocks unack'd surfaces", () => {
  withTempHome(() => {
    const domain = "gate-partial-ack.com";
    seedMergeSnapshot(domain, 1, ["surface-partial-x", "surface-partial-y"]);
    writeQueuePolicy(domain, normalizeQueuePolicy({
      partial_surface_advance_acknowledgements: [
        { surface_id: "surface-partial-x", attestation_token: "operator-nonce-12345" },
      ],
    }));
    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
      nucleus: { lifecycle_state: "OPEN_FRONTIER" },
    });
    assert.equal(evaluation.blockers.length, 1);
    assert.deepEqual(evaluation.blockers[0].surfaces, ["surface-partial-y"]);
  });
});

test("runtime gate is silent when no merge snapshot exists yet", () => {
  withTempHome(() => {
    const domain = "gate-clean.com";
    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
      nucleus: { lifecycle_state: "OPEN_FRONTIER" },
    });
    assert.deepEqual(evaluation.blockers, []);
  });
});

test("ToolError carries the partial_surfaces_remaining remediation field through the envelope", () => {
  // Constructive smoke: a ToolError with remediation surfaces it on the
  // error envelope so MCP callers see the structured remediation string.
  const error = new ToolError(
    ERROR_CODES.STATE_CONFLICT,
    "lifecycle transition blocked: OPEN_FRONTIER -> CLAIM_FREEZE blocked: 1 partial surface(s) remain",
    {
      code: "partial_surfaces_remaining",
      surfaces: ["surface-partial-x"],
    },
    {
      remediation:
        "call bob_set_queue_policy({partial_surface_advance_acknowledgements: [...]}) "
        + "with operator_attested token or schedule wave-N+1 via bob_start_next_wave",
    },
  );
  assert.equal(error.code, "STATE_CONFLICT");
  assert.equal(error.details.code, "partial_surfaces_remaining");
  assert.deepEqual(error.details.surfaces, ["surface-partial-x"]);
  assert.match(error.remediation, /partial_surface_advance_acknowledgements/);
});

test("bob_acknowledge_partial_surfaces tool DELETED (rev 4.1 Y.10 review bullet)", () => {
  const hasGhostTool = TOOL_REGISTRY.some((entry) => entry.name === "bob_acknowledge_partial_surfaces");
  assert.equal(hasGhostTool, false);
});

test("queue-policy normalization accepts partial_surface_advance_acknowledgements entries", () => {
  const policy = normalizeQueuePolicy({
    partial_surface_advance_acknowledgements: [
      { surface_id: "surface-a", attestation_token: "tok-a", rationale: "halmos timeout" },
      { surface_id: "surface-b", attestation_token: "tok-b" },
    ],
  });
  assert.equal(policy.partial_surface_advance_acknowledgements.length, 2);
  assert.equal(policy.partial_surface_advance_acknowledgements[0].surface_id, "surface-a");
  assert.equal(policy.partial_surface_advance_acknowledgements[0].rationale, "halmos timeout");
  assert.equal(policy.partial_surface_advance_acknowledgements[1].surface_id, "surface-b");
  assert.equal(policy.partial_surface_advance_acknowledgements[1].rationale, undefined);
});

test("queue-policy normalization rejects duplicate surface_id in acknowledgements", () => {
  assert.throws(
    () => normalizeQueuePolicy({
      partial_surface_advance_acknowledgements: [
        { surface_id: "surface-a", attestation_token: "tok-a" },
        { surface_id: "surface-a", attestation_token: "tok-b" },
      ],
    }),
    /duplicate surface_id/,
  );
});

test("queue-policy normalization rejects empty attestation_token", () => {
  assert.throws(
    () => normalizeQueuePolicy({
      partial_surface_advance_acknowledgements: [
        { surface_id: "surface-a", attestation_token: "" },
      ],
    }),
    /attestation_token must be a non-empty string/,
  );
});

test("orchestrator.md source and regenerated SKILL.md both carry the partial_surfaces_remaining prose (defect 10 EDIT-by-TEXT)", () => {
  const root = path.join(__dirname, "..");
  const orchestratorSrc = fs.readFileSync(path.join(root, "prompts", "roles", "orchestrator.md"), "utf8");
  const skillMd = fs.readFileSync(path.join(root, ".claude", "skills", "bob-evaluate-runner", "SKILL.md"), "utf8");
  assert.ok(orchestratorSrc.includes("partial_surfaces_remaining"),
    "prompts/roles/orchestrator.md must mention partial_surfaces_remaining");
  assert.ok(skillMd.includes("partial_surfaces_remaining"),
    "regenerated SKILL.md must mention partial_surfaces_remaining");
});
