"use strict";

// Cycle Y.12 (rev 4.1 defect 1 REFRAMED — producer-side rationale on
// bob_record_surface_leads + Y.7 silent_lead_threshold_drop runtime tripwire).
//
// Defect 1 reframing: the rev-4 spec located rationale enforcement on
// bob_promote_surface_leads with a fabricated `promote: false` parameter.
// Disk reality: bob_promote_surface_leads has no per-lead axis — its real
// schema is `{target_domain, limit, min_score, include_medium, update_state}`
// and it filters by score for batch promotion. Rev 4.1 relocates the
// rationale enforcement to the PRODUCER side (bob_record_surface_leads)
// where the rationale per lead is set at recording time.
//
// Asserts:
//   (a) fixture orchestrator handoff with 3 ranked_leads → 3 leads recorded
//       in the surface-leads.json ledger (no silent collapse to 1).
//   (b) bob_record_surface_leads({leads: [{score: 30, ...}]}) with
//       queue-policy.lead_rationale_required_when_below_threshold=true is
//       rejected with INVALID_ARGUMENTS whose remediation literally mentions
//       `rationale`.
//   (c) Same call with rationale: "low-signal but worth re-checking" is
//       accepted; the rationale persists in the recorded lead.
//   (d) Y.9 stigmergy pair
//       (surface_discovery_ranked_leads ↔ orchestrator_handoff_receipt_record_surface_leads)
//       has both manifest entries with the canonical producer_id and the
//       consumer's source_location.file = SKILL.md token bob_record_surface_leads.
//   (e) Y.7 silent_lead_threshold_drop scanner fires synthetic
//       protocol_drift_observed when handoff summary asserts 3 ranked_leads
//       but the recorded ledger contains 1 entry for the same run.
//   (f) bob_promote_surface_leads inputSchema is UNCHANGED from disk: it
//       still has `{target_domain, limit, min_score, include_medium, update_state}`
//       and NO per-lead axis (no `promote: false`, no `demote_rationale`).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordSurfaceLeadsTool = require("../mcp/lib/tools/record-surface-leads.js");
const promoteSurfaceLeadsTool = require("../mcp/lib/tools/promote-surface-leads.js");
const {
  readSurfaceLeads,
} = require("../mcp/lib/lead-promotion.js");
const { ToolError, ERROR_CODES } = require("../mcp/lib/envelope.js");
const {
  STIGMERGIC_PRODUCERS,
} = require("../mcp/lib/stigmergic-producers.js");
const {
  STIGMERGIC_CONSUMERS,
} = require("../mcp/lib/stigmergic-consumers.js");
const {
  DEFAULT_SCANNERS,
  scanTranscript,
} = require("../mcp/lib/friction-scanners.js");
const {
  sessionDir,
  attackSurfacePath,
  queuePolicyPath,
  surfaceIndexPath,
} = require("../mcp/lib/paths.js");
const {
  currentSurfaces,
} = require("../mcp/lib/frontier-projections.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-y12-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function ensureSessionDir(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

function writeQueuePolicy(domain, policy) {
  const policyPath = queuePolicyPath(domain);
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.writeFileSync(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
}

function makeLead(overrides = {}) {
  return {
    title: "leak candidate",
    hosts: ["target.example.com"],
    endpoints: ["/api/leak"],
    interesting_params: ["id"],
    score: 80,
    ...overrides,
  };
}

// (a) ─────────────────────────────────────────────────────────────────────
test("3 ranked_leads from deep-surface-discovery handoff → 3 entries in surface-leads.json", () => {
  withTempHome(() => {
    const domain = "y12-three-leads.example.com";
    ensureSessionDir(domain);
    const response = JSON.parse(recordSurfaceLeadsTool.handler({
      target_domain: domain,
      source: "deep-surface-discovery",
      source_wave: "wave-1",
      source_agent: "deep-surface-discovery",
      leads: [
        makeLead({ title: "lead-a", hosts: ["a.target.example.com"] }),
        makeLead({ title: "lead-b", hosts: ["b.target.example.com"] }),
        makeLead({ title: "lead-c", hosts: ["c.target.example.com"] }),
      ],
    }));
    assert.equal(response.recorded, 3, `expected 3 recorded, got ${response.recorded}`);
    assert.equal(response.lead_ids.length, 3);
    const readBack = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 50 }));
    assert.equal(readBack.total, 3, "ledger total should be 3, not silently collapsed");
    assert.equal(readBack.leads.length, 3);
  });
});

// (b) ─────────────────────────────────────────────────────────────────────
test("queue-policy lead_rationale_required_when_below_threshold=true rejects below-min_score lead without rationale", () => {
  withTempHome(() => {
    const domain = "y12-rationale-required.example.com";
    ensureSessionDir(domain);
    writeQueuePolicy(domain, {
      version: 1,
      lead_rationale_required_when_below_threshold: true,
    });
    let captured;
    try {
      recordSurfaceLeadsTool.handler({
        target_domain: domain,
        leads: [
          makeLead({ title: "below-threshold", score: 30 }), // below default min_score=60
        ],
      });
      assert.fail("expected ToolError INVALID_ARGUMENTS for missing rationale below threshold");
    } catch (err) {
      captured = err;
    }
    assert.ok(captured instanceof ToolError, `expected ToolError, got ${captured && captured.constructor && captured.constructor.name}`);
    assert.equal(captured.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.ok(typeof captured.remediation === "string" && captured.remediation.length > 0,
      "ToolError should carry remediation");
    assert.ok(captured.remediation.includes("rationale"),
      `remediation must mention 'rationale' literally; got: ${captured.remediation}`);
  });
});

// (c) ─────────────────────────────────────────────────────────────────────
test("queue-policy lead_rationale_required_when_below_threshold=true accepts below-threshold lead WITH rationale", () => {
  withTempHome(() => {
    const domain = "y12-rationale-supplied.example.com";
    ensureSessionDir(domain);
    writeQueuePolicy(domain, {
      version: 1,
      lead_rationale_required_when_below_threshold: true,
    });
    const response = JSON.parse(recordSurfaceLeadsTool.handler({
      target_domain: domain,
      leads: [
        makeLead({
          title: "low-signal lead",
          score: 30,
          rationale: "low-signal but worth re-checking after deeper context routing",
        }),
      ],
    }));
    assert.equal(response.recorded, 1);
    const readBack = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 50 }));
    assert.equal(readBack.total, 1);
    assert.equal(readBack.leads[0].rationale, "low-signal but worth re-checking after deeper context routing");
  });
});

// (c.2) — toggle FALSE leaves the gate open ───────────────────────────────
test("default queue-policy (toggle OFF) accepts below-threshold lead WITHOUT rationale", () => {
  withTempHome(() => {
    const domain = "y12-toggle-off.example.com";
    ensureSessionDir(domain);
    // No queue-policy.json written → defaults apply (toggle is false).
    const response = JSON.parse(recordSurfaceLeadsTool.handler({
      target_domain: domain,
      leads: [
        makeLead({ title: "low-signal-no-rationale", score: 10 }),
      ],
    }));
    assert.equal(response.recorded, 1, "default toggle is false; recording must succeed");
  });
});

// (d) ─────────────────────────────────────────────────────────────────────
test("Y.9 stigmergy pair (surface_discovery_ranked_leads ↔ orchestrator_handoff_receipt_record_surface_leads) is wired with canonical strings", () => {
  const producer = STIGMERGIC_PRODUCERS.find((p) => p.producer_id === "surface_discovery_ranked_leads");
  assert.ok(producer, "STIGMERGIC_PRODUCERS missing canonical surface_discovery_ranked_leads entry");
  assert.ok(producer.registered_consumers.includes("orchestrator_handoff_receipt_record_surface_leads"),
    "producer must register its handoff-receipt consumer");
  const consumer = STIGMERGIC_CONSUMERS.find((c) => c.consumer_id === "orchestrator_handoff_receipt_record_surface_leads");
  assert.ok(consumer, "STIGMERGIC_CONSUMERS missing orchestrator_handoff_receipt_record_surface_leads");
  assert.equal(consumer.producer_id, "surface_discovery_ranked_leads");
  assert.equal(consumer.decision_boundary, "handoff_receipt");
  assert.equal(consumer.source_location.file, ".claude/skills/bob-evaluate-runner/SKILL.md");
  // Verify the SKILL.md token the consumer cites is actually present.
  const skillBody = fs.readFileSync(
    path.join(__dirname, "..", consumer.source_location.file),
    "utf8",
  );
  assert.ok(skillBody.includes("bob_record_surface_leads"),
    "SKILL.md must contain the bob_record_surface_leads literal cited by the consumer");
});

// (d.2) — Orchestrator handoff-receipt prose lives in source ──────────────
test("orchestrator handoff-receipt handler is rendered into SKILL.md from prompts/roles/orchestrator.md source", () => {
  const sourceBody = fs.readFileSync(
    path.join(__dirname, "..", "prompts/roles/orchestrator.md"),
    "utf8",
  );
  const skillBody = fs.readFileSync(
    path.join(__dirname, "..", ".claude/skills/bob-evaluate-runner/SKILL.md"),
    "utf8",
  );
  const sourceMatch = sourceBody.match(/Handoff receipt — deep-surface-discovery ranked_leads[\s\S]{0,600}bob_record_surface_leads/);
  assert.ok(sourceMatch, "orchestrator.md must contain the Y.12 handoff-receipt prose linking ranked_leads to bob_record_surface_leads");
  const skillMatch = skillBody.match(/Handoff receipt — deep-surface-discovery ranked_leads[\s\S]{0,600}bob_record_surface_leads/);
  assert.ok(skillMatch, "regenerated SKILL.md must contain the Y.12 handoff-receipt prose");
});

// (e) ─────────────────────────────────────────────────────────────────────
test("Y.7 silent_lead_threshold_drop fires when summary asserts 3 ranked_leads but ledger records 1", () => {
  const scanner = DEFAULT_SCANNERS.find((s) => s.name === "silent_lead_threshold_drop");
  assert.ok(scanner, "DEFAULT_SCANNERS must include silent_lead_threshold_drop");
  const records = scanTranscript([scanner], {
    target_domain: "y12-tripwire.example.com",
    run_id: "run-y12-drop",
    node_id: "N-1",
    transcript_text: "",
    tool_invocations: [],
    voluntary_frictions: [],
    evidence_files: [],
    handoff_summary: {
      ranked_leads: [
        { lead_id: "L1", score: 80 },
        { lead_id: "L2", score: 70 },
        { lead_id: "L3", score: 60 },
      ],
    },
    recorded_leads: [
      { id: "SL-1", source: "run-y12-drop" },
    ],
    queue_policy: { lead_rationale_required_when_below_threshold: true },
  });
  assert.equal(records.length, 1, `expected one silent_lead_threshold_drop drift, got ${records.length}`);
  const drift = records[0];
  assert.equal(drift.kind, "drift");
  assert.equal(drift.scanner, "silent_lead_threshold_drop");
  assert.equal(drift.payload.drift_signature, "silent_lead_threshold_drop");
  assert.equal(drift.payload.details.summary_count, 3);
  assert.equal(drift.payload.details.recorded_count, 1);
  assert.equal(drift.payload.details.rationale_required_but_missing, true);
});

// (f) ─────────────────────────────────────────────────────────────────────
test("bob_promote_surface_leads inputSchema is UNCHANGED — no per-lead promote/demote axis", () => {
  const props = promoteSurfaceLeadsTool.inputSchema.properties;
  const expected = ["target_domain", "limit", "min_score", "include_medium", "update_state"];
  const actual = Object.keys(props).sort();
  assert.deepEqual(actual, expected.slice().sort(),
    `bob_promote_surface_leads schema must remain {target_domain, limit, min_score, include_medium, update_state}; got ${actual.join(",")}`);
  // Rev 4.1 explicit anti-fabrication assertions: ensure no `promote`,
  // `demote_rationale`, or per-lead axis was silently added.
  assert.ok(!("promote" in props), "rev-4 fabricated `promote` parameter must NOT exist");
  assert.ok(!("demote_rationale" in props), "rev-4 fabricated `demote_rationale` parameter must NOT exist");
  assert.ok(!("leads" in props), "bob_promote_surface_leads must not gain per-lead axis");
});

test("bob_promote_surface_leads preserves assigned lead surfaces already in attack_surface.json", () => {
  withTempHome(() => {
    const domain = "y12-preserve-assigned-leads.example.com";
    ensureSessionDir(domain);
    const attackPath = attackSurfacePath(domain);
    const legacyAttackSurface = {
      surfaces: [
        {
          id: "lead-admin-api",
          title: "Previously assigned admin API",
          hosts: ["https://assigned.y12-preserve-assigned-leads.example.com"],
          endpoints: ["/api/assigned"],
          priority: "HIGH",
          surface_type: "web",
          labels: ["promoted_surface_lead"],
        },
        {
          id: "surface-baseline",
          hosts: ["https://y12-preserve-assigned-leads.example.com"],
          endpoints: ["/"],
          priority: "MEDIUM",
          surface_type: "web",
        },
      ],
    };
    fs.writeFileSync(attackPath, `${JSON.stringify(legacyAttackSurface, null, 2)}\n`);

    const recorded = JSON.parse(recordSurfaceLeadsTool.handler({
      target_domain: domain,
      source: "test",
      leads: [
        makeLead({
          title: "Admin API",
          hosts: ["https://new-admin.y12-preserve-assigned-leads.example.com"],
          endpoints: ["/api/new-admin"],
          confidence: "high",
          score: 91,
        }),
      ],
    }));
    assert.equal(recorded.recorded, 1);

    const attackBeforePromotion = fs.readFileSync(attackPath, "utf8");
    const promoted = JSON.parse(promoteSurfaceLeadsTool.handler({
      target_domain: domain,
      limit: 5,
      min_score: 60,
    }));

    assert.equal(promoted.promoted, 1);
    assert.deepEqual(promoted.promoted_surface_ids, ["lead-admin-api-2"]);
    assert.equal(
      fs.readFileSync(attackPath, "utf8"),
      attackBeforePromotion,
      "promotion must not rewrite attack_surface.json and drop already-assigned lead surfaces",
    );

    const surfaceIndex = JSON.parse(fs.readFileSync(surfaceIndexPath(domain), "utf8"));
    assert.ok(surfaceIndex.surfaces.some((surface) => surface.surface_id === "lead-admin-api-2"),
      "newly promoted lead must materialize into surface-index.json");

    const projectionIds = currentSurfaces(domain).surfaces.map((surface) => surface.id).sort();
    assert.deepEqual(projectionIds, ["lead-admin-api", "lead-admin-api-2", "surface-baseline"]);
  });
});

// (g) ─────────────────────────────────────────────────────────────────────
test("bob_record_surface_leads inputSchema gains optional rationale per lead", () => {
  const leadSchema = recordSurfaceLeadsTool.inputSchema.properties.leads.items;
  assert.ok(leadSchema.properties.rationale, "leads[].rationale must be declared in the lead inputSchema");
  assert.equal(leadSchema.properties.rationale.type, "string");
  assert.equal(leadSchema.properties.rationale.minLength, 1);
  assert.equal(leadSchema.properties.rationale.maxLength, 512);
});
