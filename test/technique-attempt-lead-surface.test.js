"use strict";

// Step 1 (fix/exhaustive-concurrency) — Unified surface-id resolution.
//
// bob_promote_surface_leads mints a `lead-*` surface and persists it ONLY as a
// surface.observed frontier event -> surface-index.json (attack_surface.json is
// NEVER written). Before this step, selectTechniquePacks/logTechniqueAttempt
// resolved surfaces via readAttackSurfaceStrict (attack_surface.json only), so a
// promoted lead-* id threw `Unknown surface_id: lead-*` at technique-packs.js
// BEFORE the assignment-scoping check — the required technique-attempt row could
// never be persisted and the finalize gate deadlocked. Step 1 routes both call
// sites through currentSurfaces(domain), the post-F.5 authoritative resolver that
// unions surface-index.json + legacy attack_surface.json, so promoted lead-* ids
// AND canonical surface-* ids resolve.
//
// Asserts:
//   (A) logTechniqueAttempt persists exactly one completion row for a promoted
//       lead-* surface that is ABSENT from attack_surface.json (threw
//       /Unknown surface_id/ on pre-fix code).
//   (B) selectTechniquePacks resolves the same lead-* surface (no throw) and
//       routes it to a capability pack.
//   (C) NEGATIVE: an unassigned wave/agent still throws the assignment-mismatch
//       ToolError(INVALID_ARGUMENTS) — surface resolution no longer fails first,
//       but validateAssignedWaveAgentSurface scoping is preserved.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordSurfaceLeadsTool = require("../mcp/tools/record-surface-leads.js");
const promoteSurfaceLeadsTool = require("../mcp/tools/promote-surface-leads.js");
const {
  logTechniqueAttempt,
  selectTechniquePacks,
} = require("../mcp/core/dispatch/technique-packs.js");
const { ToolError, ERROR_CODES } = require("../mcp/core/io/envelope.js");
const {
  sessionDir,
  attackSurfacePath,
  surfaceIndexPath,
  surfaceRoutesPath,
  techniqueAttemptsJsonlPath,
  waveAssignmentsPath,
} = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-step1-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Record a single high-score lead and promote it. Returns the minted lead-* id.
// The promotion path writes surface-index.json (via surface.observed frontier
// event) but does NOT create attack_surface.json — exactly the state that broke
// the pre-fix attack_surface.json-only resolver.
function promoteOneLead(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  recordSurfaceLeadsTool.handler({
    target_domain: domain,
    source: "test",
    leads: [
      {
        title: "Admin API",
        hosts: [`https://new-admin.${domain}`],
        endpoints: ["/api/new-admin"],
        interesting_params: ["id"],
        confidence: "high",
        score: 91,
      },
    ],
  });
  const promoted = JSON.parse(promoteSurfaceLeadsTool.handler({
    target_domain: domain,
    limit: 5,
    min_score: 60,
  }));
  assert.equal(promoted.promoted, 1);
  const leadId = promoted.promoted_surface_ids[0];
  // Precondition for this regression: the lead lives in surface-index.json but
  // NOT in attack_surface.json — the exact gap that threw `Unknown surface_id`.
  assert.ok(leadId.startsWith("lead-"), `expected a lead-* id, got ${leadId}`);
  assert.ok(fs.existsSync(surfaceIndexPath(domain)), "surface-index.json must exist after promotion");
  assert.equal(
    fs.existsSync(attackSurfacePath(domain)),
    false,
    "precondition: attack_surface.json must NOT exist (lead lives only in surface-index.json)",
  );
  return leadId;
}

// (A) ─────────────────────────────────────────────────────────────────────
test("logTechniqueAttempt persists a completion row for a promoted lead-* surface absent from attack_surface.json", () => {
  withTempHome(() => {
    const domain = "step1-log-lead.example.com";
    const leadId = promoteOneLead(domain);

    const result = JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      surface_id: leadId,
      pack_id: "generic-rest-api",
      status: "attempted",
      evidence: "probed REST authz on promoted lead surface across two accounts; no IDOR observed",
    }));
    assert.ok(result, "logTechniqueAttempt should return a result, not throw Unknown surface_id");

    const lines = fs
      .readFileSync(techniqueAttemptsJsonlPath(domain), "utf8")
      .trim()
      .split("\n")
      .filter(Boolean);
    assert.equal(lines.length, 1, "exactly one technique-attempt row must be persisted for the lead surface");
    const row = JSON.parse(lines[0]);
    assert.equal(row.surface_id, leadId);
    assert.equal(row.status, "attempted");
    assert.equal(row.target_domain, domain);
  });
});

// (B) ─────────────────────────────────────────────────────────────────────
test("selectTechniquePacks resolves a promoted lead-* surface and routes it to a capability pack", () => {
  withTempHome(() => {
    const domain = "step1-select-lead.example.com";
    const leadId = promoteOneLead(domain);

    const selection = JSON.parse(selectTechniquePacks({
      target_domain: domain,
      surface_id: leadId,
    }));
    assert.equal(selection.surface_id, leadId);
    assert.ok(
      typeof selection.capability_pack === "string" && selection.capability_pack.length > 0,
      "lead surface must resolve to a capability pack instead of throwing Unknown surface_id",
    );
    assert.ok(Array.isArray(selection.technique_packs), "technique_packs must be present for the resolved lead surface");
  });
});

// (C) NEGATIVE ─────────────────────────────────────────────────────────────
test("logTechniqueAttempt still enforces assignment scoping for an unassigned wave/agent on a resolvable lead surface", () => {
  withTempHome(() => {
    const domain = "step1-scoping-lead.example.com";
    const leadId = promoteOneLead(domain);

    // a1 is assigned a DIFFERENT surface than the lead we attempt to log against.
    // Pre-fix the call would have thrown `Unknown surface_id` first; the scoping
    // guard (validateAssignedWaveAgentSurface) must still run after resolution.
    fs.writeFileSync(
      waveAssignmentsPath(domain, 1),
      `${JSON.stringify({
        wave_number: 1,
        assignments: [{ agent: "a1", surface_id: "surface-some-other" }],
      }, null, 2)}\n`,
    );

    let captured;
    try {
      logTechniqueAttempt({
        target_domain: domain,
        surface_id: leadId,
        pack_id: "generic-rest-api",
        status: "attempted",
        evidence: "attempt against an unassigned surface must be rejected by the scoping guard",
        wave: "w1",
        agent: "a1",
      });
      assert.fail("expected an assignment-mismatch ToolError for an unassigned surface");
    } catch (err) {
      captured = err;
    }
    assert.ok(captured instanceof ToolError, `expected ToolError, got ${captured && captured.constructor && captured.constructor.name}`);
    assert.equal(captured.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.doesNotMatch(
      String(captured.message),
      /Unknown surface_id/,
      "resolution must succeed first; the failure must come from assignment scoping, not surface resolution",
    );
    assert.match(
      String(captured.message),
      new RegExp(leadId),
      "assignment-mismatch error must reference the attempted lead surface",
    );

    // No row should be persisted on the scoping rejection.
    assert.equal(
      fs.existsSync(techniqueAttemptsJsonlPath(domain)),
      false,
      "a scoping rejection must not persist a technique-attempt row",
    );
  });
});

// ── Unroutable smart_contract disposition (Y-D21) ──────────────────────────
// An ambiguous smart_contract surface (missing/unrecognized chain_family) is
// unroutable, not web. selectTechniquePacks must record the unroutable
// disposition and return a non-halting empty result — never getCapabilityPack(null)
// -> `Unknown capability_pack: null`, never the web pack.

// Seed a single surface directly into attack_surface.json (the legacy fallback
// currentSurfaces reads when surface-index.json is absent). Fields pass through
// unmodified, so surface_type/chain_family survive to classifySurfaceCapability.
function seedSurface(domain, surface) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.writeFileSync(
    attackSurfacePath(domain),
    `${JSON.stringify({ surfaces: [surface] }, null, 2)}\n`,
  );
}

test("selectTechniquePacks records an unroutable smart_contract surface (missing chain_family) non-haltingly with no packs", () => {
  withTempHome(() => {
    const domain = "sc-unroutable-fresh.example.com";
    seedSurface(domain, { id: "sc-unroutable", surface_type: "smart_contract" });

    let raw;
    assert.doesNotThrow(() => {
      raw = selectTechniquePacks({ target_domain: domain, surface_id: "sc-unroutable" });
    }, "unroutable SC selection must not throw Unknown capability_pack: null");
    const selection = JSON.parse(raw);

    assert.equal(selection.surface_id, "sc-unroutable");
    assert.equal(selection.capability_pack, null, "unroutable surface must not substitute a pack");
    assert.equal(selection.unroutable, true);
    assert.ok(
      typeof selection.unroutable_reason === "string" && selection.unroutable_reason.length > 0,
      "unroutable result must carry a non-empty unroutable_reason",
    );
    assert.deepEqual(selection.technique_packs, [], "unroutable surface selects no technique packs");
  });
});

test("selectTechniquePacks detects a PERSISTED disposition:unroutable route read from surface-routes.json", () => {
  withTempHome(() => {
    const domain = "sc-unroutable-persisted.example.com";
    // The surface itself would classify as unroutable too, but pin the outcome to
    // the persisted route: write a disposition:"unroutable" route to disk (the
    // shape surface-router.js emits) so the read-from-disk detection path is
    // exercised, not just fresh classification.
    seedSurface(domain, { id: "sc-persisted", surface_type: "smart_contract" });
    fs.writeFileSync(
      surfaceRoutesPath(domain),
      `${JSON.stringify({
        version: 1,
        route_version: 1,
        routes: [
          {
            surface_id: "sc-persisted",
            surface_type: "smart_contract",
            disposition: "unroutable",
            reason: "smart_contract surface is missing chain_family; capability routing requires it",
          },
        ],
      }, null, 2)}\n`,
    );

    let raw;
    assert.doesNotThrow(() => {
      raw = selectTechniquePacks({ target_domain: domain, surface_id: "sc-persisted" });
    }, "persisted unroutable route must not throw");
    const selection = JSON.parse(raw);

    assert.equal(selection.capability_pack, null);
    assert.equal(selection.unroutable, true);
    assert.equal(
      selection.unroutable_reason,
      "smart_contract surface is missing chain_family; capability routing requires it",
      "the persisted route's reason must be carried through as unroutable_reason",
    );
    assert.deepEqual(selection.technique_packs, []);
  });
});

test("logTechniqueAttempt on an unroutable smart_contract surface throws a clean surface-unroutable ToolError, not capability_pack null", () => {
  withTempHome(() => {
    const domain = "sc-unroutable-log.example.com";
    seedSurface(domain, { id: "sc-unroutable-log", surface_type: "smart_contract" });

    assert.throws(
      () =>
        logTechniqueAttempt({
          target_domain: domain,
          surface_id: "sc-unroutable-log",
          pack_id: "generic-rest-api",
          status: "attempted",
          evidence: "x",
        }),
      (err) => {
        assert.ok(err instanceof ToolError, "must be a ToolError");
        assert.equal(err.code, ERROR_CODES.INVALID_ARGUMENTS);
        assert.match(err.message, /surface unroutable/);
        assert.match(err.message, /no technique packs apply/);
        assert.doesNotMatch(err.message, /capability_pack null/);
        return true;
      },
    );

    assert.equal(
      fs.existsSync(techniqueAttemptsJsonlPath(domain)),
      false,
      "an unroutable rejection must not persist a technique-attempt row",
    );
  });
});

test("selectTechniquePacks leaves a routable smart_contract (evm) surface unchanged — real pack, no unroutable marker", () => {
  withTempHome(() => {
    const domain = "sc-routable-evm.example.com";
    seedSurface(domain, {
      id: "sc-evm",
      surface_type: "smart_contract",
      chain_family: "evm",
      contract_address: "0x0000000000000000000000000000000000000001",
    });

    const selection = JSON.parse(selectTechniquePacks({ target_domain: domain, surface_id: "sc-evm" }));
    assert.ok(
      typeof selection.capability_pack === "string" && selection.capability_pack.length > 0,
      "a routable evm SC surface must resolve to a real capability pack",
    );
    assert.notEqual(selection.unroutable, true, "a routable surface must not carry an unroutable marker");
    assert.ok(Array.isArray(selection.technique_packs));
  });
});
