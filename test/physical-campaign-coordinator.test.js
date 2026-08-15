"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  assertPhysicalCampaignClosureSatisfied,
  buildPhysicalCampaignClosurePreflight,
  createPhysicalCampaignEd25519SignerPort,
  createPhysicalCampaignEd25519VerifierPort,
} = require("../mcp/domains/physical/physical-campaign-closure.js");
const {
  initializePhysicalCampaignCoordinator,
  physicalCampaignClosureReadiness,
  readVerifiedPhysicalCampaignCompletionState,
  readVerifiedPhysicalCampaignClosureManifest,
  routePhysicalCampaignSegment,
} = require("../mcp/domains/physical/physical-campaign-coordinator.js");
const {
  createPhysicalCampaignAnchorPort,
  installPhysicalCampaignAnchorResolver,
} = require("../mcp/domains/physical/physical-campaign-anchor.js");
const {
  readFrontierEvents,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  LEDGER_PRESSURE_REFUSE_THRESHOLD,
  materializeTaskGraph,
} = require("../mcp/core/waves/task-graph-materializer.js");
const {
  appendCellProposal,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  evaluateLifecycleTransition,
} = require("../mcp/core/session/lifecycle-gates.js");
const {
  physicalCampaignDir,
  physicalSessionBootstrapPath,
  sessionDir,
  sessionNucleusPath,
} = require("../mcp/core/io/paths.js");
const {
  initSession,
} = require("../mcp/core/session/session-state.js");
const {
  readVerifiedSessionNucleus,
} = require("../mcp/core/governance/governance-store.js");
const {
  buildInitialSessionState,
} = require("../mcp/core/session/session-state-contracts.js");
const {
  writeSessionStateDocument,
} = require("../mcp/core/session/session-state-store.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("../mcp/lib/physical-scope-axis.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function values(prefix, count) {
  return Array.from({ length: count }, (_, index) => (
    `${prefix}-${String(index).padStart(5, "0")}`
  ));
}

function clone(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function physicalScopeAxis(seed) {
  return normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "physical-campaign-test",
    policy_digest: digest(`policy:${seed}`),
    projection_version: 1,
    projection_digest: digest(`projection:${seed}`),
    provenance_digest: digest(`provenance:${seed}`),
    compatibility_digest: digest(`compatibility:${seed}`),
    transition_receipt_registry_digest: digest(`transition-registry:${seed}`),
    authority_epoch: 1,
    revocation_generation: 0,
  });
}

function createAnchorHarness() {
  const states = new Map();
  const anchorSlotDigest = digest("fixture-externally-enrolled-campaign-anchor-slot");
  let outage = null;
  let readFailuresRemaining = 0;
  let makeNextCommitAmbiguous = false;
  let rejectNextCompare = false;

  function keyForContext(context) {
    return canonicalJson(context);
  }

  const port = createPhysicalCampaignAnchorPort({
    anchorSlotDigest,
    readState(context) {
      if (outage != null) throw outage;
      if (readFailuresRemaining > 0) {
        readFailuresRemaining -= 1;
        throw new Error("fixture external anchor read-back unavailable");
      }
      return clone(states.get(keyForContext(context)) || null);
    },
    compareAndSet(input) {
      if (outage != null) throw outage;
      const key = keyForContext(input.context);
      const current = states.get(key) || null;
      if (canonicalJson(current) !== canonicalJson(input.expected_state)) return false;
      if (rejectNextCompare) {
        rejectNextCompare = false;
        return false;
      }
      states.set(key, clone(input.next_state));
      if (makeNextCommitAmbiguous) {
        makeNextCommitAmbiguous = false;
        readFailuresRemaining += 1;
      }
      return true;
    },
  });

  function contextFor(fixture) {
    return {
      version: 1,
      anchor_namespace: "hacker-bob/physical-campaign-anchor/v1",
      target_domain: fixture.domain,
      anchor_slot_digest: anchorSlotDigest,
    };
  }

  return {
    port,
    makeNextCommitAmbiguous() {
      makeNextCommitAmbiguous = true;
    },
    rejectNextCommit() {
      rejectNextCompare = true;
    },
    replace(fixture, state) {
      states.set(keyForContext(contextFor(fixture)), clone(state));
    },
    setOutage(error = new Error("fixture external anchor unavailable")) {
      outage = error;
    },
    clearOutage() {
      outage = null;
    },
    stateFor(fixture) {
      return clone(states.get(keyForContext(contextFor(fixture))) || null);
    },
  };
}

function withTempHome(fn, { installAnchor = true } = {}) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-physical-campaign-coordinator-"));
  const anchorHarness = createAnchorHarness();
  const uninstall = installAnchor
    ? installPhysicalCampaignAnchorResolver(() => anchorHarness.port)
    : null;
  process.env.HOME = home;
  try {
    return fn(home, anchorHarness, uninstall);
  } finally {
    if (uninstall != null) uninstall();
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function campaignFixture(domain, {
  dimensions,
  eventsPerCell,
  segmentEventLimit,
} = {}) {
  initSession({ target_domain: domain, target_url: `https://${domain}` });
  const nucleus = readVerifiedSessionNucleus(domain);
  const pair = crypto.generateKeyPairSync("ed25519");
  const signerKeyRef = `campaign-signer:${domain.replace(/\./gu, "-")}`;
  const signer = createPhysicalCampaignEd25519SignerPort({
    signer_key_ref: signerKeyRef,
    private_key: pair.privateKey,
  });
  const verifier = createPhysicalCampaignEd25519VerifierPort({
    signer_key_ref: signerKeyRef,
    public_key: pair.publicKey,
  });
  const preflightInput = {
    session_nucleus_hash: nucleus.nucleus_hash,
    authority_binding_digest: digest(`authority:${domain}`),
    capability_pack_digest: digest(`pack:${domain}`),
    closure_signer_key_ref: signer.signer_key_ref,
    closure_signer_public_key_digest: signer.signer_public_key_digest,
    declared_dimensions: dimensions || [{ dimension_id: "asset", values: values("asset", 5) }],
    events_per_cell: eventsPerCell || 2,
    segment_event_limit: segmentEventLimit || 4,
  };
  const preflight = buildPhysicalCampaignClosurePreflight(preflightInput);
  initializePhysicalCampaignCoordinator({
    target_domain: domain,
    preflight_input: preflightInput,
    signer,
    verifier,
  });
  return { domain, signer, verifier, preflight, preflightInput };
}

function routedEventsForSegment(fixture, segmentIndex, {
  terminalStateForCell = () => "denied",
  reverse = false,
} = {}) {
  const { preflight } = fixture;
  const plan = preflight.segments[segmentIndex];
  const routed = [];
  let localIndex = 0;
  for (const cellId of plan.cell_ids) {
    for (let ordinal = 1; ordinal <= preflight.events_per_cell; ordinal += 1) {
      const terminal = ordinal === preflight.events_per_cell;
      const surfaceId = `physical:${cellId}`;
      const event = {
        cell_id: cellId,
        event_ordinal: ordinal,
        frontier_event: {
          event_id: `FE-PC-${digest(`${preflight.campaign_id}:${cellId}:${ordinal}`).slice(0, 24)}`,
          kind: "observation.recorded",
          ts: new Date(Date.UTC(2026, 0, 1)
            + (segmentIndex * preflight.segment_event_limit)
            + localIndex).toISOString(),
          payload: {
            kind: "cell_proposed",
            surface_id: surfaceId,
            cell_key: cellId,
            bug_class: "physical_fixture",
            auth_profile: "authorized_operator",
            technique_pack_ids: ["physical-fixture-technique"],
            capability_pack_ids: ["physical-fixture-capability"],
          },
        },
      };
      if (terminal) {
        event.terminal_state = terminalStateForCell(cellId);
        event.terminal_witness_digest = digest(`terminal:${cellId}:${event.terminal_state}`);
      }
      routed.push(event);
      localIndex += 1;
    }
  }
  if (reverse) routed.reverse();
  return routed;
}

function routeAll(fixture, options = {}) {
  const receipts = [];
  for (const plan of fixture.preflight.segments) {
    receipts.push(routePhysicalCampaignSegment({
      target_domain: fixture.domain,
      segment_index: plan.segment_index,
      routed_events: routedEventsForSegment(fixture, plan.segment_index, options),
      signer: fixture.signer,
    }));
  }
  return receipts;
}

test("PH-S12 routes 18,207 real Frontier events through bounded TaskGraph folds without a cloned graph store", () => {
  withTempHome(() => {
    const fixture = campaignFixture("physical-campaign-large.example.com", {
      dimensions: [
        { dimension_id: "asset", values: values("asset", 17) },
        { dimension_id: "technique", values: values("technique", 153) },
      ],
      eventsPerCell: 7,
      segmentEventLimit: 3_500,
    });
    assert.equal(fixture.preflight.declared_event_count, 18_207);
    assert.ok(fixture.preflight.declared_event_count > LEDGER_PRESSURE_REFUSE_THRESHOLD);
    const ordinaryLedgerCountBefore = readFrontierEvents(fixture.domain).length;

    const receipts = routeAll(fixture, { reverse: true });
    assert.equal(receipts.length, fixture.preflight.segment_count);
    assert.equal(receipts.at(-1).closure_satisfied, true);
    for (let index = 0; index < receipts.length; index += 1) {
      assert.ok(receipts[index].segment_event_count < LEDGER_PRESSURE_REFUSE_THRESHOLD);
      assert.equal(
        receipts[index].materialized_node_count,
        fixture.preflight.segments[index].cell_count,
        "the existing TaskGraph fold materializes every planned cell in its bounded segment",
      );
    }

    const campaignRoot = physicalCampaignDir(fixture.domain);
    const ledgerFiles = fs.readdirSync(path.join(campaignRoot, "segments"), { recursive: true })
      .filter((entry) => entry.endsWith("frontier-events.jsonl"));
    assert.equal(ledgerFiles.length, fixture.preflight.segment_count);
    const persistedEventCount = ledgerFiles.reduce((total, relative) => {
      const lines = fs.readFileSync(path.join(campaignRoot, "segments", relative), "utf8")
        .trim().split("\n");
      assert.ok(lines.length < LEDGER_PRESSURE_REFUSE_THRESHOLD);
      return total + lines.length;
    }, 0);
    assert.equal(persistedEventCount, 18_207);
    assert.equal(readFrontierEvents(fixture.domain).length, ordinaryLedgerCountBefore);
    assert.ok(ordinaryLedgerCountBefore < LEDGER_PRESSURE_REFUSE_THRESHOLD);
    assert.equal(
      fs.readdirSync(campaignRoot, { recursive: true }).some((entry) => entry.endsWith("task-graph.json")),
      false,
      "campaign segments persist source ledgers and signed roots, not a second graph store",
    );

    const manifest = readVerifiedPhysicalCampaignClosureManifest(fixture.domain);
    assert.equal(assertPhysicalCampaignClosureSatisfied(manifest), manifest);
    assert.equal(manifest.event_count, 18_207);
    assert.equal(manifest.terminal_cell_count, 2_601);
    const readiness = physicalCampaignClosureReadiness(fixture.domain);
    assert.equal(readiness.integrity_satisfied, true);
    assert.equal(readiness.satisfied, false);
    assert.equal(readiness.production_ready, false);
    assert.equal(readiness.anchor_externality_attested, false);
    assert.equal(readiness.no_active_effects_attestation_digest, null);
    assert.equal(readiness.reason, "campaign_anchor_not_production_attested");
    const completion = readVerifiedPhysicalCampaignCompletionState(fixture.domain);
    assert.equal(completion.production_ready, false);
    assert.equal(completion.active_effect_count, 0);
    assert.equal(completion.terminal_cell_count, 2_601);
    assert.equal(completion.terminal_cells.length, 2_601);
    assert.ok(completion.terminal_cells.every((cell) => cell.cell_id.startsWith("physical-cell:")));
    assert.equal(completion.no_active_effects_attestation_digest, null);
    const freeze = evaluateLifecycleTransition({
      target_domain: fixture.domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
    });
    assert.equal(
      freeze.blockers.some((entry) => entry.code.startsWith("physical_campaign_")),
      true,
      "a callback-anchored aggregate remains integrity-only and cannot clear PH-S12",
    );
  });
});

test("a pending exact local tail is reverified/promoted and the local anchor journal is non-authoritative", () => {
  withTempHome((home, anchorHarness) => {
    const fixture = campaignFixture("physical-campaign-crash.example.com");
    assert.equal(fixture.preflight.segment_count, 3);
    const root = physicalCampaignDir(fixture.domain);
    const anchorPath = path.join(root, "checkpoint-anchor.json");
    const genesisAnchor = fs.readFileSync(anchorPath);

    anchorHarness.rejectNextCommit();
    assert.throws(
      () => routePhysicalCampaignSegment({
        target_domain: fixture.domain,
        segment_index: 0,
        routed_events: routedEventsForSegment(fixture, 0),
        signer: fixture.signer,
      }),
      (error) => error.code === "physical_campaign_anchor_commit_pending"
        && error.anchor_commit_outcome === "pending",
    );
    assert.equal(anchorHarness.stateFor(fixture).generation, 0);

    const recovered = initializePhysicalCampaignCoordinator({
      target_domain: fixture.domain,
      preflight_input: fixture.preflightInput,
      signer: fixture.signer,
      verifier: fixture.verifier,
    });
    assert.equal(recovered.accepted_segment_count, 1);
    assert.equal(anchorHarness.stateFor(fixture).generation, 1);
    const replay = routePhysicalCampaignSegment({
      target_domain: fixture.domain,
      segment_index: 0,
      routed_events: routedEventsForSegment(fixture, 0),
      signer: fixture.signer,
    });
    assert.equal(replay.replayed, true);

    // Staling only the co-located mirror cannot roll authority back. A normal
    // resume rewrites it from the externally retained head.
    fs.writeFileSync(anchorPath, genesisAnchor);
    const resumed = initializePhysicalCampaignCoordinator({
      target_domain: fixture.domain,
      preflight_input: fixture.preflightInput,
      signer: fixture.signer,
      verifier: fixture.verifier,
    });
    assert.equal(resumed.accepted_segment_count, 1);
    assert.equal(resumed.local_anchor_journal_synced, true);
    assert.equal(JSON.parse(fs.readFileSync(anchorPath, "utf8")).generation, 1);
  });
});

test("an external head detects whole campaign-root deletion and rollback to an older root snapshot", () => {
  withTempHome((home, anchorHarness) => {
    const fixture = campaignFixture("physical-campaign-root-rollback.example.com");
    const root = physicalCampaignDir(fixture.domain);
    routePhysicalCampaignSegment({
      target_domain: fixture.domain,
      segment_index: 0,
      routed_events: routedEventsForSegment(fixture, 0),
      signer: fixture.signer,
    });
    assert.equal(anchorHarness.stateFor(fixture).generation, 1);
    const snapshot = path.join(home, "campaign-generation-one-snapshot");
    fs.cpSync(root, snapshot, { recursive: true });
    const nucleusPath = sessionNucleusPath(fixture.domain);
    const nucleusBytes = fs.readFileSync(nucleusPath);

    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(nucleusPath);
    assert.throws(
      () => physicalCampaignClosureReadiness(fixture.domain),
      (error) => error.code === "physical_campaign_checkpoint_rollback",
    );
    const missingRootFreeze = evaluateLifecycleTransition({
      target_domain: fixture.domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
    });
    assert.ok(missingRootFreeze.blockers.some((entry) => (
      entry.code === "physical_campaign_closure_invalid"
    )));

    fs.writeFileSync(nucleusPath, nucleusBytes);
    fs.cpSync(snapshot, root, { recursive: true });
    routePhysicalCampaignSegment({
      target_domain: fixture.domain,
      segment_index: 1,
      routed_events: routedEventsForSegment(fixture, 1),
      signer: fixture.signer,
    });
    assert.equal(anchorHarness.stateFor(fixture).generation, 2);
    fs.rmSync(root, { recursive: true, force: true });
    fs.cpSync(snapshot, root, { recursive: true });
    assert.throws(
      () => physicalCampaignClosureReadiness(fixture.domain),
      (error) => error.code === "physical_campaign_checkpoint_rollback",
    );
  });
});

test("slot/preflight/nucleus/anchor drift and a second campaign in one enrolled slot fail closed", () => {
  withTempHome((home, anchorHarness) => {
    const fixture = campaignFixture("physical-campaign-anchor-fork.example.com");
    routePhysicalCampaignSegment({
      target_domain: fixture.domain,
      segment_index: 0,
      routed_events: routedEventsForSegment(fixture, 0),
      signer: fixture.signer,
    });
    const current = anchorHarness.stateFor(fixture);
    function validAnchorWith(fields) {
      const basis = { ...current, ...fields };
      delete basis.anchor_digest;
      return {
        ...basis,
        anchor_digest: hashCanonicalJson({
          domain: "hacker-bob/physical-campaign-checkpoint-anchor/v1",
          ...basis,
        }),
      };
    }

    for (const [field, code] of [
      ["anchor_slot_digest", "physical_campaign_authority_drift"],
      ["preflight_digest", "physical_campaign_authority_drift"],
      ["session_nucleus_hash", "physical_campaign_authority_drift"],
    ]) {
      anchorHarness.replace(fixture, validAnchorWith({ [field]: digest(`fork:${field}`) }));
      assert.throws(
        () => physicalCampaignClosureReadiness(fixture.domain),
        (error) => error.code === code,
      );
      anchorHarness.replace(fixture, current);
    }

    anchorHarness.replace(fixture, {
      ...current,
      anchor_digest: digest("tampered-anchor-digest"),
    });
    assert.throws(
      () => physicalCampaignClosureReadiness(fixture.domain),
      (error) => error.code === "physical_campaign_anchor_tamper",
    );
    anchorHarness.replace(fixture, current);

    anchorHarness.replace(fixture, validAnchorWith({
      checkpoint_envelope_digest: digest("different-valid-external-checkpoint-head"),
    }));
    assert.throws(
      () => physicalCampaignClosureReadiness(fixture.domain),
      (error) => error.code === "physical_campaign_checkpoint_fork",
    );
    anchorHarness.replace(fixture, current);

    assert.throws(
      () => initializePhysicalCampaignCoordinator({
        target_domain: fixture.domain,
        preflight_input: {
          ...fixture.preflightInput,
          capability_pack_digest: digest("different-second-campaign-pack"),
        },
        signer: fixture.signer,
        verifier: fixture.verifier,
      }),
      (error) => error.code === "physical_campaign_authority_drift"
        || error.code === "physical_campaign_preflight_fork",
    );
  });
});

test("external anchor outage and missing active resolver fail readiness/lifecycle closed", () => {
  withTempHome((home, anchorHarness, uninstall) => {
    anchorHarness.setOutage();
    assert.throws(
      () => campaignFixture("physical-campaign-anchor-init-outage.example.com"),
      (error) => error.code === "physical_campaign_anchor_read_failed",
    );
    assert.equal(
      fs.existsSync(physicalCampaignDir("physical-campaign-anchor-init-outage.example.com")),
      false,
      "an anchor read outage is detected before campaign files are created",
    );
    anchorHarness.clearOutage();
    const fixture = campaignFixture("physical-campaign-anchor-outage.example.com");
    anchorHarness.setOutage();
    assert.throws(
      () => physicalCampaignClosureReadiness(fixture.domain),
      (error) => error.code === "physical_campaign_anchor_read_failed",
    );
    const freeze = evaluateLifecycleTransition({
      target_domain: fixture.domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
    });
    assert.ok(freeze.blockers.some((entry) => (
      entry.code === "physical_campaign_closure_invalid"
    )));
    anchorHarness.clearOutage();
    uninstall();
    assert.throws(
      () => physicalCampaignClosureReadiness(fixture.domain),
      (error) => error.code === "physical_campaign_anchor_runtime_unconfigured",
    );
  });
});

test("an unconfigured resolver refuses campaign initialization before campaign writes", () => {
  withTempHome(() => {
    const domain = "physical-campaign-anchor-unconfigured-init.example.com";
    assert.throws(
      () => campaignFixture(domain),
      (error) => error.code === "physical_campaign_anchor_runtime_unconfigured",
    );
    assert.equal(fs.existsSync(physicalCampaignDir(domain)), false);
  }, { installAnchor: false });
});

test("an ambiguous external CAS is noncompensable and restart accepts only the exact committed tail", () => {
  withTempHome((home, anchorHarness) => {
    const fixture = campaignFixture("physical-campaign-anchor-ambiguous.example.com", {
      dimensions: [{ dimension_id: "asset", values: ["fixture-a"] }],
      eventsPerCell: 2,
      segmentEventLimit: 4,
    });
    anchorHarness.makeNextCommitAmbiguous();
    assert.throws(
      () => routePhysicalCampaignSegment({
        target_domain: fixture.domain,
        segment_index: 0,
        routed_events: routedEventsForSegment(fixture, 0),
        signer: fixture.signer,
      }),
      (error) => error.code === "physical_campaign_anchor_commit_ambiguous"
        && error.anchor_commit_outcome === "ambiguous",
    );
    assert.equal(anchorHarness.stateFor(fixture).generation, 1);
    assert.equal(
      JSON.parse(fs.readFileSync(
        path.join(physicalCampaignDir(fixture.domain), "checkpoint.json"),
        "utf8",
      )).generation,
      1,
    );
    assert.equal(
      fs.existsSync(path.join(
        physicalCampaignDir(fixture.domain),
        "segments/000000/frontier-events.jsonl",
      )),
      true,
      "ambiguous commit never compensates the durable local tail",
    );
    const replay = routePhysicalCampaignSegment({
      target_domain: fixture.domain,
      segment_index: 0,
      routed_events: routedEventsForSegment(fixture, 0),
      signer: fixture.signer,
    });
    assert.equal(replay.accepted, false);
    assert.equal(replay.replayed, true);
    assert.equal(anchorHarness.stateFor(fixture).generation, 1);
    assert.equal(
      assertPhysicalCampaignClosureSatisfied(
        readVerifiedPhysicalCampaignClosureManifest(fixture.domain),
      ).event_count,
      2,
    );
  });
});

test("post-CAS crash-journal and manifest mirror failures cannot negate committed closure", () => {
  withTempHome((home, anchorHarness) => {
    const fixture = campaignFixture("physical-campaign-mirror-failure.example.com", {
      dimensions: [{ dimension_id: "asset", values: ["fixture-a"] }],
      eventsPerCell: 2,
      segmentEventLimit: 4,
    });
    const root = physicalCampaignDir(fixture.domain);
    const journalPath = path.join(root, "checkpoint-anchor.json");
    const manifestPath = path.join(root, "aggregate-manifest.json");
    fs.rmSync(journalPath);
    fs.mkdirSync(journalPath);
    fs.mkdirSync(manifestPath);

    const committed = routePhysicalCampaignSegment({
      target_domain: fixture.domain,
      segment_index: 0,
      routed_events: routedEventsForSegment(fixture, 0),
      signer: fixture.signer,
    });
    assert.equal(committed.accepted, true);
    assert.equal(committed.closure_satisfied, true);
    assert.equal(committed.local_anchor_journal_synced, false);
    assert.equal(committed.manifest_synced, false);
    assert.equal(anchorHarness.stateFor(fixture).generation, 1);

    fs.rmSync(journalPath, { recursive: true, force: true });
    fs.rmSync(manifestPath, { recursive: true, force: true });
    const repaired = initializePhysicalCampaignCoordinator({
      target_domain: fixture.domain,
      preflight_input: fixture.preflightInput,
      signer: fixture.signer,
      verifier: fixture.verifier,
    });
    assert.equal(repaired.local_anchor_journal_synced, true);
    assert.equal(
      assertPhysicalCampaignClosureSatisfied(
        readVerifiedPhysicalCampaignClosureManifest(fixture.domain),
      ).closure_satisfied,
      true,
    );
  });
});

test("terminal residue blocks readiness and OPEN_FRONTIER -> CLAIM_FREEZE", () => {
  withTempHome(() => {
    const fixture = campaignFixture("physical-campaign-residue.example.com", {
      dimensions: [{ dimension_id: "asset", values: ["fixture-a"] }],
      eventsPerCell: 2,
      segmentEventLimit: 4,
    });
    routeAll(fixture, { terminalStateForCell: () => "inconclusive" });
    const readiness = physicalCampaignClosureReadiness(fixture.domain);
    assert.equal(readiness.active, true);
    assert.equal(readiness.satisfied, false);
    assert.equal(readiness.reason, "terminal_residue");
    assert.equal(readiness.residue_cell_count, 1);
    const freeze = evaluateLifecycleTransition({
      target_domain: fixture.domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
    });
    assert.ok(freeze.blockers.some((entry) => (
      entry.code === "physical_campaign_closure_required"
      && entry.physical_campaign.reason === "terminal_residue"
    )));
  });
});

test("legacy ordinary gate artifacts need no physical nucleus when no campaign authority exists", () => {
  withTempHome(() => {
    const domain = "legacy-gate-only.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    assert.equal(fs.existsSync(sessionNucleusPath(domain)), false);
    assert.deepEqual(
      physicalCampaignClosureReadiness(domain),
      { active: false, satisfied: true },
    );
    const freeze = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
      nucleus: { lifecycle_state: "OPEN_FRONTIER" },
    });
    assert.equal(
      freeze.blockers.some((entry) => entry.code.startsWith("physical_campaign_")),
      false,
    );
    assert.equal(
      fs.existsSync(sessionNucleusPath(domain)),
      false,
      "the read-only closure gate must not synthesize physical authority",
    );
  });
});

test("physical state or bootstrap markers without a verified nucleus remain fail-closed", () => {
  withTempHome(() => {
    const stateDomain = "physical-state-without-nucleus.example.com";
    fs.mkdirSync(sessionDir(stateDomain), { recursive: true });
    writeSessionStateDocument(
      stateDomain,
      {},
      buildInitialSessionState(stateDomain, null, {
        egressProfile: {
          name: "default",
          region: null,
          proxy_configured: false,
          egress_profile_identity_hash: null,
          egress_profile_identity_version: null,
          egress_profile_identity_source: {
            proxy_url_source: "none",
            proxy_env_var: null,
            proxy_url_redacted: null,
            resolved_proxy: null,
          },
        },
        physicalScope: physicalScopeAxis(stateDomain),
      }),
    );
    assert.throws(
      () => physicalCampaignClosureReadiness(stateDomain),
      (error) => error.code === "physical_campaign_session_authority_missing",
    );
    const stateFreeze = evaluateLifecycleTransition({
      target_domain: stateDomain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
      nucleus: { lifecycle_state: "OPEN_FRONTIER" },
    });
    assert.ok(stateFreeze.blockers.some((entry) => (
      entry.code === "physical_campaign_closure_invalid"
    )));

    const bootstrapDomain = "physical-bootstrap-without-nucleus.example.com";
    fs.mkdirSync(sessionDir(bootstrapDomain), { recursive: true });
    fs.writeFileSync(physicalSessionBootstrapPath(bootstrapDomain), "{}\n");
    assert.throws(
      () => physicalCampaignClosureReadiness(bootstrapDomain),
      (error) => error.code === "physical_campaign_session_authority_missing",
    );
  });
});

test("ordinary sessions retain the existing Frontier writer/materializer path and no PH-S12 blocker", () => {
  withTempHome(() => {
    const domain = "ordinary-session.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    assert.deepEqual(physicalCampaignClosureReadiness(domain), { active: false, satisfied: true });
    appendCellProposal({
      target_domain: domain,
      surface_id: "surface:ordinary",
      cell_key: "ordinary-cell",
      bug_class: "ordinary_fixture",
      auth_profile: "anonymous",
      technique_pack_ids: ["ordinary-technique"],
      capability_pack_ids: ["ordinary-capability"],
      ts: "2026-01-01T00:00:00.000Z",
    });
    const graph = materializeTaskGraph(domain);
    assert.equal(graph.document.source_event_count, 2);
    assert.equal(graph.document.node_count, 1);
    const freeze = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
    });
    assert.equal(
      freeze.blockers.some((entry) => entry.code.startsWith("physical_campaign_")),
      false,
    );
  });
});
