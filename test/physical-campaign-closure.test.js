"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const {
  COVERAGE_CREDIT_STATE_VALUES,
  MAX_CAMPAIGN_CELLS,
  TERMINAL_STATE_VALUES,
  assertPhysicalCampaignClosureSatisfied,
  buildPhysicalCampaignClosurePreflight,
  campaignGenesisDigest,
  createPhysicalCampaignClosureAccumulator,
  createPhysicalCampaignEd25519SignerPort,
  createPhysicalCampaignEd25519VerifierPort,
  sealPhysicalCampaignClosureSegment,
  verifyPhysicalCampaignClosureSegment,
} = require("../mcp/domains/physical/physical-campaign-closure.js");
const {
  LEDGER_PRESSURE_REFUSE_THRESHOLD,
} = require("../mcp/core/waves/task-graph-materializer.js");

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function publicKeyDigest(publicKey) {
  return crypto.createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function values(prefix, count) {
  return Array.from({ length: count }, (_, index) => (
    `${prefix}-${String(index).padStart(5, "0")}`
  ));
}

const keyPair = crypto.generateKeyPairSync("ed25519");
const signerKeyRef = "campaign-closure-signer:test-key";
const signer = createPhysicalCampaignEd25519SignerPort({
  signer_key_ref: signerKeyRef,
  private_key: keyPair.privateKey,
});
const verifier = createPhysicalCampaignEd25519VerifierPort({
  signer_key_ref: signerKeyRef,
  public_key: keyPair.publicKey,
});
const signerPublicKeyDigest = publicKeyDigest(keyPair.publicKey);

function preflightInput(overrides = {}) {
  return {
    session_nucleus_hash: digest("physical-session-nucleus"),
    authority_binding_digest: digest("immutable-physical-authority"),
    capability_pack_digest: digest("physical-capability-pack"),
    closure_signer_key_ref: signerKeyRef,
    closure_signer_public_key_digest: signerPublicKeyDigest,
    // 17 * 153 = 2,601 cells; seven declared events per cell = 18,207
    // events, intentionally beyond the current 18,000-event fold refusal.
    declared_dimensions: [
      { dimension_id: "asset", values: values("asset", 17) },
      { dimension_id: "technique", values: values("technique", 153) },
    ],
    events_per_cell: 7,
    segment_event_limit: 3_500,
    ...overrides,
  };
}

const preflight = buildPhysicalCampaignClosurePreflight(preflightInput());

function eventsForSegment(plan, {
  traversal = "forward",
  sourceVariant = "stable",
  terminalStateForCell = () => "denied",
} = {}) {
  const events = [];
  for (const cellId of plan.cell_ids) {
    for (let ordinal = 1; ordinal <= preflight.events_per_cell; ordinal += 1) {
      const event = {
        cell_id: cellId,
        event_ordinal: ordinal,
        event_kind: ordinal === preflight.events_per_cell ? "cell.terminal" : `cell.step.${ordinal}`,
        source_event_digest: digest(`${sourceVariant}:${cellId}:${ordinal}`),
      };
      if (ordinal === preflight.events_per_cell) {
        event.terminal_state = terminalStateForCell(cellId);
        event.terminal_witness_digest = digest(`terminal-witness:${cellId}:${event.terminal_state}`);
      }
      events.push(event);
    }
  }
  if (traversal === "reverse") events.reverse();
  if (traversal === "striped") {
    events.sort((left, right) => (
      right.event_ordinal - left.event_ordinal || left.cell_id.localeCompare(right.cell_id)
    ));
  }
  return events;
}

function sealCampaign({
  traversal = "forward",
  sourceVariant = "stable",
  terminalStateForCell = () => "denied",
} = {}) {
  const segments = [];
  let previousSegmentDigest = campaignGenesisDigest(preflight);
  for (const plan of preflight.segments) {
    const segment = sealPhysicalCampaignClosureSegment(
      preflight,
      plan.segment_index,
      eventsForSegment(plan, { traversal, sourceVariant, terminalStateForCell }),
      {
        previous_segment_digest: previousSegmentDigest,
        materialized_graph_hash: digest(`materialized-graph:${plan.segment_index}`),
        signer,
      },
    );
    segments.push(segment);
    previousSegmentDigest = segment.sealed_segment_digest;
  }
  return segments;
}

let coveredSegmentsCache = null;
function coveredSegments() {
  if (coveredSegmentsCache == null) coveredSegmentsCache = sealCampaign({ traversal: "reverse" });
  return coveredSegmentsCache;
}

function closeSegments(segments) {
  const accumulator = createPhysicalCampaignClosureAccumulator(preflight, {
    verifier,
  });
  for (const segment of segments) accumulator.appendSegment(segment);
  return { accumulator, manifest: accumulator.finalize() };
}

test("PH-S12 preflight expands above 18,000 events into bounded deterministic whole-cell segments", () => {
  assert.deepEqual(
    TERMINAL_STATE_VALUES,
    ["verified", "denied", "inconclusive", "blocked", "not_applicable"],
  );
  assert.deepEqual(COVERAGE_CREDIT_STATE_VALUES, ["verified", "denied", "not_applicable"]);
  assert.equal(preflight.declared_cell_count, 2_601);
  assert.equal(preflight.declared_event_count, 18_207);
  assert.ok(preflight.declared_event_count > LEDGER_PRESSURE_REFUSE_THRESHOLD);
  assert.equal(preflight.segment_count, 6);
  assert.equal(
    preflight.segments.reduce((total, segment) => total + segment.expected_event_count, 0),
    preflight.declared_event_count,
  );
  for (const segment of preflight.segments) {
    assert.ok(segment.expected_event_count <= preflight.segment_event_limit);
    assert.ok(segment.expected_event_count < LEDGER_PRESSURE_REFUSE_THRESHOLD);
    assert.equal(
      segment.expected_event_count,
      segment.cell_count * preflight.events_per_cell,
      "a cell is never split across ledgers",
    );
  }

  const reordered = buildPhysicalCampaignClosurePreflight(preflightInput({
    declared_dimensions: [
      { dimension_id: "technique", values: values("technique", 153).reverse() },
      { dimension_id: "asset", values: values("asset", 17).reverse() },
    ],
  }));
  assert.equal(reordered.preflight_digest, preflight.preflight_digest);
  assert.deepEqual(reordered.segments, preflight.segments);
});

test("cardinality is refused before Cartesian expansion and duplicate dimensions do not collapse silently", () => {
  assert.throws(
    () => buildPhysicalCampaignClosurePreflight(preflightInput({
      declared_dimensions: [
        { dimension_id: "a", values: values("a", 257) },
        { dimension_id: "b", values: values("b", 257) },
      ],
      events_per_cell: 1,
    })),
    (error) => error.code === "campaign_cardinality_refusal"
      && error.message.includes(String(MAX_CAMPAIGN_CELLS)),
  );
  assert.throws(
    () => buildPhysicalCampaignClosurePreflight(preflightInput({
      declared_dimensions: [
        { dimension_id: "asset", values: ["same", "same"] },
      ],
    })),
    (error) => error.code === "campaign_duplicate",
  );
  assert.throws(
    () => buildPhysicalCampaignClosurePreflight(preflightInput({
      segment_event_limit: LEDGER_PRESSURE_REFUSE_THRESHOLD,
    })),
    (error) => error.code === "campaign_contract_invalid",
  );
  assert.throws(
    () => buildPhysicalCampaignClosurePreflight(preflightInput({
      declared_dimensions: [{ dimension_id: "asset", values: ["/tmp/device"] }],
    })),
    (error) => error.code === "campaign_contract_invalid"
      && !error.message.includes("/tmp/device"),
    "declared dimensions are opaque tokens and errors do not echo path-like values",
  );
});

test("an 18,207-event campaign closes exactly and traversal order cannot change roots or totals", () => {
  const reversed = coveredSegments();
  const striped = sealCampaign({ traversal: "striped" });
  assert.deepEqual(
    striped.map((segment) => segment.sealed_segment_digest),
    reversed.map((segment) => segment.sealed_segment_digest),
    "canonical segment roots are independent of event traversal order",
  );

  const { manifest } = closeSegments(reversed);
  assert.equal(manifest.closure_satisfied, true);
  assert.equal(manifest.closure_status, "closed");
  assert.equal(manifest.event_count, 18_207);
  assert.equal(manifest.event_count, manifest.declared_event_count);
  assert.equal(manifest.terminal_cell_count, 2_601);
  assert.equal(manifest.terminal_complete, true);
  assert.equal(manifest.coverage_credited_cell_count, 2_601);
  assert.equal(manifest.terminal_state_counts.denied, 2_601);
  assert.equal(manifest.residue_cell_count, 0);
  assert.equal(manifest.segment_count, preflight.segment_count);
  assert.equal(manifest.segment_receipts[0].previous_segment_digest, campaignGenesisDigest(preflight));
  for (let index = 1; index < manifest.segment_receipts.length; index += 1) {
    assert.equal(
      manifest.segment_receipts[index].previous_segment_digest,
      manifest.segment_receipts[index - 1].sealed_segment_digest,
    );
  }
  assert.equal(assertPhysicalCampaignClosureSatisfied(manifest), manifest);
  assert.throws(
    () => assertPhysicalCampaignClosureSatisfied(structuredClone(manifest)),
    (error) => error.code === "campaign_manifest_untrusted",
    "serialized or forged plain objects cannot assert trusted closure without durable reconstruction",
  );
  assert.throws(
    () => assertPhysicalCampaignClosureSatisfied({
      closure_satisfied: true,
      closure_status: "closed",
      terminal_complete: true,
      residue_cell_count: 0,
    }),
    (error) => error.code === "campaign_manifest_untrusted",
  );

  const stripedManifest = closeSegments(striped).manifest;
  assert.equal(stripedManifest.aggregate_closure_root, manifest.aggregate_closure_root);
  assert.equal(stripedManifest.manifest_digest, manifest.manifest_digest);
});

test("restart from an externally anchored checkpoint is exact and replay is idempotent", () => {
  const segments = coveredSegments();
  const firstRuntime = createPhysicalCampaignClosureAccumulator(preflight, {
    verifier,
  });
  firstRuntime.appendSegment(segments[0]);
  firstRuntime.appendSegment(segments[1]);
  const checkpoint = JSON.parse(JSON.stringify(firstRuntime.snapshot()));

  const resumed = createPhysicalCampaignClosureAccumulator(preflight, {
    verifier,
    checkpoint,
    expected_checkpoint_digest: checkpoint.checkpoint_digest,
  });
  const replay = resumed.appendSegment(segments[1]);
  assert.equal(replay.accepted, false);
  assert.equal(replay.replayed, true);
  assert.equal(replay.accepted_event_count, checkpoint.accepted_event_count);
  for (const segment of segments.slice(2)) resumed.appendSegment(segment);
  const resumedManifest = resumed.finalize();
  const uninterruptedManifest = closeSegments(segments).manifest;
  assert.equal(resumedManifest.aggregate_closure_root, uninterruptedManifest.aggregate_closure_root);
  assert.equal(resumedManifest.manifest_digest, uninterruptedManifest.manifest_digest);

  assert.throws(
    () => createPhysicalCampaignClosureAccumulator(preflight, {
      verifier,
      checkpoint,
    }),
    (error) => error.code === "campaign_checkpoint_anchor_required",
  );

  const trimmed = structuredClone(checkpoint);
  trimmed.accepted_segments.pop();
  assert.throws(
    () => createPhysicalCampaignClosureAccumulator(preflight, {
      verifier,
      checkpoint: trimmed,
      expected_checkpoint_digest: checkpoint.checkpoint_digest,
    }),
    (error) => error.code === "campaign_checkpoint_tamper",
    "trimmed signed checkpoints cannot be presented as the anchored authority",
  );
});

test("checkpoint validation rejects accessors and Proxies before canonical hashing can invoke them", () => {
  const runtime = createPhysicalCampaignClosureAccumulator(preflight, { verifier });
  runtime.appendSegment(coveredSegments()[0]);
  const checkpoint = structuredClone(runtime.snapshot());

  let nestedGetterReads = 0;
  const accessorCheckpoint = structuredClone(checkpoint);
  Object.defineProperty(accessorCheckpoint.accepted_segments[0], "event_root", {
    enumerable: true,
    configurable: true,
    get() {
      nestedGetterReads += 1;
      return digest("accessor-root");
    },
  });
  assert.throws(
    () => createPhysicalCampaignClosureAccumulator(preflight, {
      verifier,
      checkpoint: accessorCheckpoint,
      expected_checkpoint_digest: checkpoint.checkpoint_digest,
    }),
    (error) => error.code === "campaign_contract_invalid",
  );
  assert.equal(nestedGetterReads, 0, "nested segment accessors are not evaluated");

  let arrayGetterReads = 0;
  const arrayAccessorCheckpoint = structuredClone(checkpoint);
  const firstSegment = arrayAccessorCheckpoint.accepted_segments[0];
  Object.defineProperty(arrayAccessorCheckpoint.accepted_segments, "0", {
    enumerable: true,
    configurable: true,
    get() {
      arrayGetterReads += 1;
      return firstSegment;
    },
  });
  assert.throws(
    () => createPhysicalCampaignClosureAccumulator(preflight, {
      verifier,
      checkpoint: arrayAccessorCheckpoint,
      expected_checkpoint_digest: checkpoint.checkpoint_digest,
    }),
    (error) => error.code === "campaign_contract_invalid",
  );
  assert.equal(arrayGetterReads, 0, "array index accessors are not evaluated");

  let proxyReads = 0;
  const proxyCheckpoint = new Proxy(checkpoint, {
    get(target, property, receiver) {
      proxyReads += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  assert.throws(
    () => createPhysicalCampaignClosureAccumulator(preflight, {
      verifier,
      checkpoint: proxyCheckpoint,
      expected_checkpoint_digest: checkpoint.checkpoint_digest,
    }),
    (error) => error.code === "campaign_contract_invalid",
  );
  assert.equal(proxyReads, 0, "Proxy traps are not evaluated before rejection");
});

test("gap, valid fork, duplicate source evidence, duplicate event slots, and incomplete closure fail closed", () => {
  const segments = coveredSegments();
  const gapRuntime = createPhysicalCampaignClosureAccumulator(preflight, {
    verifier,
  });
  assert.throws(
    () => gapRuntime.appendSegment(segments[1]),
    (error) => error.code === "campaign_segment_gap",
  );
  assert.throws(
    () => gapRuntime.finalize(),
    (error) => error.code === "campaign_incomplete",
  );

  const forkRuntime = createPhysicalCampaignClosureAccumulator(preflight, {
    verifier,
  });
  forkRuntime.appendSegment(segments[0]);
  const validFork = sealPhysicalCampaignClosureSegment(
    preflight,
    0,
    eventsForSegment(preflight.segments[0], { sourceVariant: "valid-fork" }),
    {
      previous_segment_digest: campaignGenesisDigest(preflight),
      materialized_graph_hash: digest("materialized-graph:0"),
      signer,
    },
  );
  assert.throws(
    () => forkRuntime.appendSegment(validFork),
    (error) => error.code === "campaign_segment_fork",
  );

  const duplicateRuntime = createPhysicalCampaignClosureAccumulator(preflight, {
    verifier,
  });
  duplicateRuntime.appendSegment(segments[0]);
  const duplicateEvents = eventsForSegment(preflight.segments[1]);
  duplicateEvents[0].source_event_digest = segments[0].source_event_digests[0];
  const duplicateSegment = sealPhysicalCampaignClosureSegment(
    preflight,
    1,
    duplicateEvents,
    {
      previous_segment_digest: segments[0].sealed_segment_digest,
      materialized_graph_hash: digest("materialized-graph:1"),
      signer,
    },
  );
  assert.throws(
    () => duplicateRuntime.appendSegment(duplicateSegment),
    (error) => error.code === "campaign_duplicate",
  );

  const duplicateSlots = eventsForSegment(preflight.segments[0]);
  duplicateSlots[1] = { ...duplicateSlots[0] };
  assert.throws(
    () => sealPhysicalCampaignClosureSegment(
      preflight,
      0,
      duplicateSlots,
      {
        previous_segment_digest: campaignGenesisDigest(preflight),
        materialized_graph_hash: digest("materialized-graph:0"),
        signer,
      },
    ),
    (error) => error.code === "campaign_duplicate",
  );
});

test("tamper, signer drift, and checkpoint projection forgery fail before closure", () => {
  const segment = coveredSegments()[0];
  assert.throws(
    () => sealPhysicalCampaignClosureSegment(preflight, 0, [], {
      previous_segment_digest: campaignGenesisDigest(preflight),
      materialized_graph_hash: digest("materialized-graph:0"),
      signer: structuredClone(signer),
    }),
    (error) => error.code === "campaign_signer_port_untrusted",
    "a cloned signer descriptor does not retain the private port brand",
  );
  assert.throws(
    () => verifyPhysicalCampaignClosureSegment(segment, preflight, {
      verifier: structuredClone(verifier),
      expected_previous_segment_digest: campaignGenesisDigest(preflight),
    }),
    (error) => error.code === "campaign_verifier_port_untrusted",
    "a cloned verifier descriptor does not retain the public-key port brand",
  );
  const tampered = structuredClone(segment);
  tampered.event_root = digest("forged-event-root");
  assert.throws(
    () => verifyPhysicalCampaignClosureSegment(tampered, preflight, {
      verifier,
      expected_previous_segment_digest: campaignGenesisDigest(preflight),
    }),
    (error) => error.code === "campaign_segment_tamper",
  );

  const authorityDrift = structuredClone(segment);
  authorityDrift.authority_binding_digest = digest("other-authority");
  assert.throws(
    () => verifyPhysicalCampaignClosureSegment(authorityDrift, preflight, {
      verifier,
      expected_previous_segment_digest: campaignGenesisDigest(preflight),
    }),
    (error) => error.code === "campaign_authority_drift",
  );

  assert.throws(
    () => verifyPhysicalCampaignClosureSegment(segment, preflight, {
      verifier: { verify_ed25519: () => true },
      expected_previous_segment_digest: campaignGenesisDigest(preflight),
    }),
    (error) => error.code === "campaign_verifier_port_untrusted",
  );

  const runtime = createPhysicalCampaignClosureAccumulator(preflight, {
    verifier,
  });
  runtime.appendSegment(segment);
  const checkpoint = structuredClone(runtime.snapshot());
  checkpoint.accepted_event_count -= 1;
  assert.throws(
    () => createPhysicalCampaignClosureAccumulator(preflight, {
      verifier,
      checkpoint,
      expected_checkpoint_digest: runtime.snapshot().checkpoint_digest,
    }),
    (error) => error.code === "campaign_checkpoint_tamper",
  );
});

test("terminal residue remains cryptographically visible and can never report successful closure", () => {
  const residueCell = preflight.segments[0].cell_ids[0];
  const segments = sealCampaign({
    traversal: "reverse",
    terminalStateForCell: (cellId) => (cellId === residueCell ? "inconclusive" : "denied"),
  });
  const { manifest } = closeSegments(segments);
  assert.equal(manifest.event_count, preflight.declared_event_count);
  assert.equal(manifest.terminal_cell_count, preflight.declared_cell_count);
  assert.equal(manifest.terminal_complete, true);
  assert.equal(manifest.coverage_credited_cell_count, preflight.declared_cell_count - 1);
  assert.equal(manifest.residue_cell_count, 1);
  assert.equal(manifest.terminal_state_counts.inconclusive, 1);
  assert.equal(manifest.closure_status, "terminal_residue");
  assert.equal(manifest.closure_satisfied, false);
  assert.deepEqual(manifest.residue_cells.map((cell) => cell.cell_id), [residueCell]);
  assert.throws(
    () => assertPhysicalCampaignClosureSatisfied(manifest),
    (error) => error.code === "campaign_terminal_residue",
  );
  assert.notEqual(manifest.aggregate_closure_root, closeSegments(coveredSegments()).manifest.aggregate_closure_root);
});
