"use strict";

// Plane X Cycle X.5 — Capability-pack derivation function tests.
//
// X.5 ships:
//   - mcp/lib/capability-pack-derivation.js exporting derivePackForNode +
//     buildOneHopGraphContext + the load-time purity lint guard.
//   - mcp/lib/technique-packs.js gains the web3_identity_handoff technique
//     pack content + the TECHNIQUE_PACKS_BY_ID / getTechniquePackById
//     lookup helper.
//
// Per the Do step 4 (Review) the suite covers:
//   1. 3× byte-identical output for the same inputs (X-P4 determinism).
//   2. Transition node pack contains BOTH endpoint families' tools.
//   3. ≤1-hop bound enforced (X-P5: graph_context trimmed beyond 1-hop).
//   4. Hypothesis node pack matches Contract's production_paths.
//   5. recommended_reads_for_node[] populated from a Contract carrying a
//      relational_value_match witness across http_record:R7 + evm_call:T9
//      (so the brief renderer can inline both refs' distilled summaries).
// Plus auxiliary checks for the X-P4 lint guard, the technique pack
// surfacing under web3_identity_handoff, and the brief_emphasis projection.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const {
  DEFAULT_CAPABILITY_PACK_ID,
  EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK,
  RECOMMENDED_READS_HARD_CAP,
  RECOMMENDED_READS_PER_SURFACE,
  WEB3_IDENTITY_HANDOFF_PACK_ID,
  routabilityForSurfaceMetadata,
  buildOneHopGraphContext,
  derivePackForNode,
} = require("../mcp/core/capability/capability-pack-derivation.js");
const {
  WEB3_IDENTITY_HANDOFF_TECHNIQUE_PACK,
  TECHNIQUE_PACKS_BY_ID,
  getTechniquePackById,
} = require("../mcp/core/dispatch/technique-packs.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
} = require("../mcp/core/waves/task-graph-events.js");
const {
  normalizeContract,
} = require("../mcp/core/contract/index.js");
const {
  VALID_ROLE_BUNDLES,
  toolNamesForRoleBundle,
  roleBundleResolvesToTools,
} = require("../mcp/tools/tool-registry.js");

// ─── Fixtures ────────────────────────────────────────────────────────────

function webSurfaceMetadata(id) {
  return {
    id,
    surface_type: "api",
  };
}

function smartContractEvmSurfaceMetadata(id) {
  return {
    id,
    surface_type: "smart_contract",
    chain_family: "evm",
  };
}

function smartContractSvmSurfaceMetadata(id) {
  return {
    id,
    surface_type: "smart_contract",
    chain_family: "svm",
  };
}

function makeSurfaceNode(nodeId, surfaceId) {
  return {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-${nodeId}`,
    kind: "surface",
    state: "proposed",
    surface_refs: [surfaceId],
    contract_hash: null,
    severity_floor: null,
    priority: "medium",
    ts_first: "2026-05-31T00:00:00.000Z",
    ts_last: "2026-05-31T00:00:00.000Z",
    source_events: ["FE-fixture-surface"],
  };
}

function makeTransitionNode(nodeId, fromSurfaceId, toSurfaceId) {
  return {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}T-${nodeId}`,
    kind: "transition",
    state: "proposed",
    surface_refs: [fromSurfaceId, toSurfaceId],
    contract_hash: null,
    severity_floor: null,
    priority: "medium",
    ts_first: "2026-05-31T00:00:00.000Z",
    ts_last: "2026-05-31T00:00:00.000Z",
    source_events: ["FE-fixture-transition"],
  };
}

function makeHypothesisNode(nodeId, surfaceRefs) {
  return {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}H-${nodeId}`,
    kind: "hypothesis",
    state: "proposed",
    surface_refs: surfaceRefs.slice(),
    contract_hash: null,
    severity_floor: null,
    priority: "medium",
    ts_first: "2026-05-31T00:00:00.000Z",
    ts_last: "2026-05-31T00:00:00.000Z",
    source_events: ["FE-fixture-hypothesis"],
  };
}

function relationalContract({
  contractId = "C-cross-stack",
  leftRef = "http_record:R7",
  rightRef = "evm_call:T9",
  severityFloor = "high",
} = {}) {
  return normalizeContract({
    contract_id: contractId,
    severity_floor: severityFloor,
    invariants: [
      { id: "I1", statement: "off-chain auth principal must equal on-chain signer" },
    ],
    witnesses: [
      {
        id: "W1",
        kind: "relational_value_match",
        predicate: {
          left: { artifact_ref: leftRef, extract_path: "$.payload.sub" },
          op: "eq",
          right: { artifact_ref: rightRef, extract_path: "$.recovered_signer" },
        },
      },
    ],
    production_paths: [
      {
        description: "fetch the auth token then recover the on-chain signer",
        tool_call_pattern: [
          { tool: "bob_http_scan" },
          { tool: "bob_evm_call" },
        ],
      },
    ],
  });
}

// ─── Constants are wired correctly ───────────────────────────────────────

test("WEB3_IDENTITY_HANDOFF_PACK_ID matches the technique pack id", () => {
  assert.equal(WEB3_IDENTITY_HANDOFF_PACK_ID, "web3_identity_handoff");
  assert.equal(WEB3_IDENTITY_HANDOFF_TECHNIQUE_PACK.id, "web3_identity_handoff");
});

test("web3_identity_handoff lens_affinity covers every X.3 transition kind", () => {
  const expected = [
    "identity_propagation",
    "value_movement",
    "trust_handoff",
    "state_dependency",
    "oracle_dependency",
    "message_passing",
  ];
  for (const kind of expected) {
    assert.ok(
      WEB3_IDENTITY_HANDOFF_TECHNIQUE_PACK.lens_affinity.includes(kind),
      `lens_affinity should include ${kind}`,
    );
  }
});

test("web3_identity_handoff summary carries the cross-stack hunting vocabulary", () => {
  const summary = WEB3_IDENTITY_HANDOFF_TECHNIQUE_PACK.summary;
  // Direct echoes of the X.5 Do step 2 spec wording.
  const wantedSubstrings = [
    "token-to-wallet correlation",
    "off-chain auth assumption used as on-chain trust",
    "signature recovery accepting forged eth_sign",
    "meta-transaction replay",
    "gas relayer permission escalation",
    "message-bridge validator threshold under-set",
  ];
  for (const sub of wantedSubstrings) {
    assert.ok(
      summary.includes(sub),
      `summary should include "${sub}" — got: ${summary}`,
    );
  }
});

test("getTechniquePackById resolves both OSS packs and the new web3 pack", () => {
  // Existing OSS pack still resolves (regression for Cycle O.6 surface).
  assert.equal(getTechniquePackById("oss_dependency").id, "oss_dependency");
  // New pack resolves.
  assert.equal(getTechniquePackById(WEB3_IDENTITY_HANDOFF_PACK_ID).id, WEB3_IDENTITY_HANDOFF_PACK_ID);
  // Unknown id returns null.
  assert.equal(getTechniquePackById("not-a-pack"), null);
});

test("TECHNIQUE_PACKS_BY_ID is frozen and complete", () => {
  assert.ok(Object.isFrozen(TECHNIQUE_PACKS_BY_ID));
  assert.ok(Object.prototype.hasOwnProperty.call(TECHNIQUE_PACKS_BY_ID, WEB3_IDENTITY_HANDOFF_PACK_ID));
  assert.ok(Object.prototype.hasOwnProperty.call(TECHNIQUE_PACKS_BY_ID, "oss_dependency"));
});

test("DEFAULT_CAPABILITY_PACK_ID is web", () => {
  assert.equal(DEFAULT_CAPABILITY_PACK_ID, "web");
});

test("EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK is keyed on every dispatchable capability pack", () => {
  const { dispatchableCapabilityPacks } = require("../mcp/core/capability/capability-packs.js");
  for (const packId of dispatchableCapabilityPacks().map((pack) => pack.id)) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK, packId),
      `EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK missing key for ${packId}`,
    );
  }
});

// Reusable closure helper (the pattern T3/T7 reuse against their own
// source-of-truth lists + predicates): iterate values, apply a structural
// predicate, report offenders via deepEqual([]).
function assertBundleListClosed(bundles, label) {
  const dead = bundles.filter((b) => !roleBundleResolvesToTools(b));
  assert.deepEqual(dead, [], `${label}: dead role bundles: ${dead.join(", ")}`);
}

test("EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK faithfully projects dispatchable packs only", () => {
  const {
    CAPABILITY_PACKS,
    PHYSICAL_CAPABILITY_PACK,
    dispatchableCapabilityPacks,
  } = require("../mcp/core/capability/capability-packs.js");
  const dispatchablePacks = dispatchableCapabilityPacks();
  assert.deepEqual(
    Object.keys(EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK).sort(),
    dispatchablePacks.map((pack) => pack.id).sort(),
    "derived map key set must equal the dispatchable capability-pack key set",
  );
  for (const pack of dispatchablePacks) {
    const packId = pack.id;
    assert.deepEqual(
      EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK[packId],
      pack.role_bundles,
      `derived bundles for ${packId} must equal CAPABILITY_PACKS.${packId}.role_bundles`,
    );
  }
  assert.equal(CAPABILITY_PACKS.physical, PHYSICAL_CAPABILITY_PACK);
  assert.equal(PHYSICAL_CAPABILITY_PACK.dispatchable, false);
  assert.deepEqual(PHYSICAL_CAPABILITY_PACK.role_bundles, ["evaluator-physical"]);
  assert.equal(
    Object.prototype.hasOwnProperty.call(EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK, "physical"),
    false,
    "a registered inactive pack must not mint evaluator role/tool authority",
  );
});

// CR-1 closure: keys existing is not enough — every VALUE (each derived role
// bundle) must be a declared VALID_ROLE_BUNDLES member AND resolve to a
// non-empty tool set. This closes the dead-bundle class (e.g. the historical
// `evaluator-oss`, a valid-looking name no tool declared, which silently
// produced zero OSS tools per surface). Data-agnostic: it fails on any pack
// that maps onto a non-member or empty-resolving bundle, not just the bundle
// that happened to be wrong when it was written.
test("every derived evaluator role bundle is a VALID_ROLE_BUNDLES member that resolves to >=1 tool", () => {
  for (const [packId, bundles] of Object.entries(EVALUATOR_ROLE_BUNDLES_BY_CAPABILITY_PACK)) {
    assert.ok(
      Array.isArray(bundles) && bundles.length > 0,
      `pack ${packId} must derive at least one role bundle`,
    );
    for (const bundle of bundles) {
      // The registry predicate must agree with the raw conjunction — guards
      // against the helper silently weakening to always-true in a refactor.
      assert.equal(
        roleBundleResolvesToTools(bundle),
        VALID_ROLE_BUNDLES.includes(bundle) && toolNamesForRoleBundle(bundle).length > 0,
        `roleBundleResolvesToTools(${bundle}) disagrees with raw membership/tool-count`,
      );
    }
    assertBundleListClosed(bundles, `pack ${packId}`);
  }
});

test("every VALID_ROLE_BUNDLES entry itself resolves to >=1 tool (no orphan-declared bundles)", () => {
  const orphans = VALID_ROLE_BUNDLES.filter((b) => toolNamesForRoleBundle(b).length === 0);
  assert.deepEqual(orphans, [], `declared role bundles with no tools: ${orphans.join(", ")}`);
});

test("oss_native_code allowed tools include bob_static_scan + bob_import_static_artifact", () => {
  const node = {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}oss-native`,
    kind: "surface",
    surface_refs: ["surface:oss"],
  };
  const graphContext = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { "surface:oss": { capability_pack: "oss_native_code" } },
  };
  const out = derivePackForNode(node, graphContext, [], null);
  const tools = new Set(out.allowed_tools_for_node);
  assert.ok(tools.has("bob_static_scan"), "oss_native_code must surface bob_static_scan");
  assert.ok(
    tools.has("bob_import_static_artifact"),
    "oss_native_code must surface bob_import_static_artifact",
  );
});

// ─── X-P4 lint guard ─────────────────────────────────────────────────────

test("the derivation module's purity guard ran at load time without throwing", () => {
  // If the lint guard had tripped, the require() at the top of this file
  // would have thrown. Re-require with cache invalidation to exercise the
  // load path a second time so a future regression that adds Date.now()
  // (or similar) trips the guard in CI.
  const modulePath = require.resolve("../mcp/core/capability/capability-pack-derivation.js");
  delete require.cache[modulePath];
  assert.doesNotThrow(() => {
    require("../mcp/core/capability/capability-pack-derivation.js");
  });
});

test("the derivation module's source body contains no forbidden patterns under purity", () => {
  // Mirror the in-module lint guard so the same property is also asserted at
  // test-time. Belt-and-suspenders: if a regression sneaks in via a path the
  // load-time guard misses (e.g., dynamic require) the test still catches it.
  const source = fs.readFileSync(
    path.join(__dirname, "..", "mcp", "core", "capability", "capability-pack-derivation.js"),
    "utf8",
  );
  const divider = "─── Per-node-kind derivations ───";
  const dividerIdx = source.indexOf(divider);
  assert.ok(dividerIdx > 0, "divider must be present so the lint body is identifiable");
  const body = source.slice(dividerIdx);
  // Strip comments and string literals before scanning — same discipline as
  // the in-module guard so a comment about Date.now() doesn't trip the test.
  const stripped = body
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/`(?:\\.|[^`\\])*`/g, "``")
    .replace(/([=(,:&|!])\s*\/(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\])+\/[a-z]*/g, "$1 /__re__/");
  const forbiddenPatterns = [
    new RegExp("\\b" + "Date" + "\\s*\\."),
    new RegExp("\\b" + "Date" + "\\s*\\("),
    new RegExp("\\bnew\\s+" + "Date" + "\\b"),
    new RegExp("\\b" + "Math" + "\\.random\\b"),
    new RegExp("\\b" + "process" + "\\.env\\b"),
    new RegExp("\\b" + "performance" + "\\.now\\b"),
  ];
  for (const re of forbiddenPatterns) {
    assert.ok(!re.test(stripped), `forbidden pattern ${re} must not appear in derivation body`);
  }
});

test("the lint guard regexes actually trip on synthetic forbidden source", () => {
  // Positive control: feed the same regexes used by the in-module lint guard
  // a body that DOES contain each forbidden pattern. Confirms the regex
  // pattern is real and the stripping discipline doesn't disable it.
  const stripFn = (src) => src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/'(?:\\.|[^'\\])*'/g, "''")
    .replace(/`(?:\\.|[^`\\])*`/g, "``")
    .replace(/([=(,:&|!])\s*\/(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\])+\/[a-z]*/g, "$1 /__re__/");
  const samples = [
    { src: "const ts = " + "Date" + ".now();", re: new RegExp("\\b" + "Date" + "\\s*\\.") },
    { src: "const ts = " + "Date" + "();", re: new RegExp("\\b" + "Date" + "\\s*\\(") },
    { src: "const d = new " + "Date" + "(0);", re: new RegExp("\\bnew\\s+" + "Date" + "\\b") },
    { src: "const r = " + "Math" + ".random();", re: new RegExp("\\b" + "Math" + "\\.random\\b") },
    { src: "const h = " + "process" + ".env.HOME;", re: new RegExp("\\b" + "process" + "\\.env\\b") },
    { src: "const t = " + "performance" + ".now();", re: new RegExp("\\b" + "performance" + "\\.now\\b") },
  ];
  for (const sample of samples) {
    const stripped = stripFn(sample.src);
    assert.ok(
      sample.re.test(stripped),
      `regex ${sample.re} should trip on synthetic body containing the forbidden pattern (${sample.src})`,
    );
  }
});

// ─── derivePackForNode shape + input validation ──────────────────────────

test("derivePackForNode throws on non-object node", () => {
  assert.throws(
    () => derivePackForNode(null, {}, [], null),
    /node must be an object/,
  );
});

test("derivePackForNode throws on node without the TG- id prefix", () => {
  assert.throws(
    () => derivePackForNode({ node_id: "S-foo", kind: "surface", surface_refs: [] }, {}, [], null),
    /TG- prefix/,
  );
});

test("derivePackForNode throws on unsupported kind", () => {
  const node = {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-foo`,
    kind: "bogus",
    surface_refs: [],
  };
  assert.throws(
    () => derivePackForNode(node, {}, [], null),
    /unsupported node kind/,
  );
});

test("derivePackForNode returns a stable pack for a cell node", () => {
  const node = {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}cell-alpha`,
    kind: "cell",
    surface_refs: ["surface:alpha"],
  };
  const result = derivePackForNode(node, {}, [], null);
  assert.ok(Object.isFrozen(result));
  assert.equal(result.brief_emphasis.node_kind, "cell");
  assert.deepEqual(result.brief_emphasis.capability_pack_ids, []);
  assert.ok(
    result.allowed_tools_for_node.length > 0,
    "cell carries the evaluator-shared baseline",
  );
  // X-P4 determinism: byte-identical across calls.
  assert.deepEqual(derivePackForNode(node, {}, [], null), result);
});

test("derivePackForNode returns a frozen result with the documented keys", () => {
  const node = makeSurfaceNode("alpha", "surface:alpha");
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { "surface:alpha": webSurfaceMetadata("surface:alpha") },
  }, [], null);
  assert.ok(Object.isFrozen(result));
  assert.deepEqual(Object.keys(result).sort(), [
    "allowed_tools_for_node",
    "brief_emphasis",
    "cli_tool_packs",
    "recommended_reads_for_node",
    "technique_packs",
  ]);
  assert.ok(Object.isFrozen(result.allowed_tools_for_node));
  assert.ok(Object.isFrozen(result.technique_packs));
  assert.ok(Object.isFrozen(result.recommended_reads_for_node));
});

// ─── Determinism (Do step 4.1: 3× byte-identical output) ─────────────────

test("derivePackForNode produces byte-identical output across 3 calls (X-P4 determinism)", () => {
  const node = makeTransitionNode("auth-bridge", "surface:auth", "surface:vault");
  const graphContext = {
    adjacent_nodes: [
      makeSurfaceNode("auth-node", "surface:auth"),
      makeSurfaceNode("vault-node", "surface:vault"),
    ],
    incident_edges: [
      {
        from_node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-auth-node`,
        to_node_id: node.node_id,
        edge_kind: "bridges",
        weight: 1,
        source_event_id: "FE-edge-auth",
      },
      {
        from_node_id: node.node_id,
        to_node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-vault-node`,
        edge_kind: "bridges",
        weight: 1,
        source_event_id: "FE-edge-vault",
      },
    ],
    surface_metadata_by_id: {
      "surface:auth": webSurfaceMetadata("surface:auth"),
      "surface:vault": smartContractEvmSurfaceMetadata("surface:vault"),
    },
  };
  const observationHistory = [
    {
      kind: "observation.recorded",
      payload: { kind: "http_record_observed", artifact_ref: "http_record:R7" },
    },
    {
      kind: "observation.recorded",
      payload: { kind: "http_record_observed", artifact_ref: "http_record:R8" },
    },
  ];
  const contract = relationalContract();

  const first = derivePackForNode(node, graphContext, observationHistory, contract);
  const second = derivePackForNode(node, graphContext, observationHistory, contract);
  const third = derivePackForNode(node, graphContext, observationHistory, contract);

  // Pure functions return byte-identical canonical JSON for the same inputs.
  const a = JSON.stringify(first);
  const b = JSON.stringify(second);
  const c = JSON.stringify(third);
  assert.equal(a, b);
  assert.equal(b, c);
});

// ─── Transition node UNION of endpoint families (Do step 4.2) ───────────

test("Transition node pack UNIONs both endpoint families' tools", () => {
  const node = makeTransitionNode("auth-bridge", "surface:auth", "surface:vault");
  const graphContext = {
    adjacent_nodes: [
      makeSurfaceNode("auth-node", "surface:auth"),
      makeSurfaceNode("vault-node", "surface:vault"),
    ],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:auth": webSurfaceMetadata("surface:auth"),
      "surface:vault": smartContractEvmSurfaceMetadata("surface:vault"),
    },
  };
  const result = derivePackForNode(node, graphContext, [], null);
  // Sanity: the brief emphasis lists both endpoint packs.
  assert.deepEqual(
    result.brief_emphasis.endpoint_capability_packs.slice().sort(),
    ["smart_contract_evm", "web"],
  );
  // Tool union: web tools (bob_http_scan) AND smart_contract_evm tools
  // (bob_foundry_run / bob_evm_call / bob_evm_fetch_source) are all
  // surfaced via allowed_tools_for_node[].
  const allowed = result.allowed_tools_for_node;
  assert.ok(allowed.includes("bob_http_scan"), "transition pack must include the web producer");
  assert.ok(allowed.includes("bob_foundry_run"), "transition pack must include the EVM runner");
  assert.ok(allowed.includes("bob_evm_call"), "transition pack must include the EVM read tool");
  assert.ok(allowed.includes("bob_evm_fetch_source"), "transition pack must include the EVM source fetch tool");
});

function smartContractUnroutableSurfaceMetadata(id) {
  return {
    id,
    surface_type: "smart_contract",
    chain_family: "dogechain",
  };
}

test("Transition with a chain endpoint + an UNROUTABLE-SC endpoint contributes the chain pack + evaluator-shared baseline, never web", () => {
  // The unroutable endpoint must NOT be laundered into the web pack (as
  // deriveSurfacePack already refuses to do). It contributes only the read-only
  // evaluator-shared baseline; the routable EVM endpoint still contributes its
  // chain pack. bob_http_scan (the true web producer, absent from
  // evaluator-shared) proves no web attack toolset leaked in.
  const node = makeTransitionNode("evm-doge", "surface:evm", "surface:doge");
  const graphContext = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:evm": smartContractEvmSurfaceMetadata("surface:evm"),
      "surface:doge": smartContractUnroutableSurfaceMetadata("surface:doge"),
    },
  };
  const result = derivePackForNode(node, graphContext, [], null);
  // The unroutable endpoint contributes NO capability_pack id — only the EVM pack.
  assert.deepEqual(result.brief_emphasis.endpoint_capability_packs, ["smart_contract_evm"]);
  const allowed = result.allowed_tools_for_node;
  // Chain tools present.
  assert.ok(allowed.includes("bob_evm_call"), "chain endpoint still contributes its EVM read tool");
  assert.ok(allowed.includes("bob_foundry_run"), "chain endpoint still contributes its EVM runner");
  // Evaluator-shared baseline present (the unroutable endpoint's contribution).
  const shared = toolNamesForRoleBundle("evaluator-shared");
  for (const tool of shared) {
    assert.ok(allowed.includes(tool), `evaluator-shared tool ${tool} must be in the union`);
  }
  // The web producer is NOT injected by the unroutable SC.
  assert.ok(!allowed.includes("bob_http_scan"), "unroutable SC must not inject the web producer");
});

test("Transition with a GENUINE WEB endpoint + an unroutable-SC endpoint STILL includes web tools (web-regression guard — fix did not 'skip web')", () => {
  // The trap: packIdForSurfaceMetadata returns "web" for BOTH a genuine web
  // endpoint AND an unroutable SC. The fix must discriminate via routability so
  // it does NOT drop a legitimate web endpoint. Prove bob_http_scan survives.
  const node = makeTransitionNode("web-doge", "surface:web", "surface:doge");
  const graphContext = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:web": webSurfaceMetadata("surface:web"),
      "surface:doge": smartContractUnroutableSurfaceMetadata("surface:doge"),
    },
  };
  const result = derivePackForNode(node, graphContext, [], null);
  // The genuine web endpoint still contributes the web pack id (the unroutable
  // one contributes none).
  assert.deepEqual(result.brief_emphasis.endpoint_capability_packs, ["web"]);
  const allowed = result.allowed_tools_for_node;
  assert.ok(allowed.includes("bob_http_scan"), "genuine web endpoint STILL contributes the web producer");
});

test("Transition with BOTH endpoints unroutable yields the evaluator-shared baseline, never web", () => {
  // The surface_refs-seen-but-all-unroutable path: the web fallback guard fires
  // only when surface_refs is empty AND the tool set is empty, so a transition
  // whose endpoints exist but are all unroutable must union to exactly the
  // evaluator-shared baseline — no pack ids, no web fallback.
  const node = makeTransitionNode("doge-doge2", "surface:doge", "surface:doge2");
  const graphContext = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:doge": smartContractUnroutableSurfaceMetadata("surface:doge"),
      "surface:doge2": smartContractUnroutableSurfaceMetadata("surface:doge2"),
    },
  };
  const result = derivePackForNode(node, graphContext, [], null);
  assert.deepEqual(result.brief_emphasis.endpoint_capability_packs, []);
  const allowed = result.allowed_tools_for_node;
  const shared = toolNamesForRoleBundle("evaluator-shared");
  for (const tool of shared) {
    assert.ok(allowed.includes(tool), `evaluator-shared tool ${tool} must be in the all-unroutable union`);
  }
  assert.ok(!allowed.includes("bob_http_scan"), "all-unroutable transition must not fall back to web");
  assert.ok(!allowed.includes("bob_evm_call"), "all-unroutable transition carries no chain tools");
});

test("Transition CELL pack UNIONs both endpoint families' tools (cross-stack cell fix)", () => {
  // A transition cell (kind 'cell', surface_refs=[from,to]) must get the SAME
  // cross-stack union a transition NODE gets. Without it a web->EVM handoff cell
  // gets only the web baseline (no bob_evm_*), so the cell agent's honest EVM work
  // is rejected by the X.6 tool_constraint_violation check at bob_finalize_node.
  const cellNode = {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}cell-xstack`,
    kind: "cell",
    state: "contracted",
    surface_refs: ["surface:auth", "surface:vault"],
    contract_hash: null,
    severity_floor: null,
    priority: "medium",
    ts_first: "2026-05-31T00:00:00.000Z",
    ts_last: "2026-05-31T00:00:00.000Z",
    source_events: ["FE-fixture-cell"],
  };
  const graphContext = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:auth": webSurfaceMetadata("surface:auth"),
      "surface:vault": smartContractEvmSurfaceMetadata("surface:vault"),
    },
  };
  const allowed = derivePackForNode(cellNode, graphContext, [], null).allowed_tools_for_node;
  assert.ok(allowed.includes("bob_http_scan"), "cross-stack cell includes the web producer");
  assert.ok(allowed.includes("bob_evm_call"), "cross-stack cell includes the EVM read tool (the fix)");
  assert.ok(allowed.includes("bob_evm_fetch_source"), "cross-stack cell includes the EVM source fetch tool");
});

test("A single-surface cell keeps the evaluator-shared baseline (no cross-stack union)", () => {
  const cellNode = {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}cell-single`,
    kind: "cell",
    state: "contracted",
    surface_refs: ["surface:web"],
    contract_hash: null,
    severity_floor: null,
    priority: "medium",
    ts_first: "2026-05-31T00:00:00.000Z",
    ts_last: "2026-05-31T00:00:00.000Z",
    source_events: ["FE-fixture-cell"],
  };
  const graphContext = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { "surface:web": webSurfaceMetadata("surface:web") },
  };
  const allowed = derivePackForNode(cellNode, graphContext, [], null).allowed_tools_for_node;
  assert.ok(!allowed.includes("bob_evm_call"), "a single-surface cell does NOT get cross-stack EVM tools");
});

test("Transition node ALWAYS includes web3_identity_handoff technique pack", () => {
  const node = makeTransitionNode("auth-bridge", "surface:auth", "surface:vault");
  const graphContext = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:auth": webSurfaceMetadata("surface:auth"),
      "surface:vault": smartContractEvmSurfaceMetadata("surface:vault"),
    },
  };
  const result = derivePackForNode(node, graphContext, [], null);
  const techniqueIds = result.technique_packs.map((p) => p.id);
  assert.ok(techniqueIds.includes(WEB3_IDENTITY_HANDOFF_PACK_ID));
});

test("Surface node WITHOUT an adjacent transition does NOT include web3_identity_handoff", () => {
  const node = makeSurfaceNode("billing", "surface:billing");
  const graphContext = {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:billing": webSurfaceMetadata("surface:billing"),
    },
  };
  const result = derivePackForNode(node, graphContext, [], null);
  const techniqueIds = result.technique_packs.map((p) => p.id);
  assert.ok(!techniqueIds.includes(WEB3_IDENTITY_HANDOFF_PACK_ID));
});

test("Surface node WITH an adjacent Transition (via ≤1-hop) DOES include web3_identity_handoff", () => {
  const node = makeSurfaceNode("billing", "surface:billing");
  const graphContext = {
    adjacent_nodes: [
      makeTransitionNode("xfer", "surface:billing", "surface:vault"),
    ],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:billing": webSurfaceMetadata("surface:billing"),
    },
  };
  const result = derivePackForNode(node, graphContext, [], null);
  const techniqueIds = result.technique_packs.map((p) => p.id);
  assert.ok(techniqueIds.includes(WEB3_IDENTITY_HANDOFF_PACK_ID));
});

// ─── ≤1-hop bound enforcement (Do step 4.3) ──────────────────────────────

test("buildOneHopGraphContext returns only direct neighbors of the dispatched node", () => {
  // Build a 3-hop chain: TG-S-a -- bridges -- TG-T-mid -- bridges -- TG-S-b
  // -- claim_links -- TG-S-c. From TG-T-mid, the ≤1-hop neighborhood is
  // {TG-S-a, TG-S-b} only — TG-S-c is 2 hops away and must be trimmed.
  const nodeA = makeSurfaceNode("a", "surface:a");
  const nodeB = makeSurfaceNode("b", "surface:b");
  const nodeC = makeSurfaceNode("c", "surface:c");
  const nodeMid = makeTransitionNode("mid", "surface:a", "surface:b");
  const materialized = {
    nodes: [nodeA, nodeB, nodeC, nodeMid],
    edges: [
      {
        from_node_id: nodeA.node_id,
        to_node_id: nodeMid.node_id,
        edge_kind: "bridges",
        weight: 1,
        source_event_id: "FE-edge-1",
      },
      {
        from_node_id: nodeMid.node_id,
        to_node_id: nodeB.node_id,
        edge_kind: "bridges",
        weight: 1,
        source_event_id: "FE-edge-2",
      },
      {
        from_node_id: nodeB.node_id,
        to_node_id: nodeC.node_id,
        edge_kind: "claim_links",
        weight: 1,
        source_event_id: "FE-edge-3",
      },
    ],
  };
  const surfaceMetadata = {
    "surface:a": webSurfaceMetadata("surface:a"),
    "surface:b": smartContractEvmSurfaceMetadata("surface:b"),
    // Include surface:c so we can prove buildOneHopGraphContext TRIMS it
    // (it sits behind a 2-hop edge from the dispatched node).
    "surface:c": webSurfaceMetadata("surface:c"),
  };
  const context = buildOneHopGraphContext(materialized, nodeMid.node_id, surfaceMetadata);
  const adjacentIds = context.adjacent_nodes.map((n) => n.node_id).sort();
  assert.deepEqual(adjacentIds, [nodeA.node_id, nodeB.node_id].sort());
  // surface:c must be trimmed — it's not referenced by the dispatched node
  // or any 1-hop neighbor.
  assert.ok(!Object.prototype.hasOwnProperty.call(context.surface_metadata_by_id, "surface:c"));
  // The two 1-hop surfaces ARE surfaced.
  assert.ok(Object.prototype.hasOwnProperty.call(context.surface_metadata_by_id, "surface:a"));
  assert.ok(Object.prototype.hasOwnProperty.call(context.surface_metadata_by_id, "surface:b"));
});

test("derivePackForNode trims surface metadata to ≤1-hop even when a caller smuggles extras", () => {
  // The dispatched Transition only knows about surface:auth and surface:vault.
  // A caller smuggling surface_metadata_by_id with "surface:other" should
  // see that the derivation ignores it (the surface isn't referenced by the
  // node or its 1-hop neighbors). Use buildOneHopGraphContext to enforce
  // the trim — that's the contract the X-P5 bound rides on.
  const node = makeTransitionNode("auth-bridge", "surface:auth", "surface:vault");
  const materialized = {
    nodes: [
      node,
      makeSurfaceNode("auth-node", "surface:auth"),
      makeSurfaceNode("vault-node", "surface:vault"),
      makeSurfaceNode("other-node", "surface:other"),
    ],
    edges: [
      {
        from_node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-auth-node`,
        to_node_id: node.node_id,
        edge_kind: "bridges",
        weight: 1,
        source_event_id: "FE-edge-1",
      },
      {
        from_node_id: node.node_id,
        to_node_id: `${TASK_GRAPH_NODE_ID_PREFIX}S-vault-node`,
        edge_kind: "bridges",
        weight: 1,
        source_event_id: "FE-edge-2",
      },
    ],
  };
  const surfaceMetadata = {
    "surface:auth": webSurfaceMetadata("surface:auth"),
    "surface:vault": smartContractEvmSurfaceMetadata("surface:vault"),
    "surface:other": smartContractSvmSurfaceMetadata("surface:other"),
  };
  const context = buildOneHopGraphContext(materialized, node.node_id, surfaceMetadata);
  // surface:other lives on a node that is NOT adjacent to the dispatched
  // Transition; the context must drop its metadata regardless of what the
  // caller passed in.
  assert.ok(!Object.prototype.hasOwnProperty.call(context.surface_metadata_by_id, "surface:other"));
  // Negative case: the resulting allowed_tools must NOT contain SVM tools.
  const result = derivePackForNode(node, context, [], null);
  const allowed = result.allowed_tools_for_node;
  assert.ok(!allowed.includes("bob_svm_fetch_program"), "SVM tools must not leak via 2-hop surfaces");
  assert.ok(!allowed.includes("bob_svm_fetch_account"), "SVM tools must not leak via 2-hop surfaces");
});

// ─── Hypothesis Contract production_paths alignment (Do step 4.4) ────────

test("Hypothesis node pack matches Contract's production_paths tools", () => {
  // A Contract whose production_paths span web + EVM should produce a pack
  // whose allowed_tools_for_node contains BOTH stacks' tools (the Contract
  // is the source of truth for a Hypothesis-node pack).
  const contract = normalizeContract({
    contract_id: "C-hypothesis-cross",
    severity_floor: "medium",
    invariants: [{ id: "I1", statement: "the bridged amount must equal the off-chain claim" }],
    witnesses: [
      {
        id: "W1",
        kind: "tool_output_match",
        predicate: { tool: "bob_http_scan", match: { path: "$.status", equals: 200 } },
      },
      {
        id: "W2",
        kind: "tool_output_match",
        predicate: { tool: "bob_evm_call", match: { path: "$.result", equals: "0x" } },
      },
    ],
    production_paths: [
      {
        description: "fetch the off-chain claim",
        tool_call_pattern: [{ tool: "bob_http_scan" }],
      },
      {
        description: "verify the on-chain balance",
        tool_call_pattern: [{ tool: "bob_evm_call" }],
      },
    ],
  });
  const node = makeHypothesisNode("cross-claim", ["surface:billing", "surface:vault"]);
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {},
  }, [], contract);
  const allowed = result.allowed_tools_for_node;
  assert.ok(allowed.includes("bob_http_scan"), "hypothesis pack must include the Contract's web tool");
  assert.ok(allowed.includes("bob_evm_call"), "hypothesis pack must include the Contract's EVM tool");
  // The brief_emphasis records the discovered capability_pack ids.
  const packIds = result.brief_emphasis.capability_pack_ids;
  assert.ok(packIds.includes("web"), "hypothesis brief_emphasis must name the web pack");
  assert.ok(packIds.includes("smart_contract_evm"), "hypothesis brief_emphasis must name the EVM pack");
});

test("Hypothesis node WITHOUT a Contract returns the shared evaluator bundle only", () => {
  const node = makeHypothesisNode("no-contract", ["surface:billing"]);
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { "surface:billing": webSurfaceMetadata("surface:billing") },
  }, [], null);
  // The pack falls back to evaluator-shared (so the agent can still read
  // session state etc), but does NOT include chain-specific tools because
  // there's no Contract pinning them.
  const allowed = result.allowed_tools_for_node;
  const sharedTools = toolNamesForRoleBundle("evaluator-shared");
  for (const tool of sharedTools) {
    assert.ok(allowed.includes(tool), `evaluator-shared tool ${tool} must be in the pack`);
  }
  // Chain-specific tools should NOT appear without a Contract.
  assert.ok(!allowed.includes("bob_foundry_run"), "EVM runner must not appear without a Contract");
  assert.ok(!allowed.includes("bob_anchor_run"), "SVM runner must not appear without a Contract");
});

// ─── recommended_reads_for_node[] from Contract (Do step 4.5) ───────────

test("recommended_reads_for_node[] populated from a Contract relational_value_match referencing http_record:R7 and evm_call:T9", () => {
  // Direct echo of the X.5 Do step 4 wording: a Contract with a
  // relational_value_match witness whose left.artifact_ref == http_record:R7
  // and right.artifact_ref == evm_call:T9 produces a pack whose
  // recommended_reads_for_node[] contains BOTH refs (in insertion order).
  const contract = relationalContract({ leftRef: "http_record:R7", rightRef: "evm_call:T9" });
  const node = makeTransitionNode("auth-bridge", "surface:auth", "surface:vault");
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:auth": webSurfaceMetadata("surface:auth"),
      "surface:vault": smartContractEvmSurfaceMetadata("surface:vault"),
    },
  }, [], contract);
  const refs = result.recommended_reads_for_node;
  assert.ok(refs.includes("http_record:R7"), "pack must surface the left.artifact_ref");
  assert.ok(refs.includes("evm_call:T9"), "pack must surface the right.artifact_ref");
});

test("recommended_reads_for_node[] preserves Contract-then-observation order and dedupes", () => {
  const contract = relationalContract({ leftRef: "http_record:R7", rightRef: "evm_call:T9" });
  const node = makeTransitionNode("auth-bridge", "surface:auth", "surface:vault");
  const observationHistory = [
    {
      kind: "observation.recorded",
      payload: { kind: "http_record_observed", artifact_ref: "http_record:R8" },
    },
    // Duplicate of a Contract-surfaced ref to prove dedupe preserves insertion order.
    {
      kind: "observation.recorded",
      payload: { kind: "http_record_observed", artifact_ref: "http_record:R7" },
    },
  ];
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:auth": webSurfaceMetadata("surface:auth"),
      "surface:vault": smartContractEvmSurfaceMetadata("surface:vault"),
    },
  }, observationHistory, contract);
  const refs = result.recommended_reads_for_node;
  // Contract refs land first; observation-only refs land after; duplicates
  // are deduped.
  assert.deepEqual(refs.slice(0, 2), ["http_record:R7", "evm_call:T9"]);
  assert.ok(refs.includes("http_record:R8"), "observation-only ref must still surface");
  // The duplicate http_record:R7 from observations must NOT be re-included.
  assert.equal(refs.filter((r) => r === "http_record:R7").length, 1);
});

test("recommended_reads_for_node[] is hard-capped per RECOMMENDED_READS_HARD_CAP", () => {
  const contract = normalizeContract({
    contract_id: "C-many",
    severity_floor: "low",
    invariants: [{ id: "I1", statement: "lots of refs to defend the brief budget" }],
    witnesses: [
      // A handful of hash_equals witnesses, each surfacing a unique ref.
      ...Array.from({ length: 20 }).map((_, i) => ({
        id: `W${i}`,
        kind: "hash_equals",
        predicate: {
          artifact_ref: `http_record:R${i}`,
          // Lowercase hex digest, 32+ chars per the normalizer.
          expected_hash: "deadbeef".repeat(8),
        },
      })),
    ],
    production_paths: [
      {
        description: "fetch the records",
        tool_call_pattern: [{ tool: "bob_http_scan" }],
      },
    ],
  });
  const node = makeHypothesisNode("many-refs", ["surface:vault"]);
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { "surface:vault": webSurfaceMetadata("surface:vault") },
  }, [], contract);
  assert.ok(
    result.recommended_reads_for_node.length <= RECOMMENDED_READS_HARD_CAP,
    `recommended_reads must be capped at ${RECOMMENDED_READS_HARD_CAP}`,
  );
});

test("recommended_reads_for_node[] is empty when there is neither a Contract nor observation refs", () => {
  const node = makeSurfaceNode("billing", "surface:billing");
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { "surface:billing": webSurfaceMetadata("surface:billing") },
  }, [], null);
  assert.equal(result.recommended_reads_for_node.length, 0);
});

// ─── Surface node mirrors static pack routing ────────────────────────────

test("Surface node with a web surface ref classifies into the web pack", () => {
  const node = makeSurfaceNode("billing", "surface:billing");
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { "surface:billing": webSurfaceMetadata("surface:billing") },
  }, [], null);
  assert.equal(result.brief_emphasis.capability_pack, "web");
  // Web producer tool is in the pack.
  assert.ok(result.allowed_tools_for_node.includes("bob_http_scan"));
});

test("Surface node with an EVM surface ref classifies into the smart_contract_evm pack", () => {
  const node = makeSurfaceNode("vault", "surface:vault");
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { "surface:vault": smartContractEvmSurfaceMetadata("surface:vault") },
  }, [], null);
  assert.equal(result.brief_emphasis.capability_pack, "smart_contract_evm");
  // EVM-specific producer is in the pack.
  assert.ok(result.allowed_tools_for_node.includes("bob_foundry_run"));
  // Web-only producer is NOT in the pack (negative check on cross-stack leakage).
  assert.ok(!result.allowed_tools_for_node.includes("bob_http_scan"));
});

test("Surface node with no surface metadata falls back to the default web pack", () => {
  const node = makeSurfaceNode("missing", "surface:missing");
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {},
  }, [], null);
  assert.equal(result.brief_emphasis.capability_pack, DEFAULT_CAPABILITY_PACK_ID);
});

// ─── Hypothesis node with a relational Contract surfaces web3_identity_handoff ───

test("Hypothesis node with a relational_value_match Contract includes web3_identity_handoff", () => {
  const contract = relationalContract();
  const node = makeHypothesisNode("cross-claim", ["surface:billing", "surface:vault"]);
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {},
  }, [], contract);
  const techniqueIds = result.technique_packs.map((p) => p.id);
  assert.ok(techniqueIds.includes(WEB3_IDENTITY_HANDOFF_PACK_ID));
});

// ─── Claim node returns a stable (wave-scheduled) pack ───────────────────

test("Claim node returns an evaluator-shared-only pack (wave-scheduled per X-D7)", () => {
  const node = {
    node_id: `${TASK_GRAPH_NODE_ID_PREFIX}C-finding-1`,
    kind: "claim",
    state: "proposed",
    surface_refs: ["surface:billing"],
    contract_hash: null,
    severity_floor: null,
    priority: "medium",
    ts_first: "2026-05-31T00:00:00.000Z",
    ts_last: "2026-05-31T00:00:00.000Z",
    source_events: ["FE-fixture-claim"],
  };
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {},
  }, [], null);
  // The pack is non-empty (shared tools always surface) but does NOT carry
  // chain-specific producers — claim nodes ride the wave-scheduler.
  assert.ok(result.allowed_tools_for_node.length > 0);
  assert.ok(!result.allowed_tools_for_node.includes("bob_foundry_run"));
  assert.ok(!result.allowed_tools_for_node.includes("bob_anchor_run"));
  assert.equal(result.brief_emphasis.node_kind, "claim");
});

// ─── Surface routability: SC routes on chain_family; unroutable never web ──

test("evm smart_contract surface derives the smart_contract_evm pack when surface_metadata_by_id is populated", () => {
  const node = makeSurfaceNode("evm-vault", "surface:evm-vault");
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:evm-vault": smartContractEvmSurfaceMetadata("surface:evm-vault"),
    },
  }, [], null);
  assert.equal(result.brief_emphasis.capability_pack, "smart_contract_evm");
  assert.ok(
    result.allowed_tools_for_node.includes("bob_evm_call"),
    "evm SC surface must surface an on-chain read tool",
  );
  // Not the web toolset: a web-only attack producer must not appear.
  assert.ok(
    !result.allowed_tools_for_node.includes("bob_http_scan"),
    "evm SC surface is not routed to the web pack",
  );
  const webNode = makeSurfaceNode("web-ref", "surface:web-ref");
  const webResult = derivePackForNode(webNode, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: { "surface:web-ref": webSurfaceMetadata("surface:web-ref") },
  }, [], null);
  assert.notDeepEqual(
    result.allowed_tools_for_node.slice().sort(),
    webResult.allowed_tools_for_node.slice().sort(),
    "evm SC toolset differs from the web toolset",
  );
});

test("unroutable smart_contract (unsupported chain_family) does NOT derive the web pack", () => {
  const node = makeSurfaceNode("doge", "surface:doge");
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:doge": { id: "surface:doge", surface_type: "smart_contract", chain_family: "dogechain" },
    },
  }, [], null);
  assert.equal(result.brief_emphasis.capability_pack, null);
  assert.equal(result.brief_emphasis.routable, false);
  assert.ok(
    typeof result.brief_emphasis.unroutable_reason === "string"
      && result.brief_emphasis.unroutable_reason.length > 0,
    "unroutable SC carries a non-empty unroutable_reason",
  );
  assert.ok(
    !result.allowed_tools_for_node.includes("bob_http_scan"),
    "unroutable SC must not carry a web-only attack tool",
  );
});

test("unroutable smart_contract (missing chain_family) does NOT derive the web pack", () => {
  const node = makeSurfaceNode("no-chain", "surface:no-chain");
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:no-chain": { id: "surface:no-chain", surface_type: "smart_contract" },
    },
  }, [], null);
  assert.equal(result.brief_emphasis.capability_pack, null);
  assert.equal(result.brief_emphasis.routable, false);
  assert.ok(
    typeof result.brief_emphasis.unroutable_reason === "string"
      && result.brief_emphasis.unroutable_reason.length > 0,
    "missing-chain_family SC carries a non-empty unroutable_reason",
  );
  assert.ok(!result.allowed_tools_for_node.includes("bob_http_scan"));
});

test("web unknown-type surface still falls back to the web pack", () => {
  const node = makeSurfaceNode("unknown", "surface:unknown");
  const result = derivePackForNode(node, {
    adjacent_nodes: [],
    incident_edges: [],
    surface_metadata_by_id: {
      "surface:unknown": { id: "surface:unknown", surface_type: "totally_unknown_type" },
    },
  }, [], null);
  assert.equal(result.brief_emphasis.capability_pack, "web");
  assert.ok(result.brief_emphasis.routable !== false, "web fallback is routable");
});

test("routabilityForSurfaceMetadata maps A1's classifier result for the three cases", () => {
  const evm = routabilityForSurfaceMetadata(smartContractEvmSurfaceMetadata("s1"));
  assert.equal(evm.routable, true);
  assert.equal(evm.pack_id, "smart_contract_evm");
  assert.equal(evm.reason, null);

  const unsupported = routabilityForSurfaceMetadata({ surface_type: "smart_contract", chain_family: "dogechain" });
  assert.equal(unsupported.routable, false);
  assert.equal(unsupported.pack_id, null);
  assert.equal(unsupported.surface_type, "smart_contract");
  assert.ok(typeof unsupported.reason === "string" && unsupported.reason.length > 0);

  const missing = routabilityForSurfaceMetadata({ surface_type: "smart_contract" });
  assert.equal(missing.routable, false);
  assert.equal(missing.pack_id, null);
  assert.ok(typeof missing.reason === "string" && missing.reason.length > 0);

  const web = routabilityForSurfaceMetadata({ surface_type: "totally_unknown_type" });
  assert.equal(web.routable, true);
  assert.equal(web.pack_id, "web");
  assert.equal(web.reason, null);

  const nonObject = routabilityForSurfaceMetadata(null);
  assert.equal(nonObject.routable, true);
  assert.equal(nonObject.pack_id, DEFAULT_CAPABILITY_PACK_ID);
});
