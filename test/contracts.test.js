"use strict";

// Plane X Cycle X.4 — Contract schema + attach with pre-dispatch
// satisfiability check.
//
// X.4 ships:
//   - mcp/lib/contracts.js with the X-D4 frozen 7-witness schema, the
//     normalizeContract / appendContract / assertContractSatisfiable
//     entry points, the X-D12 closed artifact_ref prefix set, and the
//     restricted JSONPath selector validator.
//   - mcp/lib/tools/attach-contract.js exposing bob_attach_contract.
//
// Do step 5 specifies five test families; the suite below covers them
// plus a handful of auxiliary checks that lock in the schema-level
// invariants (per-Contract severity_floor binding into contract_hash,
// witness/invariant id uniqueness, predicate normalizer round-trip):
//
//   1. hash round-trip with severity_floor (changes to severity flip the
//      hash, identical inputs reproduce the same hash).
//   2. oversize invariant statement refused (>280 chars).
//   3. re-attach refused (node already contracted; second attach refused
//      with node_not_proposed; the underlying invalid_node_transition
//      remains the lower-level guard exercised in task-graph-events tests).
//   4. satisfiability gate positive (well-formed Contract attaches) +
//      negative (a Contract referencing an unknown tool refuses with
//      contract_unsatisfiable.tool_not_in_registry; an allowed_tools_for_node
//      argument with a missing tool refuses with tool_outside_pack).
//   5. relational_value_match validator refuses unsafe extract_paths AND
//      artifact_refs whose prefix is outside the X-D12 closed set.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  ARTIFACT_REF_PREFIX_VALUES,
  INVARIANT_STATEMENT_MAX_CHARS,
  PRODUCTION_PATH_DESCRIPTION_MAX_CHARS,
  RELATIONAL_MATCH_OP_VALUES,
  SEVERITY_FLOOR_VALUES,
  WITNESS_KIND_VALUES,
  appendContract,
  artifactRefPrefix,
  assertContractSatisfiable,
  collectContractArtifactRefs,
  normalizeContract,
} = require("../mcp/lib/contracts.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
  appendHypothesisProposal,
  appendNodeTransition,
  readNodeTransitions,
} = require("../mcp/lib/task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../mcp/lib/task-graph-materializer.js");
const { TOOL_HANDLERS } = require("../mcp/lib/tool-registry.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-contracts-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Choose a real tool name that lives in the MCP registry so the
// universal satisfiability fallback (Object.hasOwnProperty on TOOL_HANDLERS)
// passes. bob_http_scan is the canonical web producer used across web-stack
// contracts; any registered tool would do but http_scan is the one the X.11
// transition contract templates lean on.
const KNOWN_TOOL = "bob_http_scan";
assert.ok(
  Object.prototype.hasOwnProperty.call(TOOL_HANDLERS, KNOWN_TOOL),
  `${KNOWN_TOOL} must be registered for the satisfiability tests to be meaningful`,
);
const SECOND_KNOWN_TOOL = "bob_evm_call";
assert.ok(
  Object.prototype.hasOwnProperty.call(TOOL_HANDLERS, SECOND_KNOWN_TOOL),
  `${SECOND_KNOWN_TOOL} must be registered for the cross-stack contract test to be meaningful`,
);

// A minimal well-formed Contract used as the base for most positive tests.
// Returns a fresh object each call so individual mutations don't pollute
// other tests.
function baseContractInput({
  contractId = "C-base",
  severity = "high",
  witnessKind = "tool_output_match",
  predicateOverride = null,
  invariantStatement = "Auth token cannot escalate roles.",
} = {}) {
  let predicate;
  if (predicateOverride) {
    predicate = predicateOverride;
  } else if (witnessKind === "tool_output_match") {
    predicate = { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } };
  } else if (witnessKind === "file_exists") {
    predicate = { path: "claims.jsonl" };
  } else if (witnessKind === "hash_equals") {
    predicate = {
      artifact_ref: "http_record:R1",
      expected_hash: "abcdef0123456789abcdef0123456789",
    };
  } else if (witnessKind === "evidence_ref_kind_present") {
    predicate = { kind: "http_replay" };
  } else if (witnessKind === "frontier_event_emitted") {
    predicate = { kind: "observation.recorded", payload_kind: "http_record_observed" };
  } else if (witnessKind === "cli_pack_invoked") {
    predicate = { cli_pack: "web_auth_probes" };
  } else if (witnessKind === "relational_value_match") {
    predicate = {
      left: { artifact_ref: "http_record:R7", extract_path: "$.response.body.sub" },
      op: "eq",
      right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
    };
  } else {
    throw new Error(`baseContractInput does not know witness kind ${witnessKind}`);
  }
  return {
    contract_id: contractId,
    severity_floor: severity,
    invariants: [{ id: "I1", statement: invariantStatement }],
    witnesses: [{ id: "W1", kind: witnessKind, predicate }],
    production_paths: [{
      description: "invoke the canonical web producer",
      tool_call_pattern: [{ tool: KNOWN_TOOL }],
    }],
  };
}

// ─── Frozen vocabulary checks ────────────────────────────────────────────

test("WITNESS_KIND_VALUES is closed at the 7 X-D4 kinds", () => {
  assert.deepEqual(WITNESS_KIND_VALUES.slice().sort(), [
    "cli_pack_invoked",
    "evidence_ref_kind_present",
    "file_exists",
    "frontier_event_emitted",
    "hash_equals",
    "relational_value_match",
    "tool_output_match",
  ]);
});

test("ARTIFACT_REF_PREFIX_VALUES is closed at the 7 X-D12 prefixes", () => {
  assert.deepEqual(ARTIFACT_REF_PREFIX_VALUES.slice().sort(), [
    "evidence_pack",
    "evm_call",
    "finding",
    "frontier_event",
    "http_record",
    "repo_check",
    "repo_command_run",
  ]);
});

test("SEVERITY_FLOOR_VALUES excludes info (per X-D9 adjudication chain mapping)", () => {
  assert.deepEqual(SEVERITY_FLOOR_VALUES.slice().sort(), ["critical", "high", "low", "medium"]);
});

test("RELATIONAL_MATCH_OP_VALUES matches the X-D4 sub-schema", () => {
  assert.deepEqual(RELATIONAL_MATCH_OP_VALUES.slice().sort(), ["contains", "eq", "neq", "subset_of"]);
});

test("INVARIANT_STATEMENT_MAX_CHARS is 280 per X.4 Do step 4", () => {
  assert.equal(INVARIANT_STATEMENT_MAX_CHARS, 280);
  assert.equal(PRODUCTION_PATH_DESCRIPTION_MAX_CHARS, 280);
});

// ─── normalizeContract: shape + hash round-trip ──────────────────────────

test("normalizeContract round-trips a minimal Contract and binds severity_floor into contract_hash", () => {
  const inputA = baseContractInput({ severity: "high" });
  const inputB = baseContractInput({ severity: "high" });
  const inputC = baseContractInput({ severity: "low" });
  const a = normalizeContract(inputA);
  const b = normalizeContract(inputB);
  const c = normalizeContract(inputC);

  // Identical inputs reproduce the same hash.
  assert.equal(a.contract_hash, b.contract_hash);
  assert.match(a.contract_hash, /^[0-9a-f]{64}$/);
  // Per X-D9: severity_floor is bound into contract_hash, so changing it
  // flips the hash. This is the anti-pattern guard against silently
  // downgrading a Contract's adjudication chain.
  assert.notEqual(a.contract_hash, c.contract_hash);
  // The normalized shape carries the severity verbatim back so callers
  // (X.5 derivePackForNode, X.8 prepare_node) see the per-Contract floor
  // without re-decoding.
  assert.equal(a.severity_floor, "high");
  assert.equal(c.severity_floor, "low");
});

test("normalizeContract reorders predicate keys for canonical hashing", () => {
  // hashCanonicalJson sorts object keys; reordering keys at the input
  // must not change the contract_hash.
  const a = normalizeContract(baseContractInput({
    predicateOverride: {
      tool: KNOWN_TOOL,
      match: { path: "$.status", equals: 200 },
    },
  }));
  const b = normalizeContract(baseContractInput({
    predicateOverride: {
      match: { equals: 200, path: "$.status" },
      tool: KNOWN_TOOL,
    },
  }));
  assert.equal(a.contract_hash, b.contract_hash);
});

test("normalizeContract refuses an oversize invariant statement", () => {
  const overlong = "x".repeat(INVARIANT_STATEMENT_MAX_CHARS + 1);
  let caught = null;
  try {
    normalizeContract(baseContractInput({ invariantStatement: overlong }));
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, "must refuse oversize invariant statement");
  assert.equal(caught.code, "prose_too_long");
  assert.equal(caught.details.field, "invariants[0].statement");
  assert.equal(caught.details.max_chars, INVARIANT_STATEMENT_MAX_CHARS);
});

test("normalizeContract refuses an empty witnesses array", () => {
  const input = baseContractInput();
  input.witnesses = [];
  assert.throws(
    () => normalizeContract(input),
    /witnesses must be a non-empty array/,
  );
});

test("normalizeContract refuses an empty production_paths array", () => {
  const input = baseContractInput();
  input.production_paths = [];
  assert.throws(
    () => normalizeContract(input),
    /production_paths must be a non-empty array/,
  );
});

test("normalizeContract refuses duplicate witness ids", () => {
  const input = baseContractInput();
  input.witnesses = [
    { id: "Wdup", kind: "file_exists", predicate: { path: "claims.jsonl" } },
    { id: "Wdup", kind: "file_exists", predicate: { path: "findings.jsonl" } },
  ];
  assert.throws(
    () => normalizeContract(input),
    /duplicate witness id: Wdup/,
  );
});

test("normalizeContract refuses an out-of-enum severity_floor", () => {
  const input = baseContractInput();
  input.severity_floor = "info";
  assert.throws(
    () => normalizeContract(input),
    /severity_floor must be one of/,
  );
});

test("normalizeContract refuses an out-of-enum witness kind", () => {
  const input = baseContractInput();
  input.witnesses = [{ id: "W1", kind: "magical_witness", predicate: {} }];
  assert.throws(
    () => normalizeContract(input),
    /witnesses\[0\].kind must be one of/,
  );
});

// ─── Per-witness normalizers (all 7) ─────────────────────────────────────

test("normalizeContract accepts each of the 7 witness kinds", () => {
  for (const kind of WITNESS_KIND_VALUES) {
    const input = baseContractInput({ witnessKind: kind, contractId: `C-${kind}` });
    const contract = normalizeContract(input);
    assert.equal(contract.witnesses[0].kind, kind);
    assert.ok(contract.witnesses[0].predicate, `${kind} predicate must round-trip`);
  }
});

// ─── relational_value_match validator (Do step 2 + Do step 5) ────────────

test("relational_value_match refuses an extract_path with filter expression", () => {
  const predicateOverride = {
    left: { artifact_ref: "http_record:R7", extract_path: "$.body[?(@.sub == 'foo')].sub" },
    op: "eq",
    right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
  };
  let caught = null;
  try {
    normalizeContract(baseContractInput({
      witnessKind: "relational_value_match",
      predicateOverride,
    }));
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, "filter expressions must be refused");
  assert.equal(caught.code, "extract_path_unsafe");
  assert.equal(caught.details.field, "witnesses[0].predicate.left.extract_path");
  assert.match(caught.details.extract_path, /\?/);
});

test("relational_value_match refuses an extract_path with recursive descent", () => {
  const predicateOverride = {
    left: { artifact_ref: "http_record:R7", extract_path: "$..sub" },
    op: "eq",
    right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
  };
  assert.throws(
    () => normalizeContract(baseContractInput({
      witnessKind: "relational_value_match",
      predicateOverride,
    })),
    /extract_path_unsafe/,
  );
});

test("relational_value_match refuses an extract_path with shell metacharacters", () => {
  const predicateOverride = {
    left: { artifact_ref: "http_record:R7", extract_path: "$.body; rm -rf /" },
    op: "eq",
    right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
  };
  assert.throws(
    () => normalizeContract(baseContractInput({
      witnessKind: "relational_value_match",
      predicateOverride,
    })),
    /extract_path_unsafe/,
  );
});

test("relational_value_match accepts the closed JSONPath selector subset", () => {
  const safePaths = [
    "$.field",
    "$.field.nested",
    "$.array[0]",
    "$.array[*].field",
    "$.matrix[2].row[*]",
  ];
  for (const extractPath of safePaths) {
    const predicateOverride = {
      left: { artifact_ref: "http_record:R7", extract_path: extractPath },
      op: "eq",
      right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
    };
    const contract = normalizeContract(baseContractInput({
      witnessKind: "relational_value_match",
      predicateOverride,
    }));
    assert.equal(contract.witnesses[0].predicate.left.extract_path, extractPath);
  }
});

test("relational_value_match refuses an artifact_ref whose prefix is outside the X-D12 closed set", () => {
  const predicateOverride = {
    left: { artifact_ref: "secret_store:R7", extract_path: "$.sub" },
    op: "eq",
    right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
  };
  let caught = null;
  try {
    normalizeContract(baseContractInput({
      witnessKind: "relational_value_match",
      predicateOverride,
    }));
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, "must refuse unknown artifact_ref prefix");
  assert.equal(caught.code, "artifact_ref_unknown_prefix");
  assert.equal(caught.details.prefix, "secret_store");
  assert.deepEqual(caught.details.allowed_prefixes.slice().sort(), [
    "evidence_pack",
    "evm_call",
    "finding",
    "frontier_event",
    "http_record",
    "repo_check",
    "repo_command_run",
  ]);
});

test("relational_value_match refuses a malformed artifact_ref (missing ref_id)", () => {
  const predicateOverride = {
    left: { artifact_ref: "http_record:", extract_path: "$.sub" },
    op: "eq",
    right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
  };
  assert.throws(
    () => normalizeContract(baseContractInput({
      witnessKind: "relational_value_match",
      predicateOverride,
    })),
    /artifact_ref_malformed/,
  );
});

test("relational_value_match refuses an out-of-enum op", () => {
  const predicateOverride = {
    left: { artifact_ref: "http_record:R7", extract_path: "$.sub" },
    op: "matches_regex",
    right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
  };
  assert.throws(
    () => normalizeContract(baseContractInput({
      witnessKind: "relational_value_match",
      predicateOverride,
    })),
    /predicate\.op must be one of/,
  );
});

// ─── Satisfiability gate (Do step 3 + Do step 5) ─────────────────────────

test("assertContractSatisfiable accepts a Contract whose tools all live in the MCP registry", () => {
  const contract = normalizeContract(baseContractInput());
  assert.equal(assertContractSatisfiable(contract), true);
});

test("assertContractSatisfiable refuses a Contract referencing an unknown tool", () => {
  const input = baseContractInput();
  input.production_paths = [{
    description: "invoke a tool that doesn't exist",
    tool_call_pattern: [{ tool: "bob_definitely_not_a_real_tool" }],
  }];
  // Re-normalize so the witness still references the now-absent production
  // path's tool — tool_output_match witness references bob_http_scan which
  // remains real. We want the satisfiability gate to refuse on the
  // production_paths side, not the witness side.
  input.witnesses = [{
    id: "W1",
    kind: "file_exists",
    predicate: { path: "claims.jsonl" },
  }];
  const contract = normalizeContract(input);
  let caught = null;
  try {
    assertContractSatisfiable(contract);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, "must refuse unknown tool");
  assert.equal(caught.code, "contract_unsatisfiable");
  assert.equal(caught.reason, "tool_not_in_registry");
  assert.equal(caught.details.unknown_tools.length, 1);
  assert.equal(caught.details.unknown_tools[0].tool, "bob_definitely_not_a_real_tool");
});

test("assertContractSatisfiable refuses a Contract whose tools fall outside allowed_tools_for_node", () => {
  // The production_paths tool exists in the registry but is NOT in the
  // injected per-node pack. This is the X.5 retrofit path: when
  // derivePackForNode supplies allowed_tools_for_node, the gate enforces
  // pack membership in addition to registry membership.
  const input = baseContractInput();
  input.witnesses = [{
    id: "W1",
    kind: "file_exists",
    predicate: { path: "claims.jsonl" },
  }];
  const contract = normalizeContract(input);
  let caught = null;
  try {
    assertContractSatisfiable(contract, {
      allowed_tools_for_node: ["bob_evm_call", "bob_foundry_run"],
    });
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, "must refuse tool outside pack");
  assert.equal(caught.code, "contract_unsatisfiable");
  assert.equal(caught.reason, "tool_outside_pack");
  assert.equal(caught.details.tools_outside_pack.length, 1);
  assert.equal(caught.details.tools_outside_pack[0].tool, KNOWN_TOOL);
});

test("assertContractSatisfiable accepts when allowed_tools_for_node includes the referenced tool", () => {
  const contract = normalizeContract(baseContractInput());
  assert.equal(
    assertContractSatisfiable(contract, {
      allowed_tools_for_node: [KNOWN_TOOL, SECOND_KNOWN_TOOL],
    }),
    true,
  );
});

test("assertContractSatisfiable refuses a tool_output_match witness referencing a tool absent from production_paths", () => {
  // tool_output_match → predicate.tool must appear in production_paths so
  // the verifier never has to invent a tool invocation that wasn't part
  // of the declared production path.
  const input = baseContractInput();
  input.witnesses = [{
    id: "W1",
    kind: "tool_output_match",
    predicate: { tool: SECOND_KNOWN_TOOL, match: { path: "$.result" } },
  }];
  // production_paths only declares KNOWN_TOOL; the witness references
  // SECOND_KNOWN_TOOL → mismatch.
  const contract = normalizeContract(input);
  let caught = null;
  try {
    assertContractSatisfiable(contract);
  } catch (error) {
    caught = error;
  }
  assert.ok(caught, "must refuse tool_output_match referencing a tool absent from production_paths");
  assert.equal(caught.code, "contract_unsatisfiable");
  assert.equal(caught.reason, "tool_output_match_not_in_production_paths");
  assert.equal(caught.details.mismatches.length, 1);
  assert.equal(caught.details.mismatches[0].witness_id, "W1");
});

// ─── collectContractArtifactRefs (Do step 1 → X.5 dependency) ────────────

test("collectContractArtifactRefs surfaces relational_value_match + hash_equals artifact_refs", () => {
  const input = baseContractInput();
  input.witnesses = [
    {
      id: "W-rel",
      kind: "relational_value_match",
      predicate: {
        left: { artifact_ref: "http_record:R7", extract_path: "$.body.sub" },
        op: "eq",
        right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
      },
    },
    {
      id: "W-hash",
      kind: "hash_equals",
      predicate: {
        artifact_ref: "repo_check:RC-1",
        expected_hash: "deadbeefdeadbeefdeadbeefdeadbeef",
      },
    },
    {
      id: "W-file",
      kind: "file_exists",
      predicate: { path: "claims.jsonl" },
    },
  ];
  const contract = normalizeContract(input);
  const refs = collectContractArtifactRefs(contract);
  // Order: left, right of relational, then hash_equals. file_exists does
  // not surface an artifact_ref.
  assert.deepEqual(refs, ["http_record:R7", "evm_call:T9", "repo_check:RC-1"]);
});

test("artifactRefPrefix returns the canonical prefix or null for malformed refs", () => {
  assert.equal(artifactRefPrefix("http_record:R7"), "http_record");
  assert.equal(artifactRefPrefix("evm_call:tx:0xabc"), "evm_call");
  assert.equal(artifactRefPrefix("no_colon"), null);
  assert.equal(artifactRefPrefix(""), null);
  assert.equal(artifactRefPrefix(null), null);
});

// ─── appendContract: emits node.transitioned proposed → contracted ──────

function seedProposedHypothesis(domain) {
  // Hypothesis nodes enter the materialized graph in state "proposed"
  // straight away; no explicit node.transitioned event is required.
  // The materializer then folds the hypothesis_proposed observation into
  // a TG-H-<proposal_id> node.
  const proposalId = "HP-test-001";
  appendHypothesisProposal({
    target_domain: domain,
    ts: "2026-05-31T00:00:00.000Z",
    hypothesis_statement: "An attacker can replay JWTs against the EVM vault.",
    surface_refs: ["surface:auth-server"],
    proposal_id: proposalId,
  });
  // Materialize so the X.4 attach-contract tool's state lookup sees the
  // proposed node.
  materializeTaskGraph(domain, { write: true });
  return `${TASK_GRAPH_NODE_ID_PREFIX}H-${proposalId}`;
}

test("appendContract emits node.transitioned proposed → contracted with the contract_hash", () => {
  withTempHome(() => {
    const domain = "x4-append.example.com";
    const nodeId = seedProposedHypothesis(domain);

    const { event, contract } = appendContract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput(),
      ts: "2026-05-31T01:00:00.000Z",
    });

    assert.equal(event.kind, "node.transitioned");
    assert.equal(event.payload.node_id, nodeId);
    assert.equal(event.payload.from_state, "proposed");
    assert.equal(event.payload.to_state, "contracted");
    assert.equal(event.payload.contract_hash, contract.contract_hash);
    assert.match(contract.contract_hash, /^[0-9a-f]{64}$/);
  });
});

test("appendContract refuses to re-emit proposed → contracted when the node is already contracted", () => {
  withTempHome(() => {
    const domain = "x4-reattach.example.com";
    const nodeId = seedProposedHypothesis(domain);

    appendContract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput(),
    });

    // A second attach against the already-contracted node must refuse
    // because the live materialized state is now "contracted", not
    // "proposed". appendContract's live-state check fires before the
    // X.1 appendNodeTransition guard with a structured node_not_proposed
    // refusal so the operator sees a domain-specific error.
    let caught = null;
    try {
      appendContract({
        target_domain: domain,
        node_id: nodeId,
        contract: baseContractInput({ contractId: "C-2" }),
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "second appendContract must refuse");
    assert.equal(caught.code, "node_not_proposed");
    assert.equal(caught.details.current_state, "contracted");
    assert.deepEqual(
      caught.details.legal_from_states,
      ["proposed", "failed"],
      "structured error must surface the legal_from_states list",
    );
  });
});

// X.8 retry-with-recall: appendContract emits failed → contracted when
// the operator re-contracts a failed node. The prior failure events stay
// on the ledger so the X.8 prepare_node brief's `prior_attempt` slice can
// surface the structured failure payload.
test("appendContract emits failed → contracted when re-contracting a failed node (X.8 retry-with-recall)", () => {
  withTempHome(() => {
    const domain = "x4-recontract-failed.example.com";
    const nodeId = seedProposedHypothesis(domain);

    // Initial attach lands proposed → contracted.
    appendContract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput({ contractId: "C-initial" }),
    });
    // Walk through the full lifecycle to land at `failed` so the next
    // re-contract has a real prior failure to recall.
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "contracted",
      to_state: "ready",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "ready",
      to_state: "dispatched",
      prep_token_hash: "synthetic-prep-token-hash",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "dispatched",
      to_state: "executed",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "executed",
      to_state: "failed",
      failure_reason: {
        reason: "mechanical_verifier_failed",
        failures: [{ witness_id: "W1", reason: "tool_output_did_not_match" }],
      },
    });
    materializeTaskGraph(domain, { write: true });

    // The materializer surfaces state: failed.
    let doc = materializeTaskGraph(domain, { write: false }).document;
    let node = doc.nodes.find((n) => n.node_id === nodeId);
    assert.equal(node.state, "failed");

    // Re-contract with a refined Contract. The X.8 retry-with-recall
    // path emits failed → contracted; the result's from_state must match.
    const refined = baseContractInput({
      contractId: "C-refined",
      witnessKind: "tool_output_match",
      predicateOverride: { tool: KNOWN_TOOL, match: { path: "$.status", equals: 201 } },
    });
    const { event, contract, from_state } = appendContract({
      target_domain: domain,
      node_id: nodeId,
      contract: refined,
    });
    assert.equal(from_state, "failed");
    assert.equal(event.payload.from_state, "failed");
    assert.equal(event.payload.to_state, "contracted");
    assert.equal(event.payload.contract_hash, contract.contract_hash);

    // The prior failure event is still on the ledger.
    const transitions = readNodeTransitions(domain);
    const priorFailed = transitions.filter(
      (t) => t.payload && t.payload.node_id === nodeId && t.payload.to_state === "failed",
    );
    assert.equal(priorFailed.length, 1);
    assert.equal(priorFailed[0].payload.failure_reason.reason, "mechanical_verifier_failed");

    // The materialized node now reflects the refined contract_hash.
    materializeTaskGraph(domain, { write: true });
    doc = materializeTaskGraph(domain, { write: false }).document;
    node = doc.nodes.find((n) => n.node_id === nodeId);
    assert.equal(node.state, "contracted");
    assert.equal(node.contract_hash, contract.contract_hash);
  });
});

// The X.8 retry-with-recall path is the ONLY non-`proposed` entry to
// the legal from_states. All other non-proposed, non-failed states must
// refuse with the structured node_not_proposed error.
test("appendContract refuses to re-contract from states other than proposed or failed", () => {
  withTempHome(() => {
    const domain = "x4-recontract-other.example.com";
    const nodeId = seedProposedHypothesis(domain);

    // Land the node at `dispatched` (not in {proposed, failed}).
    appendContract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput({ contractId: "C-initial" }),
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "contracted",
      to_state: "ready",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "ready",
      to_state: "dispatched",
      prep_token_hash: "synthetic-prep-token-hash-other",
    });
    materializeTaskGraph(domain, { write: true });

    let caught = null;
    try {
      appendContract({
        target_domain: domain,
        node_id: nodeId,
        contract: baseContractInput({ contractId: "C-attempt-from-dispatched" }),
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "re-contract from dispatched must refuse");
    assert.equal(caught.code, "node_not_proposed");
    assert.equal(caught.details.current_state, "dispatched");
  });
});

// ─── bob_attach_contract tool roundtrip (Do step 3) ──────────────────────

test("bob_attach_contract attaches a Contract to a proposed Hypothesis node and surfaces contract_hash", () => {
  withTempHome(() => {
    const domain = "x4-tool.example.com";
    const nodeId = seedProposedHypothesis(domain);

    const result = JSON.parse(TOOL_HANDLERS.bob_attach_contract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput(),
    }));
    assert.equal(result.attached, true);
    assert.equal(result.target_domain, domain);
    assert.equal(result.node_id, nodeId);
    assert.equal(result.severity_floor, "high");
    assert.equal(result.from_state, "proposed");
    assert.equal(result.to_state, "contracted");
    assert.match(result.contract_hash, /^[0-9a-f]{64}$/);
    assert.match(result.event_id, /^FE-/);

    // The frontier ledger now carries exactly one node.transitioned event
    // for this node.
    const transitions = readNodeTransitions(domain);
    const forNode = transitions.filter((t) => t.payload && t.payload.node_id === nodeId);
    assert.equal(forNode.length, 1);
    assert.equal(forNode[0].payload.to_state, "contracted");
  });
});

test("bob_attach_contract refuses an unknown node_id with structured unknown_node error", () => {
  withTempHome(() => {
    const domain = "x4-unknown-node.example.com";
    let caught = null;
    try {
      TOOL_HANDLERS.bob_attach_contract({
        target_domain: domain,
        node_id: `${TASK_GRAPH_NODE_ID_PREFIX}does-not-exist`,
        contract: baseContractInput(),
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must refuse unknown node");
    assert.equal(caught.code, "unknown_node");
    assert.match(caught.message, /not present in the materialized task-graph/);
  });
});

test("bob_attach_contract refuses re-attach with structured node_not_proposed error", () => {
  withTempHome(() => {
    const domain = "x4-tool-reattach.example.com";
    const nodeId = seedProposedHypothesis(domain);

    TOOL_HANDLERS.bob_attach_contract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput(),
    });

    // After contracted, the second attach must refuse via the
    // tool-level node_not_proposed code (the lower-level
    // invalid_node_transition is still the underlying check but the
    // tool surface gives operators a clearer message).
    let caught = null;
    try {
      TOOL_HANDLERS.bob_attach_contract({
        target_domain: domain,
        node_id: nodeId,
        contract: baseContractInput({ contractId: "C-2" }),
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must refuse re-attach");
    assert.equal(caught.code, "node_not_proposed");
    assert.equal(caught.details.current_state, "contracted");
    assert.deepEqual(
      caught.details.legal_from_states,
      ["proposed", "failed"],
      "structured error surfaces the legal_from_states list",
    );
  });
});

// X.8 retry-with-recall via the bob_attach_contract tool surface: the
// operator re-contracts a failed node with a refined Contract and the
// tool's response surfaces from_state=failed so callers can detect the
// retry path explicitly.
test("bob_attach_contract accepts re-contracting a failed node and surfaces from_state=failed (X.8 retry-with-recall)", () => {
  withTempHome(() => {
    const domain = "x4-tool-recontract-failed.example.com";
    const nodeId = seedProposedHypothesis(domain);

    // Initial attach.
    TOOL_HANDLERS.bob_attach_contract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput({ contractId: "C-initial" }),
    });
    // Walk to failed.
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "contracted",
      to_state: "ready",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "ready",
      to_state: "dispatched",
      prep_token_hash: "synthetic-prep-token-hash-tool",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "dispatched",
      to_state: "executed",
    });
    appendNodeTransition({
      target_domain: domain,
      node_id: nodeId,
      from_state: "executed",
      to_state: "failed",
      failure_reason: { reason: "mechanical_verifier_failed" },
    });
    materializeTaskGraph(domain, { write: true });

    // Re-contract via the tool.
    const result = JSON.parse(TOOL_HANDLERS.bob_attach_contract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput({ contractId: "C-refined" }),
    }));
    assert.equal(result.attached, true);
    assert.equal(result.from_state, "failed");
    assert.equal(result.to_state, "contracted");
  });
});

test("bob_attach_contract refuses a Contract whose witness predicate uses an unsafe extract_path", () => {
  withTempHome(() => {
    const domain = "x4-unsafe-path.example.com";
    const nodeId = seedProposedHypothesis(domain);

    const unsafe = baseContractInput();
    unsafe.witnesses = [{
      id: "W-rel",
      kind: "relational_value_match",
      predicate: {
        left: { artifact_ref: "http_record:R7", extract_path: "$..sub" },
        op: "eq",
        right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
      },
    }];
    let caught = null;
    try {
      TOOL_HANDLERS.bob_attach_contract({
        target_domain: domain,
        node_id: nodeId,
        contract: unsafe,
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must refuse unsafe extract_path");
    assert.equal(caught.code, "extract_path_unsafe");
  });
});

test("bob_attach_contract refuses a Contract whose artifact_ref prefix is outside X-D12", () => {
  withTempHome(() => {
    const domain = "x4-bad-prefix.example.com";
    const nodeId = seedProposedHypothesis(domain);

    const bad = baseContractInput();
    bad.witnesses = [{
      id: "W-rel",
      kind: "relational_value_match",
      predicate: {
        left: { artifact_ref: "secret_store:S1", extract_path: "$.value" },
        op: "eq",
        right: { artifact_ref: "evm_call:T9", extract_path: "$.recovered_signer" },
      },
    }];
    let caught = null;
    try {
      TOOL_HANDLERS.bob_attach_contract({
        target_domain: domain,
        node_id: nodeId,
        contract: bad,
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must refuse unknown artifact_ref prefix");
    assert.equal(caught.code, "artifact_ref_unknown_prefix");
    assert.equal(caught.details.prefix, "secret_store");
  });
});

test("bob_attach_contract refuses a Contract whose production_path tool is unknown to the registry", () => {
  withTempHome(() => {
    const domain = "x4-unknown-tool.example.com";
    const nodeId = seedProposedHypothesis(domain);

    const unknown = baseContractInput();
    unknown.production_paths = [{
      description: "ghost tool path",
      tool_call_pattern: [{ tool: "bob_definitely_not_a_real_tool" }],
    }];
    unknown.witnesses = [{
      id: "W1",
      kind: "file_exists",
      predicate: { path: "claims.jsonl" },
    }];
    let caught = null;
    try {
      TOOL_HANDLERS.bob_attach_contract({
        target_domain: domain,
        node_id: nodeId,
        contract: unknown,
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "must refuse unknown tool");
    assert.equal(caught.code, "contract_unsatisfiable");
    assert.equal(caught.details.reason, "tool_not_in_registry");
  });
});

test("bob_attach_contract supports the optional allowed_tools_for_node argument (X.5 forward-compat)", () => {
  withTempHome(() => {
    const domain = "x4-allowed-pack.example.com";
    const nodeId = seedProposedHypothesis(domain);

    // Positive: pack includes the production-path tool.
    const positive = JSON.parse(TOOL_HANDLERS.bob_attach_contract({
      target_domain: domain,
      node_id: nodeId,
      contract: baseContractInput(),
      allowed_tools_for_node: [KNOWN_TOOL, SECOND_KNOWN_TOOL],
    }));
    assert.equal(positive.attached, true);
  });

  withTempHome(() => {
    const domain = "x4-allowed-pack-neg.example.com";
    const nodeId = seedProposedHypothesis(domain);

    // Negative: pack excludes the production-path tool → refused.
    let caught = null;
    try {
      TOOL_HANDLERS.bob_attach_contract({
        target_domain: domain,
        node_id: nodeId,
        contract: baseContractInput(),
        allowed_tools_for_node: [SECOND_KNOWN_TOOL],
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "tool outside pack must refuse");
    assert.equal(caught.code, "contract_unsatisfiable");
    assert.equal(caught.details.reason, "tool_outside_pack");
  });
});

// ─── Registered tool metadata ────────────────────────────────────────────

test("bob_attach_contract has role_bundles per X-D10 (orchestrator + evaluator-shared + chain after Y.11)", () => {
  const { TOOL_REGISTRY } = require("../mcp/lib/tool-registry.js");
  const tool = TOOL_REGISTRY.find((t) => t.name === "bob_attach_contract");
  assert.ok(tool, "bob_attach_contract must be registered");
  // Y.11 (rev 4.1 defect 3) widens role_bundles[] with `chain` so the
  // chain-builder can attach Contracts to chain-proposed Hypothesis
  // nodes via the graph apparatus. Y-P8 single-spawner topology
  // preserved via the Y.9 chain-bundle audit (the `// chain+evaluator-
  // shared justified:` header comment is asserted by
  // test/single-spawner-topology.test.js).
  assert.deepEqual(
    tool.role_bundles.slice().sort(),
    ["chain", "evaluator-shared", "orchestrator"],
  );
  assert.equal(tool.mutating, true);
  assert.equal(tool.network_access, false);
  assert.equal(tool.browser_access, false);
  // session_artifacts_written must surface frontier-events.jsonl (the
  // appendContract path is the only writer of node.transitioned events
  // emitted by this tool).
  assert.ok(tool.session_artifacts_written.includes("frontier-events.jsonl"));
});
