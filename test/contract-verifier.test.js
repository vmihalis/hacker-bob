"use strict";

// Plane X Cycle X.6 — mechanical Contract DSL verifier tests.
//
// Per Do step 5 the suite covers each of the 7 X-D4 witness kinds with
//   (positive case) + (negative case) + (malformed-predicate guard)
// for a total of 21 baseline tests. `relational_value_match` additionally
// gets the 3 cases from the spec: same-artifact extraction, cross-artifact
// eq holds, cross-artifact eq fails with full structured failure payload.
//
// Per Operator Discipline (Part VII): "X.6 Reviewer MUST confirm each of
// 7 witness kinds has positive + negative + malformed predicate test
// (≥21 tests); relational_value_match gets 3 additional cross-artifact
// extraction tests." The tests below tag each case with its
// witness-kind / class label so a Reviewer can grep them quickly.
//
// The malformed-predicate cases assert the X.4 attach-time
// normalizeContract refuses the predicate — the X.6 verifier never sees
// malformed predicates at runtime because X.4 stops them at the gate.
// This mirrors the layered-validation discipline: X.4 owns shape, X.6
// owns evaluation, and an X.6 test that simulates a malformed predicate
// reaching the verifier would mean X.4 has regressed.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const {
  mechanicalVerify,
  extractByJsonPath,
} = require("../mcp/lib/contract-verifier.js");
const {
  WITNESS_KIND_VALUES,
  normalizeContract,
} = require("../mcp/lib/contracts.js");
const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  sessionDir,
  trafficJsonlPath,
  claimsJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  appendJsonlLine,
} = require("../mcp/lib/storage.js");
const { TOOL_HANDLERS } = require("../mcp/lib/tool-registry.js");

// ─── Fixture helpers ─────────────────────────────────────────────────────

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-contract-verifier-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function ensureSessionDir(domain) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

const KNOWN_TOOL = "bob_http_scan";
assert.ok(
  Object.prototype.hasOwnProperty.call(TOOL_HANDLERS, KNOWN_TOOL),
  `${KNOWN_TOOL} must be registered for the verifier tests to round-trip with normalizeContract`,
);

// Build a single-witness Contract that round-trips through normalizeContract
// so the verifier sees the exact frozen shape it will see in production.
// Callers pass the witness kind + predicate; the rest of the Contract is
// fixed scaffolding (one invariant, one production_path).
function buildContractWith(witnessKind, predicate, { contractId = "C-test" } = {}) {
  return normalizeContract({
    contract_id: contractId,
    severity_floor: "medium",
    invariants: [{ id: "I1", statement: "verifier-test invariant" }],
    witnesses: [{ id: "W1", kind: witnessKind, predicate }],
    production_paths: [{
      description: "invoke the canonical web producer",
      tool_call_pattern: [{ tool: KNOWN_TOOL }],
    }],
  });
}

// Convenience for tests that need to assert "the witness landed in
// failures[] with the expected reason". Returns the matching failure or
// throws via assert when none is present.
function findFailure(verdict, witnessId) {
  const match = verdict.failures.find((f) => f.witness_id === witnessId);
  assert.ok(match, `expected verdict.failures[] to include witness ${witnessId}; got: ${JSON.stringify(verdict.failures, null, 2)}`);
  return match;
}

// ─── extractByJsonPath unit checks ───────────────────────────────────────
//
// The relational evaluator + tool_output_match evaluator depend on this
// helper. A small unit suite locks in the X.4 closed selector subset
// behavior so the relational evaluator tests below can rely on extraction
// semantics being stable.

test("extractByJsonPath returns nested object scalar", () => {
  assert.deepEqual(extractByJsonPath({ a: { b: 42 } }, "$.a.b"), [42]);
});

test("extractByJsonPath returns array element by integer index", () => {
  assert.deepEqual(extractByJsonPath({ a: [10, 20, 30] }, "$.a[1]"), [20]);
});

test("extractByJsonPath fans out wildcard", () => {
  const root = { items: [{ sub: "alice" }, { sub: "bob" }] };
  assert.deepEqual(extractByJsonPath(root, "$.items[*].sub"), ["alice", "bob"]);
});

test("extractByJsonPath returns empty array on missing key", () => {
  assert.deepEqual(extractByJsonPath({ a: 1 }, "$.b"), []);
});

test("extractByJsonPath refuses non-restricted path (returns empty)", () => {
  // ?(@.sub == 'foo') is outside the closed subset; the helper returns
  // empty rather than evaluating the filter so a Contract that was
  // edited out-of-band degrades to extract_yielded_no_value.
  assert.deepEqual(extractByJsonPath({}, "$.a[?(@.b == 1)]"), []);
});

// ─── tool_output_match: positive + negative + malformed ──────────────────

test("tool_output_match POSITIVE: invocation matches structured equals", () => {
  const contract = buildContractWith("tool_output_match", {
    tool: KNOWN_TOOL,
    match: { path: "$.status", equals: 200 },
  });
  const agentOutput = {
    tool_invocations: [
      { tool: KNOWN_TOOL, output: { status: 200, body: "ok" } },
    ],
  };
  const verdict = mechanicalVerify(contract, agentOutput, { target_domain: "example.com" });
  assert.equal(verdict.satisfied, true);
  assert.deepEqual(verdict.missing, []);
  assert.deepEqual(verdict.failures, []);
});

test("tool_output_match NEGATIVE: tool not invoked → missing", () => {
  const contract = buildContractWith("tool_output_match", {
    tool: KNOWN_TOOL,
    match: { path: "$.status", equals: 200 },
  });
  const agentOutput = { tool_invocations: [] };
  const verdict = mechanicalVerify(contract, agentOutput, { target_domain: "example.com" });
  assert.equal(verdict.satisfied, false);
  assert.deepEqual(verdict.missing, ["W1"]);
  const failure = findFailure(verdict, "W1");
  assert.equal(failure.reason, "tool_not_invoked");
  assert.equal(failure.tool, KNOWN_TOOL);
});

test("tool_output_match NEGATIVE: invocation present but value differs → failed", () => {
  const contract = buildContractWith("tool_output_match", {
    tool: KNOWN_TOOL,
    match: { path: "$.status", equals: 200 },
  });
  const agentOutput = {
    tool_invocations: [
      { tool: KNOWN_TOOL, output: { status: 500, body: "boom" } },
    ],
  };
  const verdict = mechanicalVerify(contract, agentOutput, { target_domain: "example.com" });
  assert.equal(verdict.satisfied, false);
  assert.deepEqual(verdict.missing, []);
  const failure = findFailure(verdict, "W1");
  assert.equal(failure.reason, "tool_output_did_not_match");
  assert.equal(failure.tool, KNOWN_TOOL);
  assert.deepEqual(failure.expected, { path: "$.status", equals: 200 });
});

test("tool_output_match MALFORMED: refused at attach-time (normalizeContract)", () => {
  // match must be an object — a string is refused by the X.4 predicate
  // normalizer so the verifier never sees a malformed predicate.
  assert.throws(
    () => buildContractWith("tool_output_match", { tool: KNOWN_TOOL, match: "not-an-object" }),
    /predicate\.match must be an object/,
  );
});

// ─── file_exists: positive + negative + malformed ────────────────────────

test("file_exists POSITIVE: under-session file present", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    fs.writeFileSync(path.join(sessionDir(domain), "claims.jsonl"), "");
    const contract = buildContractWith("file_exists", {
      path: "claims.jsonl",
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, true);
  });
});

test("file_exists NEGATIVE: under-session file missing → missing", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    const contract = buildContractWith("file_exists", {
      path: "claims.jsonl",
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, false);
    assert.deepEqual(verdict.missing, ["W1"]);
    const failure = findFailure(verdict, "W1");
    assert.equal(failure.reason, "file_not_found");
    assert.equal(failure.path, "claims.jsonl");
  });
});

test("file_exists MALFORMED: empty path refused at attach", () => {
  assert.throws(
    () => buildContractWith("file_exists", { path: "" }),
    /predicate\.path/,
  );
});

// ─── hash_equals: positive + negative + malformed ────────────────────────

test("hash_equals POSITIVE: resolver content_hash matches expected", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    // Write a frontier event whose resolver round-trip produces a known body.
    const event = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: { observation_kind: "test_obs", note: "hash-test" },
    });
    // Derive the expected content_hash the resolver will produce.
    const expectedBody = JSON.stringify(event, null, 2);
    // The frontier-event resolver re-reads the event row and pretty-prints
    // it; that round-trip is deterministic for the just-written event.
    const expectedHash = sha256Hex(expectedBody);

    const contract = buildContractWith("hash_equals", {
      artifact_ref: `frontier_event:${event.event_id}`,
      expected_hash: expectedHash,
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, true, `verdict failures: ${JSON.stringify(verdict.failures)}`);
  });
});

test("hash_equals NEGATIVE: content_hash differs → failed", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    const event = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: { observation_kind: "test_obs" },
    });
    // Use a deliberately wrong hash.
    const wrongHash = "0".repeat(64);
    const contract = buildContractWith("hash_equals", {
      artifact_ref: `frontier_event:${event.event_id}`,
      expected_hash: wrongHash,
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, false);
    const failure = findFailure(verdict, "W1");
    assert.equal(failure.reason, "hash_did_not_match");
    assert.equal(failure.expected_hash, wrongHash);
    assert.ok(failure.observed_hash);
  });
});

test("hash_equals NEGATIVE: missing artifact → missing", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    const contract = buildContractWith("hash_equals", {
      artifact_ref: "frontier_event:FE-does-not-exist",
      expected_hash: "0".repeat(64),
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, false);
    assert.deepEqual(verdict.missing, ["W1"]);
    const failure = findFailure(verdict, "W1");
    assert.equal(failure.reason, "missing_artifact");
    assert.equal(failure.artifact_ref, "frontier_event:FE-does-not-exist");
  });
});

test("hash_equals MALFORMED: non-hex expected_hash refused at attach", () => {
  assert.throws(
    () => buildContractWith("hash_equals", {
      artifact_ref: "frontier_event:FE-x",
      expected_hash: "not-hex-value!!",
    }),
    /expected_hash must be a lowercase hex digest/,
  );
});

// ─── evidence_ref_kind_present: positive + negative + malformed ──────────

test("evidence_ref_kind_present POSITIVE: matching kind found in agent_output", () => {
  const contract = buildContractWith("evidence_ref_kind_present", {
    kind: "repo_file",
  });
  const agentOutput = {
    evidence_refs: [
      { kind: "repo_file", file_path: "auth.js", content_hash: "a".repeat(64) },
    ],
  };
  const verdict = mechanicalVerify(contract, agentOutput, { target_domain: "example.com" });
  assert.equal(verdict.satisfied, true);
});

test("evidence_ref_kind_present NEGATIVE: kind not present → missing", () => {
  const contract = buildContractWith("evidence_ref_kind_present", {
    kind: "smart_contract_evidence",
  });
  const agentOutput = {
    evidence_refs: [
      { kind: "repo_file", file_path: "auth.js" },
    ],
  };
  const verdict = mechanicalVerify(contract, agentOutput, { target_domain: "example.com" });
  assert.equal(verdict.satisfied, false);
  assert.deepEqual(verdict.missing, ["W1"]);
  const failure = findFailure(verdict, "W1");
  assert.equal(failure.reason, "evidence_ref_kind_not_present");
  assert.equal(failure.expected_kind, "smart_contract_evidence");
  assert.deepEqual(failure.observed_kinds, ["repo_file"]);
});

test("evidence_ref_kind_present MALFORMED: empty kind refused at attach", () => {
  assert.throws(
    () => buildContractWith("evidence_ref_kind_present", { kind: "" }),
    /predicate\.kind/,
  );
});

// ─── frontier_event_emitted: positive + negative + malformed ─────────────

test("frontier_event_emitted POSITIVE: matching event on disk satisfies witness", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      payload: { observation_kind: "http_record_observed", request_id: "R-test" },
    });
    const contract = buildContractWith("frontier_event_emitted", {
      kind: "observation.recorded",
      payload_kind: "http_record_observed",
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, true, JSON.stringify(verdict.failures));
  });
});

test("frontier_event_emitted NEGATIVE: no matching event → missing", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    const contract = buildContractWith("frontier_event_emitted", {
      kind: "observation.recorded",
      payload_kind: "http_record_observed",
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, false);
    assert.deepEqual(verdict.missing, ["W1"]);
    const failure = findFailure(verdict, "W1");
    assert.equal(failure.reason, "frontier_event_not_emitted");
    assert.equal(failure.requested_kind, "observation.recorded");
    assert.equal(failure.requested_payload_kind, "http_record_observed");
  });
});

test("frontier_event_emitted MALFORMED: unknown top-level kind refused at attach", () => {
  assert.throws(
    () => buildContractWith("frontier_event_emitted", { kind: "totally.fake.kind" }),
    /is not in FRONTIER_EVENT_KINDS/,
  );
});

// ─── cli_pack_invoked: positive + negative + malformed ───────────────────

test("cli_pack_invoked POSITIVE: pack id present in cli_pack_invocations[]", () => {
  const contract = buildContractWith("cli_pack_invoked", {
    cli_pack: "web_auth_probes",
  });
  const agentOutput = {
    cli_pack_invocations: ["web_auth_probes"],
  };
  const verdict = mechanicalVerify(contract, agentOutput, { target_domain: "example.com" });
  assert.equal(verdict.satisfied, true);
});

test("cli_pack_invoked POSITIVE: pack id surfaced via tool_invocation.cli_pack tag", () => {
  const contract = buildContractWith("cli_pack_invoked", {
    cli_pack: "sqlmap",
  });
  const agentOutput = {
    tool_invocations: [
      { tool: "Bash", cli_pack: "sqlmap", output: {} },
    ],
  };
  const verdict = mechanicalVerify(contract, agentOutput, { target_domain: "example.com" });
  assert.equal(verdict.satisfied, true);
});

test("cli_pack_invoked NEGATIVE: pack id not invoked → missing", () => {
  const contract = buildContractWith("cli_pack_invoked", {
    cli_pack: "web_auth_probes",
  });
  const agentOutput = { cli_pack_invocations: ["other_pack"] };
  const verdict = mechanicalVerify(contract, agentOutput, { target_domain: "example.com" });
  assert.equal(verdict.satisfied, false);
  assert.deepEqual(verdict.missing, ["W1"]);
  const failure = findFailure(verdict, "W1");
  assert.equal(failure.reason, "cli_pack_not_invoked");
  assert.equal(failure.expected_cli_pack, "web_auth_probes");
  assert.deepEqual(failure.observed_cli_packs, ["other_pack"]);
});

test("cli_pack_invoked MALFORMED: empty cli_pack refused at attach", () => {
  assert.throws(
    () => buildContractWith("cli_pack_invoked", { cli_pack: "" }),
    /predicate\.cli_pack/,
  );
});

// ─── relational_value_match: positive + negative + malformed +
//      same-artifact + cross-artifact-eq holds + cross-artifact-eq fails
//      (Do step 5 says 3 ADDITIONAL beyond the baseline) ──────────────────

function writeFrontierEventWithBody(domain, payload) {
  const event = appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    payload,
  });
  return event;
}

test("relational_value_match POSITIVE: cross-artifact eq holds (Nike-shaped invariant)", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    // Left: a frontier event whose payload carries the off-chain identity
    // claim subject. Field names avoid the sensitive_material regex (no
    // `token`/`jwt`/`auth` parts) — the X.6 verifier addresses arbitrary
    // on-disk payload SHAPES, so we pick neutral names that round-trip
    // through appendFrontierEvent.
    const left = writeFrontierEventWithBody(domain, {
      observation_kind: "identity_claim_observed",
      response: { body: { identity_subject: "0xWALLET" } },
    });
    // Right: a frontier event with recovered_signer == "0xWALLET"
    const right = writeFrontierEventWithBody(domain, {
      observation_kind: "evm_recover_signer",
      recovered_signer: "0xWALLET",
    });
    const contract = buildContractWith("relational_value_match", {
      left: {
        artifact_ref: `frontier_event:${left.event_id}`,
        extract_path: "$.payload.response.body.identity_subject",
      },
      op: "eq",
      right: {
        artifact_ref: `frontier_event:${right.event_id}`,
        extract_path: "$.payload.recovered_signer",
      },
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, true, JSON.stringify(verdict.failures));
  });
});

test("relational_value_match NEGATIVE: cross-artifact eq fails with full structured payload (Nike-fix verifier)", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    // Left: identity subject == "0xATTACKER"
    const left = writeFrontierEventWithBody(domain, {
      observation_kind: "identity_claim_observed",
      response: { body: { identity_subject: "0xATTACKER" } },
    });
    // Right: recovered_signer == "0xVICTIM"
    const right = writeFrontierEventWithBody(domain, {
      observation_kind: "evm_recover_signer",
      recovered_signer: "0xVICTIM",
    });
    const contract = buildContractWith("relational_value_match", {
      left: {
        artifact_ref: `frontier_event:${left.event_id}`,
        extract_path: "$.payload.response.body.identity_subject",
      },
      op: "eq",
      right: {
        artifact_ref: `frontier_event:${right.event_id}`,
        extract_path: "$.payload.recovered_signer",
      },
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, false);
    assert.deepEqual(verdict.missing, []);
    const failure = findFailure(verdict, "W1");
    // The full structured failure payload per Do step 3:
    assert.equal(failure.reason, "relation_did_not_hold");
    assert.equal(failure.left_artifact_ref, `frontier_event:${left.event_id}`);
    assert.equal(failure.right_artifact_ref, `frontier_event:${right.event_id}`);
    assert.equal(failure.left_value, "0xATTACKER");
    assert.equal(failure.right_value, "0xVICTIM");
    assert.equal(failure.op, "eq");
    assert.equal(failure.left_extract_path, "$.payload.response.body.identity_subject");
    assert.equal(failure.right_extract_path, "$.payload.recovered_signer");
  });
});

test("relational_value_match SAME-ARTIFACT: extracting two values from one body holds when equal", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    // One event carrying two fields with the same value.
    const event = writeFrontierEventWithBody(domain, {
      observation_kind: "same_artifact_test",
      header_value: "0xABCDEF",
      body_value: "0xABCDEF",
    });
    const ref = `frontier_event:${event.event_id}`;
    const contract = buildContractWith("relational_value_match", {
      left: { artifact_ref: ref, extract_path: "$.payload.header_value" },
      op: "eq",
      right: { artifact_ref: ref, extract_path: "$.payload.body_value" },
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, true, JSON.stringify(verdict.failures));
  });
});

test("relational_value_match NEGATIVE: missing artifact → missing", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    const right = writeFrontierEventWithBody(domain, {
      observation_kind: "ok",
      v: "x",
    });
    const contract = buildContractWith("relational_value_match", {
      left: { artifact_ref: "frontier_event:FE-not-real", extract_path: "$.payload.v" },
      op: "eq",
      right: { artifact_ref: `frontier_event:${right.event_id}`, extract_path: "$.payload.v" },
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, false);
    assert.deepEqual(verdict.missing, ["W1"]);
    const failure = findFailure(verdict, "W1");
    assert.equal(failure.reason, "missing_artifact");
    assert.equal(failure.left_present, false);
    assert.equal(failure.right_present, true);
  });
});

test("relational_value_match NEGATIVE: extract yields no value → extract_yielded_no_value", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    const left = writeFrontierEventWithBody(domain, {
      observation_kind: "missing_field_test",
      // No `target_field` key — left extract will yield nothing.
      other_field: "x",
    });
    const right = writeFrontierEventWithBody(domain, {
      observation_kind: "ok",
      target_field: "y",
    });
    const contract = buildContractWith("relational_value_match", {
      left: { artifact_ref: `frontier_event:${left.event_id}`, extract_path: "$.payload.target_field" },
      op: "eq",
      right: { artifact_ref: `frontier_event:${right.event_id}`, extract_path: "$.payload.target_field" },
    });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.equal(verdict.satisfied, false);
    const failure = findFailure(verdict, "W1");
    assert.equal(failure.reason, "extract_yielded_no_value");
    assert.equal(failure.left_yielded_count, 0);
    assert.equal(failure.right_yielded_count, 1);
  });
});

test("relational_value_match MALFORMED extract_path: refused at attach", () => {
  assert.throws(
    () => buildContractWith("relational_value_match", {
      left: { artifact_ref: "frontier_event:FE-a", extract_path: "$.body[?(@.sub == 'x')].sub" },
      op: "eq",
      right: { artifact_ref: "frontier_event:FE-b", extract_path: "$.sub" },
    }),
    /extract_path_unsafe/,
  );
});

test("relational_value_match MALFORMED artifact_ref prefix: refused at attach", () => {
  assert.throws(
    () => buildContractWith("relational_value_match", {
      left: { artifact_ref: "totally_made_up_prefix:R1", extract_path: "$.sub" },
      op: "eq",
      right: { artifact_ref: "frontier_event:FE-b", extract_path: "$.sub" },
    }),
    /artifact_ref_unknown_prefix/,
  );
});

// ─── Top-level verdict shape locks ───────────────────────────────────────

test("mechanicalVerify returns satisfied=true + empty missing/failures on every-witness pass", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    fs.writeFileSync(path.join(sessionDir(domain), "ok.txt"), "");
    const contract = buildContractWith("file_exists", { path: "ok.txt" });
    const verdict = mechanicalVerify(contract, {}, { target_domain: domain });
    assert.deepEqual(verdict, { satisfied: true, missing: [], failures: [] });
  });
});

test("mechanicalVerify accumulates multiple witness failures distinctly", () => {
  withTempHome(() => {
    const domain = "example.com";
    ensureSessionDir(domain);
    // Two witnesses, both will fail (one missing, one failed).
    const contract = normalizeContract({
      contract_id: "C-multi",
      severity_floor: "high",
      invariants: [{ id: "I1", statement: "multi-witness invariant" }],
      witnesses: [
        {
          id: "W-missing",
          kind: "file_exists",
          predicate: { path: "absent.txt" },
        },
        {
          id: "W-failed",
          kind: "tool_output_match",
          predicate: { tool: KNOWN_TOOL, match: { path: "$.status", equals: 200 } },
        },
      ],
      production_paths: [{
        description: "multi-witness production",
        tool_call_pattern: [{ tool: KNOWN_TOOL }],
      }],
    });
    const agentOutput = {
      tool_invocations: [{ tool: KNOWN_TOOL, output: { status: 500 } }],
    };
    const verdict = mechanicalVerify(contract, agentOutput, { target_domain: domain });
    assert.equal(verdict.satisfied, false);
    assert.deepEqual(verdict.missing, ["W-missing"]);
    assert.equal(verdict.failures.length, 2);
    const ids = verdict.failures.map((f) => f.witness_id).sort();
    assert.deepEqual(ids, ["W-failed", "W-missing"]);
  });
});

// ─── 7-evaluator coverage assertion (Reviewer-grep target) ───────────────

test("EVALUATORS table covers every X-D4 witness kind", () => {
  const { EVALUATORS } = require("../mcp/lib/contract-verifier.js");
  for (const kind of WITNESS_KIND_VALUES) {
    assert.equal(typeof EVALUATORS[kind], "function", `evaluator for ${kind} missing`);
  }
  assert.equal(Object.keys(EVALUATORS).length, WITNESS_KIND_VALUES.length);
});
