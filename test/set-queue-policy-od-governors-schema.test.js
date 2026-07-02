"use strict";

// OD governor reachability through the bob_set_queue_policy TOOL boundary. The
// normalizer (normalizeQueuePolicy) and the read-modify-write merge
// (mergeInitOwnedPolicyFields) already handle the OD4 linked_contract_depth and
// the OD1 seed caps, but the tool inputSchema declared none of them and
// additionalProperties defaults false, so the real dispatch boundary
// (validateAgainstSchema) rejected `policy.linked_contract_depth is not allowed`.
// That made the operator-update branch dead code from the tool front door. The
// schema now declares the four fields with the AUTHORITATIVE normalizeQueuePolicy
// bounds, so an in-bounds override is accepted and enforced, and an out-of-bounds
// value fails closed at the schema boundary AND again in the normalizer.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const setQueuePolicy = require("../mcp/lib/tools/set-queue-policy.js");
const { validateAgainstSchema } = require("../mcp/lib/tool-validation.js");
const { CLAMP_CEILING, loadQueuePolicy } = require("../mcp/lib/queue-policy.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-od-gov-schema-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

const POLICY_PROPS = setQueuePolicy.inputSchema.properties.policy.properties;

test("the bob_set_queue_policy inputSchema declares the OD governors with the authoritative normalizeQueuePolicy bounds", () => {
  assert.deepEqual(POLICY_PROPS.linked_contract_depth, { type: "integer", minimum: 0, maximum: 32 });
  assert.deepEqual(POLICY_PROPS.seed_producer_per_pass_cap, { type: "integer", minimum: 1, maximum: CLAMP_CEILING });
  assert.deepEqual(POLICY_PROPS.per_expander_linked_address_cap, { type: "integer", minimum: 1, maximum: CLAMP_CEILING });
  assert.deepEqual(POLICY_PROPS.max_total_seed_producers, { type: "integer", minimum: 1, maximum: CLAMP_CEILING });
});

test("bob_set_queue_policy accepts the OD governors through the schema boundary and enforces the override (operator-update path now live)", () => withTempHome(() => {
  const domain = "od-gov.example.test";
  const args = {
    target_domain: domain,
    policy: { linked_contract_depth: 5, seed_producer_per_pass_cap: 20 },
  };
  // Prior state: these keys were rejected here (`policy.<x> is not allowed`,
  // additionalProperties default false). They are now declared, so the real tool
  // boundary accepts them.
  assert.doesNotThrow(() => validateAgainstSchema(args, setQueuePolicy.inputSchema, []));

  const persisted = JSON.parse(setQueuePolicy.handler(args)).queue_policy;
  assert.equal(persisted.linked_contract_depth, 5, "the enforced OD4 depth reflects the operator override");
  assert.equal(persisted.seed_producer_per_pass_cap, 20, "the enforced OD1 per-pass seed cap reflects the operator override");
  // The enforced (loadQueuePolicy) value on disk matches — this is the real setter.
  assert.equal(loadQueuePolicy(domain).linked_contract_depth, 5);
  assert.equal(loadQueuePolicy(domain).seed_producer_per_pass_cap, 20);
}));

test("the mergeInitOwnedPolicyFields branch is live from the tool front door: a later PARTIAL update omitting the OD governors preserves the operator override", () => withTempHome(() => {
  const domain = "od-gov-merge.example.test";
  // Set the OD4 depth through the tool (the branch that was unreachable behind the
  // schema gate).
  const first = { target_domain: domain, policy: { linked_contract_depth: 5 } };
  assert.doesNotThrow(() => validateAgainstSchema(first, setQueuePolicy.inputSchema, []));
  assert.equal(JSON.parse(setQueuePolicy.handler(first)).queue_policy.linked_contract_depth, 5);

  // A subsequent PARTIAL update on an unrelated field omits linked_contract_depth;
  // mergeInitOwnedPolicyFields read-modify-writes it against the persisted policy,
  // so the operator's 5 survives instead of resetting to the default 3.
  const second = { target_domain: domain, policy: { close_blocked_on_freeze: true } };
  assert.doesNotThrow(() => validateAgainstSchema(second, setQueuePolicy.inputSchema, []));
  const out = JSON.parse(setQueuePolicy.handler(second)).queue_policy;
  assert.equal(out.linked_contract_depth, 5, "the omitted OD4 governor is preserved, not reset to 3");
  assert.equal(out.close_blocked_on_freeze, true, "the partial field still applied");
  assert.equal(loadQueuePolicy(domain).linked_contract_depth, 5);
}));

test("depth 0 (no recursion) is a valid OD4 override at the boundary", () => withTempHome(() => {
  const domain = "od-gov-zero.example.test";
  const args = { target_domain: domain, policy: { linked_contract_depth: 0 } };
  assert.doesNotThrow(() => validateAgainstSchema(args, setQueuePolicy.inputSchema, []));
  assert.equal(JSON.parse(setQueuePolicy.handler(args)).queue_policy.linked_contract_depth, 0);
}));

test("an out-of-bounds OD governor fails closed at the schema boundary AND in the normalizer", () => withTempHome(() => {
  const domain = "od-gov-bad.example.test";
  // linked_contract_depth above its max (32): rejected at the schema boundary...
  assert.throws(
    () => validateAgainstSchema(
      { target_domain: domain, policy: { linked_contract_depth: 40 } },
      setQueuePolicy.inputSchema, [],
    ),
    /linked_contract_depth must be <= 32/,
  );
  // ...and again by the handler's eager normalizeQueuePolicy (defense in depth).
  assert.throws(
    () => setQueuePolicy.handler({ target_domain: domain, policy: { linked_contract_depth: 40 } }),
    /linked_contract_depth must be <= 32/,
  );

  // A negative depth is below the min 0.
  assert.throws(
    () => validateAgainstSchema(
      { target_domain: domain, policy: { linked_contract_depth: -1 } },
      setQueuePolicy.inputSchema, [],
    ),
    /linked_contract_depth must be >= 0/,
  );

  // A seed cap of 0 is below the positive-integer min 1.
  assert.throws(
    () => validateAgainstSchema(
      { target_domain: domain, policy: { seed_producer_per_pass_cap: 0 } },
      setQueuePolicy.inputSchema, [],
    ),
    /seed_producer_per_pass_cap must be >= 1/,
  );
  // A seed cap above CLAMP_CEILING is rejected at both boundaries.
  assert.throws(
    () => validateAgainstSchema(
      { target_domain: domain, policy: { max_total_seed_producers: CLAMP_CEILING + 1 } },
      setQueuePolicy.inputSchema, [],
    ),
    new RegExp(`max_total_seed_producers must be <= ${CLAMP_CEILING}`),
  );
  assert.throws(
    () => setQueuePolicy.handler({ target_domain: domain, policy: { max_total_seed_producers: CLAMP_CEILING + 1 } }),
    new RegExp(`max_total_seed_producers must be <= ${CLAMP_CEILING}`),
  );
}));
