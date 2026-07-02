"use strict";

// OD governor reachability through the bob_set_queue_policy TOOL boundary. The
// normalizer (normalizeQueuePolicy) and the read-modify-write merge
// (mergePersistedPolicyFields) already handle the OD4 linked_contract_depth and
// the OD1 seed caps, but the tool inputSchema declared none of them and
// additionalProperties defaults false, so the real dispatch boundary
// (validateAgainstSchema) rejected `policy.linked_contract_depth is not allowed`.
// That made the operator-update branch dead code from the tool front door. The
// schema now declares the four fields with the AUTHORITATIVE normalizeQueuePolicy
// bounds, so an in-bounds override is accepted and enforced, and an out-of-bounds
// value fails closed at the schema boundary AND again in the normalizer.
//
// bob_set_queue_policy is a PARTIAL (PATCH) update: mergePersistedPolicyFields
// read-modify-writes the WHOLE persisted policy, so a one-field update preserves
// every OTHER field (the OD governors AND general fields like max_parallel_tasks /
// priority_order) instead of resetting them to DEFAULT_QUEUE_POLICY.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const setQueuePolicy = require("../mcp/lib/tools/set-queue-policy.js");
const { validateAgainstSchema } = require("../mcp/lib/tool-validation.js");
const { CLAMP_CEILING, LEAN_PROFILE, loadQueuePolicy } = require("../mcp/lib/queue-policy.js");

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

test("the partial-update merge is live from the tool front door: a later PARTIAL update omitting the OD governors preserves the operator override", () => withTempHome(() => {
  const domain = "od-gov-merge.example.test";
  // Set the OD4 depth through the tool (the branch that was unreachable behind the
  // schema gate).
  const first = { target_domain: domain, policy: { linked_contract_depth: 5 } };
  assert.doesNotThrow(() => validateAgainstSchema(first, setQueuePolicy.inputSchema, []));
  assert.equal(JSON.parse(setQueuePolicy.handler(first)).queue_policy.linked_contract_depth, 5);

  // A subsequent PARTIAL update on an unrelated field omits linked_contract_depth;
  // mergePersistedPolicyFields read-modify-writes it against the persisted policy,
  // so the operator's 5 survives instead of resetting to the default 3.
  const second = { target_domain: domain, policy: { close_blocked_on_freeze: true } };
  assert.doesNotThrow(() => validateAgainstSchema(second, setQueuePolicy.inputSchema, []));
  const out = JSON.parse(setQueuePolicy.handler(second)).queue_policy;
  assert.equal(out.linked_contract_depth, 5, "the omitted OD4 governor is preserved, not reset to 3");
  assert.equal(out.close_blocked_on_freeze, true, "the partial field still applied");
  assert.equal(loadQueuePolicy(domain).linked_contract_depth, 5);
}));

test("a PARTIAL update preserves previously-persisted GENERAL fields: a custom max_parallel_tasks / priority_order survives a later linked_contract_depth-only update", () => withTempHome(() => {
  const domain = "patch-general.example.test";
  // First: persist a non-default max_parallel_tasks + priority_order through the tool.
  const customPriority = ["high", "critical", "low", "medium"];
  const first = {
    target_domain: domain,
    policy: { max_parallel_tasks: 7, priority_order: customPriority },
  };
  assert.doesNotThrow(() => validateAgainstSchema(first, setQueuePolicy.inputSchema, []));
  const firstOut = JSON.parse(setQueuePolicy.handler(first)).queue_policy;
  assert.equal(firstOut.max_parallel_tasks, 7, "the custom max_parallel_tasks persisted");
  assert.deepEqual(firstOut.priority_order, customPriority, "the custom priority_order persisted");

  // Then: a partial update touching ONLY linked_contract_depth. Under the old
  // full-overwrite semantics this reset max_parallel_tasks back to the default 128
  // and priority_order back to the default order — silent config loss. The PATCH
  // merge keeps both persisted values.
  const second = { target_domain: domain, policy: { linked_contract_depth: 6 } };
  assert.doesNotThrow(() => validateAgainstSchema(second, setQueuePolicy.inputSchema, []));
  const out = JSON.parse(setQueuePolicy.handler(second)).queue_policy;
  assert.equal(out.linked_contract_depth, 6, "the one updated field applied");
  assert.equal(out.max_parallel_tasks, 7, "the previously-persisted max_parallel_tasks is preserved, not reset to 128");
  assert.deepEqual(out.priority_order, customPriority, "the previously-persisted priority_order is preserved, not reset to default");

  // And the on-disk (loadQueuePolicy) state matches — this is the real setter.
  const onDisk = loadQueuePolicy(domain);
  assert.equal(onDisk.max_parallel_tasks, 7);
  assert.deepEqual(onDisk.priority_order, customPriority);
  assert.equal(onDisk.linked_contract_depth, 6);
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

// PATCH regression: the eager pre-lock validation must run on the MERGED policy, not
// the raw partial. Validating the raw partial fills omitted cross-guard partners with
// DEFAULTS (standard/deep wave targets/maxes 64/128) before the cross-field wave
// guards (wave_max >= wave_target) run, so a legitimate one-field wave-cap update
// against a persisted partner that diverges from the default was falsely rejected.
test("a one-field wave-cap PATCH against a persisted LEAN_PROFILE partner is accepted, not falsely rejected by a default cross-guard partner", () => withTempHome(() => {
  const domain = "wave-patch.example.test";
  // Persist LEAN_PROFILE: standard_wave_target=4, standard_wave_max=6,
  // deep_wave_target=6, deep_wave_max=8.
  const lean = { target_domain: domain, policy: { ...LEAN_PROFILE } };
  assert.doesNotThrow(() => validateAgainstSchema(lean, setQueuePolicy.inputSchema, []));
  const leanOut = JSON.parse(setQueuePolicy.handler(lean)).queue_policy;
  assert.equal(leanOut.standard_wave_target, 4);
  assert.equal(leanOut.standard_wave_max, 6);
  assert.equal(leanOut.deep_wave_target, 6);
  assert.equal(leanOut.deep_wave_max, 8);

  // A legit lower standard_wave_max that still clears the PERSISTED target (4). The
  // old raw-partial pre-check filled standard_wave_target=64 and threw; the merged
  // policy {std_t:4, std_m:5} is valid.
  const lower = { target_domain: domain, policy: { standard_wave_max: 5 } };
  assert.doesNotThrow(() => validateAgainstSchema(lower, setQueuePolicy.inputSchema, []));
  let out;
  assert.doesNotThrow(() => { out = JSON.parse(setQueuePolicy.handler(lower)).queue_policy; });
  assert.equal(out.standard_wave_max, 5, "the one wave-cap field applied");
  assert.equal(out.standard_wave_target, 4, "the persisted cross-guard partner survived the PATCH");
  assert.equal(loadQueuePolicy(domain).standard_wave_max, 5);

  // Idempotent re-affirm of the persisted value must not throw either.
  const reaffirm = { target_domain: domain, policy: { standard_wave_max: 5 } };
  assert.doesNotThrow(() => setQueuePolicy.handler(reaffirm));

  // The deep-wave pair behaves identically: `{deep_wave_max: 7}` clears the persisted
  // deep_wave_target (6) even though the raw-partial default (64) would have tripped.
  const deep = { target_domain: domain, policy: { deep_wave_max: 7 } };
  assert.doesNotThrow(() => validateAgainstSchema(deep, setQueuePolicy.inputSchema, []));
  let deepOut;
  assert.doesNotThrow(() => { deepOut = JSON.parse(setQueuePolicy.handler(deep)).queue_policy; });
  assert.equal(deepOut.deep_wave_max, 7);
  assert.equal(deepOut.deep_wave_target, 6, "the persisted deep cross-guard partner survived");
}));

test("the mirror case: a raised standard_wave_target PATCH against a persisted-above-default standard_wave_max is accepted", () => withTempHome(() => {
  const domain = "wave-patch-mirror.example.test";
  // Persist standard_wave_max=300 (> the 128 default). Merged over the default this
  // is {std_t:64, std_m:300} — valid.
  const wide = { target_domain: domain, policy: { standard_wave_max: 300 } };
  assert.doesNotThrow(() => validateAgainstSchema(wide, setQueuePolicy.inputSchema, []));
  assert.equal(JSON.parse(setQueuePolicy.handler(wide)).queue_policy.standard_wave_max, 300);

  // Raise standard_wave_target to 200. The raw-partial pre-check filled
  // standard_wave_max=128 (< 200) and threw; the merged policy {std_t:200, std_m:300}
  // is valid.
  const raise = { target_domain: domain, policy: { standard_wave_target: 200 } };
  assert.doesNotThrow(() => validateAgainstSchema(raise, setQueuePolicy.inputSchema, []));
  let out;
  assert.doesNotThrow(() => { out = JSON.parse(setQueuePolicy.handler(raise)).queue_policy; });
  assert.equal(out.standard_wave_target, 200);
  assert.equal(out.standard_wave_max, 300, "the persisted wave_max survived and cleared the raised target");
}));

// Fail-closed is preserved: a PATCH whose MERGED policy is genuinely invalid
// (wave_max < the value the same PATCH sets for wave_target) is still rejected
// eagerly by the handler, before the lock.
test("a genuinely invalid merged wave pair still fails closed at the handler", () => withTempHome(() => {
  const domain = "wave-patch-invalid.example.test";
  assert.throws(
    () => setQueuePolicy.handler({
      target_domain: domain,
      policy: { standard_wave_target: 50, standard_wave_max: 10 },
    }),
    /standard_wave_max must be >= standard_wave_target/,
  );
  // And nothing was persisted (fail-closed, no partial write).
  assert.equal(loadQueuePolicy(domain).standard_wave_target, 64, "default survives; no bad write");
}));
