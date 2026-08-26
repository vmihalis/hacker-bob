"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const {
  defineTool,
  TOOL_MANIFEST,
} = require("../mcp/tools/tool-registry.js");
const { buildToolCompositionSnapshot } = require("../scripts/lib/tool-composition-contract.js");
const {
  OBSERVED_INVARIANT_CANARY_DESIGN_HASH,
  OBSERVED_INVARIANT_CANARY_PROOF_MODE,
} = require("../mcp/core/differential/index.js");

const FIXTURE_PATH = path.join(__dirname, "fixtures", "tool-composition-contract.json");

test("tool composition registry surfaces match the committed contract", () => {
  const actual = buildToolCompositionSnapshot();
  const expected = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  assert.deepEqual(actual, expected);
});

test("closure-relevant tool proof metadata is paired and exposed in the manifest", () => {
  const meta = TOOL_MANIFEST.bob_verify_finding_differential;
  assert.equal(meta.proof_mode, OBSERVED_INVARIANT_CANARY_PROOF_MODE);
  assert.equal(meta.design_hash, OBSERVED_INVARIANT_CANARY_DESIGN_HASH);

  const base = {
    name: "bob_test_closure_tool",
    description: "test closure tool",
    inputSchema: { type: "object", properties: {}, required: [] },
    handler: () => ({}),
    role_bundles: ["verifier"],
    mutating: true,
    global_preapproval: false,
    network_access: false,
    browser_access: false,
    scope_required: false,
    sensitive_output: true,
    session_artifacts_written: ["finding-differential-verified.jsonl"],
  };
  assert.throws(
    () => defineTool({ ...base, proof_mode: OBSERVED_INVARIANT_CANARY_PROOF_MODE }),
    /declares proof_mode without design_hash/,
  );
  assert.throws(
    () => defineTool({ ...base, design_hash: OBSERVED_INVARIANT_CANARY_DESIGN_HASH }),
    /declares design_hash without proof_mode/,
  );
});
