"use strict";

// OD2 oss_repo_ref gate. The SC-address expander discovers every github ref
// the contract source references, but auto-run eligibility is denied for
// well-known third-party libraries (OpenZeppelin, solmate, forge-std, Uniswap
// libs, ds-test, chainlink). RANK != BOUND: a denylisted ref is still reported
// as a discovered oss_repo_ref lead (operator-promotable), never silently
// dropped — the denylist gates only auto_run_eligible.

const test = require("node:test");
const assert = require("node:assert/strict");

const { isStdlibRepoRef } = require("../mcp/domains/repo/oss-repo-ref-denylist.js");
const { classifyOssRepoRefLead } = require("../mcp/core/frontier/lead-promotion.js");

const DENYLISTED_REFS = [
  "github.com/OpenZeppelin/openzeppelin-contracts",
  "OpenZeppelin/openzeppelin-contracts-upgradeable",
  "transmissions11/solmate",
  "Rari-Capital/solmate",
  "foundry-rs/forge-std",
  "Uniswap/v2-core",
  "Uniswap/v3-core",
  "Uniswap/v3-periphery",
  "Uniswap/solidity-lib",
  "dapphub/ds-test",
  "smartcontractkit/chainlink",
];

const NON_STDLIB_REF = "github.com/someproto/theircontracts";

test("a non-stdlib ref is discovered and auto_run_eligible", () => {
  assert.equal(isStdlibRepoRef(NON_STDLIB_REF), false);
  const lead = classifyOssRepoRefLead(NON_STDLIB_REF);
  assert.equal(lead.auto_run_eligible, true);
  assert.equal(lead.discovered, true);
  assert.equal(lead.stdlib, false);
});

test("well-known library refs are denylisted: reported, not auto-run", () => {
  for (const ref of DENYLISTED_REFS) {
    assert.equal(isStdlibRepoRef(ref), true, `${ref} must be a stdlib ref`);
    const lead = classifyOssRepoRefLead(ref);
    assert.equal(lead.auto_run_eligible, false, `${ref} must not be auto-run`);
    assert.equal(lead.promote, false, `${ref} must remain operator-promotable`);
    assert.equal(lead.stdlib, true);
  }
});

test("denylist org match is case-insensitive", () => {
  assert.equal(isStdlibRepoRef("openzeppelin/OPENZEPPELIN-CONTRACTS"), true);
});

test("every discovered ref surfaces an oss_repo_ref lead (no silent drop)", () => {
  const allRefs = [NON_STDLIB_REF, ...DENYLISTED_REFS];
  for (const ref of allRefs) {
    const lead = classifyOssRepoRefLead(ref);
    assert.equal(lead.discovered, true, `${ref} must be discovered`);
    assert.equal(lead.github_ref, ref);
    assert.equal(lead.surface_type, "oss_repo_ref");
    assert.equal(lead.promote, false);
  }
});
