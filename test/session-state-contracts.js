"use strict";

// normalizeSessionStateDocument axis rule (O-P6 MIXED program). The relaxed
// invariant: at least one axis must be present; target_url and target_repo are
// the mutually-exclusive primary axes (carrying both is the ONLY multi-axis
// error); target_contracts MAY companion url OR repo, or stand alone (pure-SC).
// A url+repo (or url+repo+contracts) document still fails closed.

const test = require("node:test");
const assert = require("node:assert/strict");

const { normalizeSessionStateDocument } = require("../mcp/lib/session-state-contracts.js");

const DOMAIN = "example.com";
const URL = "https://example.com/";
const REPO = { root_path: "/abs/checkout/repo" };
const REPO_HASH = "deadbeefcafef00d";
const CONTRACTS = ["evm:1:0x0000000000000000000000000000000000000001"];

function base(extra) {
  return Object.assign({ lifecycle_state: "SETUP" }, extra);
}

test("url-alone is valid (regression)", () => {
  const state = normalizeSessionStateDocument(base({ target_url: URL }), DOMAIN);
  assert.equal(state.target_url, URL);
  assert.equal(state.target_repo, null);
  assert.deepEqual(state.target_contracts, []);
  assert.equal(state.chain_authority_hash, null);
});

test("repo-alone is valid (regression)", () => {
  const state = normalizeSessionStateDocument(
    base({ target_repo: REPO, repo_hash: REPO_HASH }),
    "repo-example-deadbeef",
  );
  assert.equal(state.target_repo.root_path, REPO.root_path);
  assert.equal(state.repo_hash, REPO_HASH);
  assert.equal(state.target_url, null);
  assert.deepEqual(state.target_contracts, []);
});

test("contracts-alone is valid (pure-SC, regression)", () => {
  const state = normalizeSessionStateDocument(
    base({ target_contracts: CONTRACTS, chain_authority_hash: "abcd1234" }),
    "sc-evm-1-00000000",
  );
  assert.deepEqual(state.target_contracts, CONTRACTS);
  assert.equal(state.chain_authority_hash, "abcd1234");
  assert.equal(state.target_url, null);
  assert.equal(state.target_repo, null);
});

test("url+contracts is now VALID (was rejected) — mixed web+SC", () => {
  const state = normalizeSessionStateDocument(
    base({ target_url: URL, target_contracts: CONTRACTS, chain_authority_hash: "abcd1234" }),
    DOMAIN,
  );
  // The mixed session carries BOTH the web primary axis and the contracts
  // companion; target_url normalization stays byte-identical to url-alone.
  assert.equal(state.target_url, URL);
  assert.deepEqual(state.target_contracts, CONTRACTS);
  assert.equal(state.chain_authority_hash, "abcd1234");
  assert.equal(state.target_repo, null);
});

test("repo+contracts is now VALID — mixed repo+SC", () => {
  const state = normalizeSessionStateDocument(
    base({ target_repo: REPO, repo_hash: REPO_HASH, target_contracts: CONTRACTS }),
    "repo-example-deadbeef",
  );
  assert.equal(state.target_repo.root_path, REPO.root_path);
  assert.equal(state.repo_hash, REPO_HASH);
  assert.deepEqual(state.target_contracts, CONTRACTS);
  assert.equal(state.target_url, null);
});

test("url+repo is still INVALID (mutually exclusive primary axes)", () => {
  assert.throws(
    () => normalizeSessionStateDocument(
      base({ target_url: URL, target_repo: REPO, repo_hash: REPO_HASH }),
      DOMAIN,
    ),
    /must not carry both target_url and target_repo/,
  );
});

test("url+repo+contracts is still INVALID (url/repo still exclusive)", () => {
  assert.throws(
    () => normalizeSessionStateDocument(
      base({ target_url: URL, target_repo: REPO, repo_hash: REPO_HASH, target_contracts: CONTRACTS }),
      DOMAIN,
    ),
    /must not carry both target_url and target_repo/,
  );
});

test("no axis at all is INVALID", () => {
  assert.throws(
    () => normalizeSessionStateDocument(base({}), DOMAIN),
    /at least one of target_url, target_repo, or target_contracts/,
  );
});

test("an empty target_contracts is NOT the contracts axis", () => {
  // url-alone with an explicit empty array stays single-axis (web) — the empty
  // array is the default web/repo shape, not a contracts binding.
  const state = normalizeSessionStateDocument(
    base({ target_url: URL, target_contracts: [] }),
    DOMAIN,
  );
  assert.equal(state.target_url, URL);
  assert.deepEqual(state.target_contracts, []);
  // ...and an empty target_contracts with no url/repo is no axis at all.
  assert.throws(
    () => normalizeSessionStateDocument(base({ target_contracts: [] }), DOMAIN),
    /at least one of target_url, target_repo, or target_contracts/,
  );
});
