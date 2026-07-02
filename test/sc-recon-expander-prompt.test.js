"use strict";

// produced_surfaces[] shape guard on the sc-recon-expander role prompt. The
// finalize-node server-mint folds the agent's structured
// agent_output.produced_surfaces[] into smart_contract surfaces; each item must
// carry the chain identity (chain_family, chain_id, contract_address), the
// surface_type, and the endpoint triple the materializer keys on. This guards the
// PROMPT contract so a future edit that drops produced_surfaces or any per-surface
// field is caught at test time. The quoted JSON-key form is the load-bearing
// anchor — the bare field names also appear in surrounding prose, so a quoted-key
// assertion ties the check to the contract template, not the narrative.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const PROMPT_PATH = path.join(__dirname, "..", "prompts", "roles", "sc-recon-expander.md");
const PROMPT = fs.readFileSync(PROMPT_PATH, "utf8");

test("the sc-recon-expander prompt names the structured agent_output.produced_surfaces[] return contract", () => {
  assert.match(PROMPT, /agent_output\.produced_surfaces\[\]/,
    "the prompt must name the agent_output.produced_surfaces[] return contract finalize-node mints from");
});

test("the sc-recon-expander prompt specifies every per-surface field the server-mint depends on", () => {
  assert.match(PROMPT, /"chain_family"\s*:/,
    'the produced_surfaces[] item must name the "chain_family" key');
  assert.match(PROMPT, /"chain_id"\s*:/,
    'the produced_surfaces[] item must name the "chain_id" key');
  assert.match(PROMPT, /"(?:contract_address|address)"\s*:/,
    'the produced_surfaces[] item must name the contract address key (contract_address/address)');
  assert.match(PROMPT, /"endpoints"\s*:/,
    'the produced_surfaces[] item must name the "endpoints" key');
  assert.match(PROMPT, /"surface_type"\s*:\s*"smart_contract"/,
    'the produced_surfaces[] item must declare surface_type: "smart_contract"');
});
