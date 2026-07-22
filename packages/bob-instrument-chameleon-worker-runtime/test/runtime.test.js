"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const canonicalProviderContracts = require(
  "../../bob-instrument-contracts/lib/instrument-provider-contract.js"
);
const canonicalVerificationContracts = require(
  "../../bob-instrument-contracts/lib/verification-contracts.js"
);
const closedRuntimeContracts = require("../lib/closed-runtime-contracts.js");

function rejectionProjection(assertion, value) {
  try {
    return { accepted: assertion(value, "parity_probe") === true, message: null };
  } catch (error) {
    return { accepted: false, message: error.message };
  }
}

test("worker runtime exposes the exact closed transport-neutral modules", () => {
  const codec = require("../lib/codec.js");
  const commands = require("../lib/compiled-provider-command.js");
  const compiler = require("../lib/hf14a-probe-compiler.js");
  const custody = require("../lib/usb-cdc-custody.js");

  assert.equal(typeof codec.createFrameParser, "function");
  assert.equal(typeof commands.createCompiledProviderCommandChannel, "function");
  assert.equal(typeof compiler.compileHf14aProbe, "function");
  assert.equal(typeof custody.createWorkerUsbCdcCustody, "function");
});

test("private worker contract primitives retain exact canonical accepted-domain parity", () => {
  const digestCorpus = [
    null,
    true,
    17,
    "fixture",
    [3, null, { z: false, a: "first" }],
    { z: 3, omitted: undefined, a: { y: [2, 1], x: "bound" } },
    Object.assign(Object.create(null), { beta: 2, alpha: 1 }),
  ];
  for (const value of digestCorpus) {
    assert.equal(
      closedRuntimeContracts.hashCanonicalJson(value),
      canonicalVerificationContracts.hashCanonicalJson(value),
    );
  }

  const accessor = {};
  Object.defineProperty(accessor, "secret", {
    enumerable: true,
    get() { throw new Error("accessor must never execute"); },
  });
  const symbolField = { safe: true };
  symbolField[Symbol("hostile")] = true;
  const sparse = [];
  sparse.length = 2;
  sparse[1] = "late";
  const repeatedLeaf = { value: 1 };
  const repeated = { left: repeatedLeaf, right: repeatedLeaf };
  const cycle = {};
  cycle.self = cycle;
  let tooDeep = {};
  for (let depth = 0; depth < 66; depth += 1) tooDeep = { next: tooDeep };
  const tooWide = Array.from({ length: 4_097 }, () => ({}));
  const acceptedAndHostileGraphs = [
    null,
    { scalar: "only", nested: [{ count: 2 }, null] },
    [],
    Buffer.from([1, 2, 3]),
    new Uint8Array([1, 2, 3]),
    new ArrayBuffer(4),
    accessor,
    symbolField,
    sparse,
    repeated,
    cycle,
    tooDeep,
    tooWide,
  ];
  for (const value of acceptedAndHostileGraphs) {
    assert.deepEqual(
      rejectionProjection(closedRuntimeContracts.assertNoPublicByteMaterial, value),
      rejectionProjection(canonicalProviderContracts.assertNoPublicByteMaterial, value),
    );
  }
});
