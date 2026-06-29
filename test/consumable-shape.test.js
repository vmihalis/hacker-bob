"use strict";

// The SHARED shape classifier + same-shape random generator (mcp/lib/consumable-shape.js)
// used by BOTH the cross-stack decoy MINT side (offensive-capture-writer) and the VERIFY
// side (cross-stack-differential-verifier). A mint/verify classifier divergence would be a
// soundness gap (the verifier would bind a shape the mint never produces), so this locks the
// classifier's class assignments AND that the generator always preserves byte length + class.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  classifyConsumableShape,
  mintShapeMatchedDecoyBytes,
} = require("../mcp/lib/consumable-shape.js");

test("classifyConsumableShape assigns the expected encoding classes", () => {
  assert.equal(classifyConsumableShape(Buffer.from(JSON.stringify({ a: 1, token: "x" }))), "json");
  assert.equal(classifyConsumableShape(Buffer.from("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.c2ln")), "jwt");
  assert.equal(classifyConsumableShape(Buffer.from("deadbeefcafe0011")), "hex");
  assert.equal(classifyConsumableShape(Buffer.from("YWJjZGVmZ2hpamtsbW5vcA==")), "base64");
  assert.equal(classifyConsumableShape(Buffer.from([1, 2, 3, 255, 0, 9])), "raw");
  assert.equal(classifyConsumableShape(Buffer.alloc(0)), "raw");
  assert.equal(classifyConsumableShape("not a buffer"), "raw");
});

const CAUSES = [
  ["json", Buffer.from(JSON.stringify({ token: "AAAAAAAAAAAAAAAAAAAAAAAA", sub: "user-7", role: "admin", n: 42 }))],
  ["jwt", Buffer.from("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTciLCJyb2xlIjoiYWRtaW4ifQ.c2lnbmF0dXJlLWhlcmU")],
  ["hex", Buffer.from("deadbeefcafe0011223344556677")],
  ["base64", Buffer.from("YWJjZGVmZ2hpamtsbW5vcA==")],
  ["raw", crypto.randomBytes(40)],
];

for (const [name, cause] of CAUSES) {
  test(`mintShapeMatchedDecoyBytes preserves byte length + encoding class for a ${name} cause (and differs in content)`, () => {
    const causeClass = classifyConsumableShape(cause);
    for (let i = 0; i < 50; i += 1) {
      const decoy = mintShapeMatchedDecoyBytes(cause);
      assert.equal(decoy.length, cause.length, `${name}: decoy is the SAME byte length`);
      // The class is preserved for every derivable class; raw is the length-only floor.
      if (causeClass !== "raw") {
        assert.equal(classifyConsumableShape(decoy), causeClass, `${name}: decoy is the SAME encoding class`);
      }
      assert.notEqual(Buffer.compare(decoy, cause), 0, `${name}: decoy content differs from the cause`);
    }
  });
}

test("mintShapeMatchedDecoyBytes on a degenerate (empty) cause returns a non-empty random blob (caller fails closed before this on a null cause)", () => {
  const decoy = mintShapeMatchedDecoyBytes(Buffer.alloc(0));
  assert.ok(Buffer.isBuffer(decoy) && decoy.length > 0);
});

test("even when a tiny-JSON cause falls to the raw floor, byte-length parity ALWAYS holds (the shape-binding minimum)", () => {
  const cause = Buffer.from(JSON.stringify({ a: 1, b: 2 }));
  for (let i = 0; i < 100; i += 1) {
    const decoy = mintShapeMatchedDecoyBytes(cause);
    assert.equal(decoy.length, cause.length, "byte-length parity is the always-held floor");
  }
});
