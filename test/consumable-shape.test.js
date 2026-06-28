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

test("a scalar-JSON cause is NOT classified 'json' and mint/verify AGREE on its shape (closes the scalar divergence)", () => {
  // classifyConsumableShape used to return 'json' for scalars, but the mint side raw-floors a
  // scalar (randomizeJsonLeaves needs a structure), so the verify side re-classified the decoy
  // as 'raw' and refused on the class mismatch — a scalar-token cause could NEVER produce a
  // cross-stack verified_pass. Scalars now fall through the byte-pattern cascade consistently,
  // so mint and verify agree and the decoy is bindable.
  for (const scalar of ["123", "true", "false", "null", "3.14159", "\"x\""]) {
    const cause = Buffer.from(scalar, "utf8");
    const causeClass = classifyConsumableShape(cause);
    assert.notEqual(causeClass, "json", `${scalar}: a scalar must not classify as 'json'`);
    for (let i = 0; i < 30; i += 1) {
      const decoy = mintShapeMatchedDecoyBytes(cause);
      assert.equal(decoy.length, cause.length, `${scalar}: byte-length parity`);
      assert.equal(
        classifyConsumableShape(decoy), causeClass,
        `${scalar}: decoy must re-classify to the SAME class as the cause (mint/verify agree)`,
      );
      assert.notEqual(Buffer.compare(decoy, cause), 0, `${scalar}: decoy content differs from the cause`);
    }
  }
});

test("a JWT decoy REUSES the cause's real header (no fixed-HS256 alg tell)", () => {
  // A content-blind gate that branches on the JWT header algorithm must not be able to HOLD
  // the decoy on the alg alone — the decoy's header must match the cause's, so cause and decoy
  // differ only in the credential-bearing payload+signature. Use an RS256 cause (distinct from
  // the old hardcoded HS256) so a regression to a fixed header would change the header segment.
  const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const header = b64url({ alg: "RS256", kid: "key-2026", typ: "JWT" });
  const payload = b64url({ sub: "user-7", role: "admin", iat: 1717000000 });
  const signature = "Zm9vYmFyc2lnbmF0dXJlLXdpdGgtZW5vdWdoLWxlbmd0aC10by1zdGF5LWp3dA";
  const cause = Buffer.from(`${header}.${payload}.${signature}`, "utf8");
  assert.equal(classifyConsumableShape(cause), "jwt", "fixture is a valid 3-segment JWT");
  for (let i = 0; i < 50; i += 1) {
    const decoy = mintShapeMatchedDecoyBytes(cause);
    assert.equal(decoy.length, cause.length, "byte-length parity holds");
    assert.equal(classifyConsumableShape(decoy), "jwt", "decoy stays JWT-shaped");
    const decoyHeader = decoy.toString("utf8").split(".")[0];
    assert.equal(decoyHeader, header, "decoy header segment EQUALS the cause header (no alg tell)");
    assert.notEqual(Buffer.compare(decoy, cause), 0, "decoy content (payload+signature) differs from the cause");
  }
});

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
