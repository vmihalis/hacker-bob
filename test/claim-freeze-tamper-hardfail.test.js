"use strict";

// MEDIUM A — readCurrentClaimFreeze is a THREE-STATE reader so a TAMPERED freeze can
// never silently relax a validation:
//   (a) freeze present, freeze_mac PRESENT-BUT-INVALID (tampered/forged/cross-context)
//       -> THROW STATE_CONFLICT (hard fail up the stack), NOT a silent null;
//   (b) freeze present, freeze_mac ABSENT (legacy in-flight) -> return the doc
//       (accept-with-warning), NOT a throw;
//   (c) no freeze file -> null;
//   (d) corrupt/unparseable freeze bytes -> null (torn write, distinct from a tamper).
// Plus the consumer halt: reclampSeveritiesAgainstFreeze on the TAMPERED freeze HALTS
// with STATE_CONFLICT, so inflated severities are NOT silently un-clamped. Before the
// fix a tampered freeze returned null and reclamp returned an empty Map (the fail-open).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/core/claims/claim-freeze.js");
const { appendCandidateClaim } = require("../mcp/core/claims/claims.js");
const { reclampSeveritiesAgainstFreeze } = require("../mcp/core/verification/verification-round-store.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const { claimFreezePath } = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-freeze-tamper-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedClaim(domain, findingId = "F-1") {
  appendCandidateClaim({
    target_domain: domain,
    title: "Fixture finding",
    summary: "Fixture summary.",
    severity: "medium",
    status: "candidate",
    surface_ids: ["surface:billing-profile"],
    evidence_refs: [{ kind: "finding", finding_id: findingId, content_hash: "0".repeat(64) }],
    impact: "Fixture impact.",
  });
}

function writeRaw(domain, doc) {
  fs.writeFileSync(claimFreezePath(domain), `${JSON.stringify(doc, null, 2)}\n`);
}

function buildWrittenFreeze(domain) {
  seedClaim(domain);
  return buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:00.000Z") });
}

test("(a) present-but-INVALID freeze_mac signature => THROW STATE_CONFLICT (not null)", () => withTempHome(() => {
  const domain = "freeze-tamper-invalid-sig.example.com";
  const built = buildWrittenFreeze(domain);
  assert.ok(built.freeze_mac && built.freeze_mac.scheme === "ed25519");
  // Mutate the signature to an invalid-but-well-formed base64url value, KEEPING the
  // freeze_mac envelope present. The signed preimage no longer verifies -> tamper.
  const tampered = {
    ...built,
    freeze_mac: { ...built.freeze_mac, signature: "A".repeat(86) },
  };
  writeRaw(domain, tampered);
  assert.throws(
    () => readCurrentClaimFreeze(domain),
    (err) => { assert.equal(err.code, "STATE_CONFLICT"); return true; },
    "an invalid-but-present freeze_mac signature hard-fails",
  );
}));

test("(b) STRIPPED freeze_mac (legacy in-flight) => RETURNS the doc (accept-with-warning), no throw", () => withTempHome(() => {
  const domain = "freeze-tamper-legacy.example.com";
  const built = buildWrittenFreeze(domain);
  const legacy = { ...built };
  delete legacy.freeze_mac;
  writeRaw(domain, legacy);
  let read;
  assert.doesNotThrow(() => { read = readCurrentClaimFreeze(domain); },
    "an absent freeze_mac is the legacy accept path, never a throw");
  assert.ok(read, "the legacy freeze is returned");
  assert.equal(read.freeze_mac, undefined, "the returned legacy freeze carries no freeze_mac");
  assert.ok(Array.isArray(read.claims));
}));

test("(c) no freeze file => null", () => withTempHome(() => {
  const domain = "freeze-tamper-absent.example.com";
  assert.equal(readCurrentClaimFreeze(domain), null, "a genuinely-absent freeze file reads back null");
}));

test("(d) corrupt/unparseable freeze bytes => null (torn write, distinct from a tamper)", () => withTempHome(() => {
  const domain = "freeze-tamper-corrupt.example.com";
  seedClaim(domain);
  fs.writeFileSync(claimFreezePath(domain), "{ not valid json :::");
  let result;
  assert.doesNotThrow(() => { result = readCurrentClaimFreeze(domain); },
    "a corrupt freeze fails closed to null, never throws (the torn-write state, not a tamper)");
  assert.equal(result, null);
}));

test("consumer halt: reclampSeveritiesAgainstFreeze on a TAMPERED freeze HALTS (severities not silently un-clamped)", () => withTempHome(() => {
  const domain = "freeze-tamper-reclamp-halt.example.com";
  // A real web session so reclamp's scope gate (web/repo) is satisfied and it actually
  // reads the freeze rather than no-oping on a non-web/non-repo scope.
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
  seedClaim(domain);
  const rebuilt = buildClaimFreeze(domain, { write: true, now: new Date("2026-06-01T00:00:30.000Z") });
  assert.ok(rebuilt.freeze_mac, "freeze is keyed");
  // Tamper a covered field while KEEPING the now-stale freeze_mac.
  const tampered = { ...rebuilt, claim_count: rebuilt.claim_count + 7 };
  writeRaw(domain, tampered);
  // reclamp wraps readCurrentClaimFreeze in try/catch and converts the tamper-throw into a
  // STATE_CONFLICT halt — it does NOT return an empty Map (which would silently un-clamp).
  assert.throws(
    () => reclampSeveritiesAgainstFreeze(domain, [
      { finding_id: "F-1", severity: "critical", reportable: true },
    ]),
    (err) => {
      assert.equal(err.code, "STATE_CONFLICT");
      assert.match(String(err.message), /could not read claim freeze/);
      return true;
    },
    "a tampered freeze halts the severity clamp instead of silently un-clamping",
  );
}));
