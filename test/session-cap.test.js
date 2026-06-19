"use strict";

// Y.10 — session-cap nonce tests.
//
// The session-cap nonce file (~/.bob/session-cap) backs the
// attestation_token field on bob_set_queue_policy({partial_surface_advance_
// acknowledgements: [...]}). Without these tests, the runtime gate would
// accept any non-empty token as authority and the prior Y.10 reviewer
// finding "~/.bob/session-cap mode 0600 NOT implemented" would stand.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  ensureSessionCapNonce,
  generateSessionCapNonce,
  readSessionCapMode,
  readSessionCapNonce,
  sessionCapPath,
  verifyAttestationToken,
  SESSION_CAP_MODE,
} = require("../mcp/lib/session-cap.js");

const {
  evaluateLifecycleTransition,
} = require("../mcp/lib/lifecycle-gates.js");
const {
  normalizeQueuePolicy,
  writeQueuePolicy,
} = require("../mcp/lib/queue-policy.js");
const {
  waveMergeSnapshotPath,
  waveHandoffsSnapshotDir,
} = require("../mcp/lib/wave-handoff-store.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-session-cap-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function seedMergeSnapshot(domain, waveNumber, partialSurfaceIds) {
  fs.mkdirSync(waveHandoffsSnapshotDir(domain), { recursive: true });
  fs.writeFileSync(waveMergeSnapshotPath(domain, waveNumber), JSON.stringify({
    wave_number: waveNumber,
    merged_at_iso: new Date().toISOString(),
    partial_surface_ids: partialSurfaceIds,
  }));
}

test("generateSessionCapNonce returns a 64-char hex string", () => {
  const nonce = generateSessionCapNonce();
  assert.equal(typeof nonce, "string");
  assert.equal(nonce.length, 64);
  assert.match(nonce, /^[0-9a-f]{64}$/);
});

test("ensureSessionCapNonce creates ~/.bob/session-cap with mode 0600", () => {
  withTempHome(() => {
    const nonce = ensureSessionCapNonce();
    assert.equal(typeof nonce, "string");
    assert.equal(nonce.length, 64);
    assert.ok(fs.existsSync(sessionCapPath()));
    const mode = readSessionCapMode();
    assert.equal(mode, SESSION_CAP_MODE);
    assert.equal(mode & 0o077, 0, "group/other bits must be cleared (0600)");
  });
});

test("ensureSessionCapNonce is idempotent — second call returns the same nonce", () => {
  withTempHome(() => {
    const first = ensureSessionCapNonce();
    const second = ensureSessionCapNonce();
    assert.equal(first, second);
  });
});

test("ensureSessionCapNonce re-enforces 0600 if mode drifted", () => {
  withTempHome(() => {
    ensureSessionCapNonce();
    fs.chmodSync(sessionCapPath(), 0o644);
    assert.equal(readSessionCapMode(), 0o644);
    ensureSessionCapNonce();
    assert.equal(readSessionCapMode(), SESSION_CAP_MODE);
  });
});

test("readSessionCapNonce returns null when the file is absent", () => {
  withTempHome(() => {
    assert.equal(readSessionCapNonce(), null);
  });
});

test("verifyAttestationToken: empty token returns empty_token", () => {
  withTempHome(() => {
    assert.deepEqual(verifyAttestationToken(""), { ok: false, cap_status: "empty_token" });
    assert.deepEqual(verifyAttestationToken("   "), { ok: false, cap_status: "empty_token" });
    assert.deepEqual(verifyAttestationToken(null), { ok: false, cap_status: "empty_token" });
    assert.deepEqual(verifyAttestationToken(undefined), { ok: false, cap_status: "empty_token" });
  });
});

test("verifyAttestationToken: file absent => uninitialized (ok: true)", () => {
  withTempHome(() => {
    const result = verifyAttestationToken("any-non-empty-token");
    assert.deepEqual(result, { ok: true, cap_status: "uninitialized" });
  });
});

test("verifyAttestationToken: matching nonce => matched (ok: true)", () => {
  withTempHome(() => {
    const nonce = ensureSessionCapNonce();
    const result = verifyAttestationToken(nonce);
    assert.deepEqual(result, { ok: true, cap_status: "matched" });
  });
});

test("verifyAttestationToken: mismatched token => mismatched (ok: false)", () => {
  withTempHome(() => {
    ensureSessionCapNonce();
    const result = verifyAttestationToken("not-the-real-nonce-not-the-real-nonce-not-the-real-nonce-12345678");
    assert.deepEqual(result, { ok: false, cap_status: "mismatched" });
  });
});

test("verifyAttestationToken: tolerates trailing whitespace in token", () => {
  withTempHome(() => {
    const nonce = ensureSessionCapNonce();
    const result = verifyAttestationToken(`  ${nonce}\n`);
    assert.deepEqual(result, { ok: true, cap_status: "matched" });
  });
});

test("runtime gate accepts ack when session-cap is uninitialized (back-compat)", () => {
  withTempHome(() => {
    const domain = "uninitialized-cap.com";
    seedMergeSnapshot(domain, 1, ["surface-x"]);
    writeQueuePolicy(domain, normalizeQueuePolicy({
      partial_surface_advance_acknowledgements: [
        { surface_id: "surface-x", attestation_token: "any-token" },
      ],
    }));
    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
      nucleus: { lifecycle_state: "OPEN_FRONTIER" },
    });
    assert.deepEqual(evaluation.blockers, []);
  });
});

test("runtime gate accepts ack when token matches the provisioned nonce", () => {
  withTempHome(() => {
    const nonce = ensureSessionCapNonce();
    const domain = "matched-cap.com";
    seedMergeSnapshot(domain, 1, ["surface-x"]);
    writeQueuePolicy(domain, normalizeQueuePolicy({
      partial_surface_advance_acknowledgements: [
        { surface_id: "surface-x", attestation_token: nonce },
      ],
    }));
    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
      nucleus: { lifecycle_state: "OPEN_FRONTIER" },
    });
    assert.deepEqual(evaluation.blockers, []);
  });
});

test("runtime gate REJECTS ack when token mismatches the provisioned nonce", () => {
  withTempHome(() => {
    ensureSessionCapNonce();
    const domain = "mismatched-cap.com";
    seedMergeSnapshot(domain, 1, ["surface-x"]);
    writeQueuePolicy(domain, normalizeQueuePolicy({
      partial_surface_advance_acknowledgements: [
        { surface_id: "surface-x", attestation_token: "deadbeef".repeat(8) },
      ],
    }));
    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
      nucleus: { lifecycle_state: "OPEN_FRONTIER" },
    });
    assert.equal(evaluation.blockers.length, 1);
    const blocker = evaluation.blockers[0];
    assert.equal(blocker.code, "partial_surfaces_remaining");
    assert.deepEqual(blocker.surfaces, ["surface-x"]);
    assert.ok(Array.isArray(blocker.mismatched_acknowledgements));
    assert.equal(blocker.mismatched_acknowledgements.length, 1);
    assert.equal(blocker.mismatched_acknowledgements[0].surface_id, "surface-x");
    assert.equal(blocker.mismatched_acknowledgements[0].cap_status, "mismatched");
    assert.match(blocker.remediation, /~\/.bob\/session-cap/);
  });
});

test("runtime gate accepts only the surfaces whose acks pass; rejects the rest", () => {
  withTempHome(() => {
    const nonce = ensureSessionCapNonce();
    const domain = "mixed-cap.com";
    seedMergeSnapshot(domain, 1, ["surface-a", "surface-b"]);
    writeQueuePolicy(domain, normalizeQueuePolicy({
      partial_surface_advance_acknowledgements: [
        { surface_id: "surface-a", attestation_token: nonce },
        { surface_id: "surface-b", attestation_token: "wrong-token-wrong-token-wrong" },
      ],
    }));
    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: "OPEN_FRONTIER",
      to_state: "CLAIM_FREEZE",
      nucleus: { lifecycle_state: "OPEN_FRONTIER" },
    });
    assert.equal(evaluation.blockers.length, 1);
    assert.deepEqual(evaluation.blockers[0].surfaces, ["surface-b"]);
    assert.equal(evaluation.blockers[0].mismatched_acknowledgements[0].surface_id, "surface-b");
  });
});
