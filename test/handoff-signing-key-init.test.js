"use strict";

// The handoff signing key is provisioned at session creation so every later
// path (wave assignment, handoff validation, the SubagentStop attestation hook)
// finds it; the lazy wave-assignment provisioning remains as a safety net.
// Asserts:
//   * bob_init_session leaves a readable signing key on disk
//   * bob_init_repo_session leaves a readable signing key on disk
//   * re-provisioning is idempotent — it never rotates an existing key, so
//     already-signed handoffs stay verifiable

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { initSession } = require("../mcp/core/session/session-state.js");
const { initRepoSession } = require("../mcp/domains/repo/repo-target.js");
const {
  ensureHandoffSigningKey,
  readHandoffSigningKey,
  ensureHandoffKeypair,
  readHandoffSigningPrivateKey,
  readHandoffSigningPublicKey,
  resolveOffensiveRowVerifier,
  resolveRowVerifierSafely,
} = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
const { assertExploitedClaimHasProof } = require("../mcp/core/claims/claims.js");
const {
  handoffSigningKeyPath,
  handoffSigningPrivateKeyPath,
  handoffSigningPublicKeyPath,
} = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-signkey-init-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function makeTempRepoDir() {
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), "bob-signkey-repo-"));
  return fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);
}

test("bob_init_session provisions a readable handoff signing key", () => {
  withTempHome(() => {
    const domain = "signkey.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    assert.equal(fs.existsSync(handoffSigningKeyPath(domain)), true);
    assert.ok(readHandoffSigningKey(domain), "signing key must be readable after init");
  });
});

test("bob_init_repo_session provisions a readable handoff signing key", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    try {
      const result = initRepoSession({ repo_path: repoPath });
      const domain = result.target_domain;
      assert.equal(fs.existsSync(handoffSigningKeyPath(domain)), true);
      assert.ok(readHandoffSigningKey(domain), "signing key must be readable after repo init");
    } finally {
      fs.rmSync(repoPath, { recursive: true, force: true });
    }
  });
});

test("resuming a repo session re-provisions a missing signing key", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    try {
      const first = initRepoSession({ repo_path: repoPath });
      const domain = first.target_domain;
      // A session created before init provisioned the key (e.g. an older run).
      fs.rmSync(handoffSigningKeyPath(domain), { force: true });
      assert.equal(fs.existsSync(handoffSigningKeyPath(domain)), false);

      const resumed = initRepoSession({ repo_path: repoPath });
      assert.equal(resumed.created, false);
      assert.equal(fs.existsSync(handoffSigningKeyPath(domain)), true);
    } finally {
      fs.rmSync(repoPath, { recursive: true, force: true });
    }
  });
});

test("re-provisioning never rotates an existing signing key", () => {
  withTempHome(() => {
    const domain = "signkey.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    const before = fs.readFileSync(handoffSigningKeyPath(domain), "utf8");
    // The lazy wave-assignment safety net calls ensureHandoffSigningKey again on
    // an already-provisioned session; it must read the existing key, not rotate.
    ensureHandoffSigningKey(domain);
    const after = fs.readFileSync(handoffSigningKeyPath(domain), "utf8");
    assert.equal(after, before);
  });
});

test("bob_init_session provisions the ed25519 keypair (private 0400, public world-readable)", () => {
  withTempHome(() => {
    const domain = "signkey.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });

    const privPath = handoffSigningPrivateKeyPath(domain);
    const pubPath = handoffSigningPublicKeyPath(domain);
    assert.equal(fs.existsSync(privPath), true, "ed25519 private key must exist after init");
    assert.equal(fs.existsSync(pubPath), true, "ed25519 public key must exist after init");

    // The ed25519 private key is minted owner-read-only 0400 (written once, never
    // rewritten); the tighter mode removes even the owner write bit. The custody
    // close is WHO owns the key (a dedicated signer uid), not the mode itself.
    const privMode = fs.statSync(privPath).mode & 0o777;
    assert.equal(privMode, 0o400, "ed25519 private key must be owner-read-only 0400");
    // The public key is world-readable verify material (no 0600 lockdown).
    assert.notEqual(fs.statSync(pubPath).mode & 0o004, 0, "ed25519 public key must be world-readable");

    // The symmetric handoff-provenance key stays owner read/write 0600 (the server
    // reads it back), so the tighter ed25519 mode does not relax the symmetric one.
    const symMode = fs.statSync(handoffSigningKeyPath(domain)).mode & 0o777;
    assert.equal(symMode, 0o600, "symmetric handoff key stays owner-only 0600");

    // The secure private reader accepts the owner-read-only 0400 key: its
    // (mode & 0o077)===0 check passes for 0400 with the O_NOFOLLOW/regular-file
    // discipline intact.
    const priv = readHandoffSigningPrivateKey(domain);
    assert.equal(priv.scheme, "ed25519");
    const pub = readHandoffSigningPublicKey(domain);
    assert.equal(pub.scheme, "ed25519");

    // DER export/import roundtrip: the imported keys sign + verify the same bytes.
    const message = Buffer.from("attest\nroundtrip");
    const signature = crypto.sign(null, message, priv.privateKey);
    assert.equal(crypto.verify(null, message, pub.publicKey, signature), true);
  });
});

test("ensureHandoffKeypair is idempotent — never rotates an existing keypair", () => {
  withTempHome(() => {
    const domain = "signkey.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    const privBefore = fs.readFileSync(handoffSigningPrivateKeyPath(domain), "utf8");
    const pubBefore = fs.readFileSync(handoffSigningPublicKeyPath(domain), "utf8");
    // A safety-net re-provision on an already-provisioned session must read the
    // existing keypair back, never rotate it (already-signed rows stay verifiable).
    ensureHandoffKeypair(domain);
    assert.equal(fs.readFileSync(handoffSigningPrivateKeyPath(domain), "utf8"), privBefore);
    assert.equal(fs.readFileSync(handoffSigningPublicKeyPath(domain), "utf8"), pubBefore);
  });
});

test("M-keypair: a present private key with a transiently-missing public key is NEVER spuriously unverifiable", () => {
  // The partial-write window: ensureHandoffKeypair creates the private key first
  // (the exclusive arbiter), then writes the public key. A concurrent reader between
  // those two writes sees priv-present / pub-missing. Before the fix
  // readHandoffSigningPublicKey threw 'Missing ed25519 public key' there and
  // resolveOffensiveRowVerifier dropped publicKey to null -> a present, valid row
  // spuriously rejected. The fix re-derives the public key from the private key
  // (ed25519's public key is a pure function of the private key), so a present
  // private key always yields its verifier.
  withTempHome(() => {
    const domain = "signkey.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });

    // Capture the real on-disk public key for a byte-equality check, then SIMULATE
    // the window by deleting the public key while the private key stays present.
    const realPub = readHandoffSigningPublicKey(domain).publicKey
      .export({ type: "spki", format: "der" }).toString("base64url");
    fs.rmSync(handoffSigningPublicKeyPath(domain), { force: true });
    assert.equal(fs.existsSync(handoffSigningPublicKeyPath(domain)), false, "public key transiently missing");
    assert.equal(fs.existsSync(handoffSigningPrivateKeyPath(domain)), true, "private key still present");

    // readHandoffSigningPublicKey re-derives the public key from the private key
    // instead of throwing — and it is byte-identical to the original.
    const derived = readHandoffSigningPublicKey(domain);
    assert.equal(derived.scheme, "ed25519");
    assert.equal(
      derived.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
      realPub,
      "the re-derived public key is byte-identical to the original",
    );

    // The verifier bundle still resolves a non-null public key (no spurious reject).
    const verifier = resolveOffensiveRowVerifier(domain);
    assert.ok(verifier.publicKey, "the verifier still carries a public key during the window");
    assert.notEqual(resolveRowVerifierSafely(domain), null, "the safe verifier is non-null (a valid row verifies)");

    // A real row signed by the private key MAC-verifies via the re-derived public key.
    const row = seedEd25519OffensiveRow(domain);
    const claim = {
      target_domain: domain,
      severity: "medium",
      surface_ids: ["surface:billing-profile"],
      exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
      evidence_refs: [{
        kind: "exploit_run",
        run_id: row.run_id,
        tool_id: row.tool_id,
        target: row.target,
        offensive_outcome: "exploited_safely",
        command_hash: row.command_hash,
        exit_code: row.exit_code,
        stdout_hash: row.stdout_hash,
        stderr_hash: row.stderr_hash,
      }],
    };
    assert.doesNotThrow(
      () => assertExploitedClaimHasProof(claim, { existingClaims: [] }),
      "a row signed by the private key verifies via the re-derived public key (no spurious reject in the window)",
    );
  });
});

test("M-keypair: a genuinely pre-keypair session (NO private key) still fails closed", () => {
  // The re-derive path is gated on the private key being present: with NEITHER the
  // private nor the public key, readHandoffSigningPublicKey still throws (the
  // pre-keypair-session fail-closed contract), and resolveRowVerifierSafely is null.
  withTempHome(() => {
    const domain = "signkey.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    fs.rmSync(handoffSigningPrivateKeyPath(domain), { force: true });
    fs.rmSync(handoffSigningPublicKeyPath(domain), { force: true });
    assert.throws(
      () => readHandoffSigningPublicKey(domain),
      /Missing ed25519 public key/,
      "no private key to derive from => fail closed (Missing ed25519 public key)",
    );
    fs.rmSync(handoffSigningKeyPath(domain), { force: true });
    assert.equal(resolveRowVerifierSafely(domain), null, "no key material at all -> null verifier");
  });
});

function hex(char) { return char.repeat(64); }

// Mint a MAC-valid ed25519 offensive-runs row and return its field bundle.
function seedEd25519OffensiveRow(domain) {
  const {
    signRowViaIsolatedSignerOrLocal,
  } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
  const { OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/offensive-row-mac.js");
  const { offensiveRunsJsonlPath, sessionDir } = require("../mcp/core/io/paths.js");
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const row = {
    version: 1, target_domain: domain, run_id: "row-ed-onlyed", tool_id: "bob_http_idor_confirm",
    target: `https://${domain}/api/billing/1`, offensive_outcome: "exploited_safely",
    dry_run: false, timed_out: false, command_hash: hex("1"), exit_code: 0,
    stdout_hash: hex("b"), stderr_hash: hex("c"), demonstrated_severity: "medium",
    surface_id: "surface:billing-profile",
  };
  signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
  return row;
}

test("resolveOffensiveRowVerifier returns {publicKey, hmacKey:null} for an ed25519-only session (symmetric key absent)", () => {
  withTempHome(() => {
    const domain = "signkey.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    // Drop the symmetric handoff key: an ed25519-only session need not carry it.
    fs.rmSync(handoffSigningKeyPath(domain), { force: true });
    assert.equal(fs.existsSync(handoffSigningKeyPath(domain)), false);

    // Was a STATE_CONFLICT throw before the lazy fix; now a non-throwing bundle.
    const verifier = resolveOffensiveRowVerifier(domain);
    assert.ok(verifier && typeof verifier === "object");
    assert.equal(verifier.hmacKey, null, "the absent symmetric key yields hmacKey:null, not a throw");
    assert.ok(verifier.publicKey, "the ed25519 public key is still resolved");
  });
});

test("resolveRowVerifierSafely returns the ed25519-only bundle, and null for a pre-keypair session", () => {
  withTempHome(() => {
    const domain = "signkey.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    fs.rmSync(handoffSigningKeyPath(domain), { force: true });
    const verifier = resolveRowVerifierSafely(domain);
    assert.ok(verifier && verifier.publicKey && verifier.hmacKey === null,
      "ed25519-only session -> { publicKey, hmacKey:null }");

    // Strip ALL key material: a pre-keypair session resolves to a null verifier (a
    // present row_mac then fails closed at assertRowMacOrLegacy).
    fs.rmSync(handoffSigningPrivateKeyPath(domain), { force: true });
    fs.rmSync(handoffSigningPublicKeyPath(domain), { force: true });
    assert.equal(resolveRowVerifierSafely(domain), null,
      "no key material at all -> null verifier (the pre-keypair-session contract)");
  });
});

test("assertExploitedClaimHasProof does NOT hard-fail (STATE_CONFLICT) when the symmetric key is missing", () => {
  withTempHome(() => {
    const domain = "signkey.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    const row = seedEd25519OffensiveRow(domain);
    // Drop the symmetric key AFTER signing the ed25519 row: the verify path must
    // resolve the public-key-only verifier rather than throwing on the missing
    // symmetric key.
    fs.rmSync(handoffSigningKeyPath(domain), { force: true });

    const claim = {
      target_domain: domain,
      severity: "medium",
      surface_ids: ["surface:billing-profile"],
      exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
      evidence_refs: [{
        kind: "exploit_run",
        run_id: row.run_id,
        tool_id: row.tool_id,
        target: row.target,
        offensive_outcome: "exploited_safely",
        command_hash: row.command_hash,
        exit_code: row.exit_code,
        stdout_hash: row.stdout_hash,
        stderr_hash: row.stderr_hash,
      }],
    };
    // The ed25519 row MAC-verifies via the public key with hmacKey:null, so the proof
    // gate accepts it without ever reaching the missing-symmetric-key hard-fail. Before
    // the lazy fix this threw STATE_CONFLICT ("Missing handoff signing key"); the gate
    // must instead pass (a fully valid claim) and NEVER surface STATE_CONFLICT.
    assert.doesNotThrow(() => assertExploitedClaimHasProof(claim, { existingClaims: [] }),
      "an ed25519-only session must not hard-fail; the ed25519 row backs the claim via the public key");
  });
});

test("ensureHandoffKeypair backfills the pair for a session that has only the symmetric key", () => {
  withTempHome(() => {
    const domain = "signkey.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    // Simulate a session created before keypair provisioning existed.
    fs.rmSync(handoffSigningPrivateKeyPath(domain), { force: true });
    fs.rmSync(handoffSigningPublicKeyPath(domain), { force: true });
    assert.equal(fs.existsSync(handoffSigningPrivateKeyPath(domain)), false);

    const { privateKey, publicKey } = ensureHandoffKeypair(domain);
    assert.equal(fs.existsSync(handoffSigningPrivateKeyPath(domain)), true);
    assert.equal(fs.existsSync(handoffSigningPublicKeyPath(domain)), true);
    // The backfilled pair is self-consistent.
    const message = Buffer.from("backfill\nroundtrip");
    const signature = crypto.sign(null, message, privateKey.privateKey);
    assert.equal(crypto.verify(null, message, publicKey.publicKey, signature), true);
  });
});
