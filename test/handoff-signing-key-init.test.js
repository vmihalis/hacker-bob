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
const fs = require("fs");
const os = require("os");
const path = require("path");

const { initSession } = require("../mcp/lib/session-state.js");
const { initRepoSession } = require("../mcp/lib/repo-target.js");
const { ensureHandoffSigningKey, readHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
const { handoffSigningKeyPath } = require("../mcp/lib/paths.js");

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
