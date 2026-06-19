"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  initRepoSession,
  readRepoSession,
  deriveRepoTargetDomain,
} = require("../mcp/lib/repo-target.js");
const {
  readSessionNucleus,
} = require("../mcp/lib/governance-store.js");
const {
  readSessionStateStrict,
} = require("../mcp/lib/session-state-store.js");
const {
  EXPLICIT_AUTHORITY_CLASS_BY_TOOL,
  REPO_TARGET_DOMAIN_PATTERN,
  authorizeToolCall,
} = require("../mcp/lib/session-authority.js");
const {
  normalizeScopePolicy,
  buildSessionNucleus,
} = require("../mcp/lib/governance-contracts.js");
const initRepoSessionTool = require("../mcp/lib/tools/init-repo-session.js");
const initSessionTool = require("../mcp/lib/tools/init-session.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-repo-target-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function makeTempRepoDir(prefix = "bob-repo-fixture-") {
  // Tests synthesize fixture repos at test time; the realpath() result
  // is what the slug derivation hashes, so we resolve it here for
  // deterministic comparison.
  const raw = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return fs.realpathSync.native ? fs.realpathSync.native(raw) : fs.realpathSync(raw);
}

test("initRepoSession creates a SessionNucleus and state with target_repo binding", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    const result = initRepoSession({ repo_path: repoPath });

    assert.equal(result.created, true);
    assert.equal(result.target_domain, deriveRepoTargetDomain(repoPath));
    assert.match(result.target_domain, REPO_TARGET_DOMAIN_PATTERN);
    assert.equal(result.target_repo.root_path, repoPath);
    assert.match(result.nucleus_hash, /^[0-9a-f]{64}$/);
    assert.match(result.repo_hash, /^[0-9a-f]{8,64}$/);

    const nucleus = readSessionNucleus(result.target_domain);
    assert.equal(nucleus.target_domain, result.target_domain);
    assert.equal(nucleus.scope_policy.target_repo.root_path, repoPath);
    assert.equal(nucleus.scope_policy.target_url, undefined);
    assert.equal(nucleus.repo_hash, result.repo_hash);
    assert.match(nucleus.nucleus_hash, /^[0-9a-f]{64}$/);
    assert.equal(nucleus.nucleus_hash, result.nucleus_hash);

    const { state } = readSessionStateStrict(result.target_domain);
    assert.equal(state.target, result.target_domain);
    assert.equal(state.target_url, null);
    assert.equal(state.target_repo.root_path, repoPath);
    assert.equal(state.repo_hash, result.repo_hash);
    assert.equal(state.lifecycle_state, "SETUP");
  });
});

test("initRepoSession derives a stable target_domain and repo_hash for the same path", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    const first = initRepoSession({ repo_path: repoPath });
    // Drop the just-created session so the second init can run from scratch
    // — we are only asserting derivation stability, not idempotency.
    fs.rmSync(path.join(process.env.HOME, "hacker-bob-sessions", first.target_domain), {
      recursive: true,
      force: true,
    });
    const second = initRepoSession({ repo_path: repoPath });
    assert.equal(second.target_domain, first.target_domain);
    assert.equal(second.repo_hash, first.repo_hash);
  });
});

test("initRepoSession rejects a non-existent repo_path with repo_path_not_found", () => {
  withTempHome(() => {
    const missing = path.join(os.tmpdir(), "bob-repo-target-missing-" + Date.now());
    let caught;
    try {
      initRepoSession({ repo_path: missing });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "expected an error for missing path");
    assert.match(caught.message, /does not exist/);
    assert.equal(caught.details && caught.details.repo_error_code, "repo_path_not_found");
  });
});

test("initRepoSession rejects a file path with repo_path_not_directory", () => {
  withTempHome(() => {
    const dir = makeTempRepoDir();
    const filePath = path.join(dir, "not-a-dir.txt");
    fs.writeFileSync(filePath, "hello");
    let caught;
    try {
      initRepoSession({ repo_path: filePath });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught, "expected an error for file path");
    assert.match(caught.message, /not a directory/);
    assert.equal(caught.details && caught.details.repo_error_code, "repo_path_not_directory");
  });
});

test("normalizeScopePolicy refuses both target_url and target_repo together", () => {
  const repoPath = makeTempRepoDir();
  try {
    assert.throws(
      () => normalizeScopePolicy({
        target_domain: "example.com",
        target_url: "https://example.com/",
        target_repo: { root_path: repoPath },
      }),
      /exactly one of target_url or target_repo/,
    );
  } finally {
    fs.rmSync(repoPath, { recursive: true, force: true });
  }
});

test("normalizeScopePolicy refuses neither target_url nor target_repo", () => {
  assert.throws(
    () => normalizeScopePolicy({ target_domain: "example.com" }),
    /requires exactly one of target_url or target_repo/,
  );
});

test("buildSessionNucleus persists repo_hash when supplied", () => {
  const repoPath = makeTempRepoDir();
  try {
    const nucleus = buildSessionNucleus({
      target_domain: "repo-test-12345678",
      target_repo: { root_path: repoPath },
      repo_hash: "deadbeefcafef00d",
      scope_policy: {
        target_domain: "repo-test-12345678",
        target_repo: { root_path: repoPath },
        checkpoint_mode: "normal",
        block_internal_hosts: false,
        block_internal_hosts_source: "mode_default",
      },
    });
    assert.equal(nucleus.repo_hash, "deadbeefcafef00d");
    assert.equal(nucleus.scope_policy.target_repo.root_path, repoPath);
    assert.equal(nucleus.scope_policy.target_url, undefined);
  } finally {
    fs.rmSync(repoPath, { recursive: true, force: true });
  }
});

test("bob_init_repo_session tool handler returns a JSON envelope", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    const payload = JSON.parse(initRepoSessionTool.handler({ repo_path: repoPath }));
    assert.equal(payload.version, 1);
    assert.equal(payload.created, true);
    assert.equal(payload.target_repo.root_path, repoPath);
    assert.match(payload.target_domain, REPO_TARGET_DOMAIN_PATTERN);
    assert.match(payload.nucleus_hash, /^[0-9a-f]{64}$/);
  });
});

test("bob_init_repo_session authority class is registered as bootstrap_session", () => {
  assert.equal(EXPLICIT_AUTHORITY_CLASS_BY_TOOL.bob_init_repo_session, "bootstrap_session");
});

test("session-authority bootstrap accepts repo-only arguments (no target_url)", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    const targetDomain = deriveRepoTargetDomain(repoPath);
    const decision = authorizeToolCall(initRepoSessionTool, {
      target_domain: targetDomain,
      target_repo: { root_path: repoPath },
    });
    assert.equal(decision.authority_result, "allowed");
    assert.equal(decision.authority_class, "bootstrap_session");
    assert.equal(decision.authority_target_domain, targetDomain);
  });
});

test("session-authority bootstrap refuses both target_url and target_repo together", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    const targetDomain = deriveRepoTargetDomain(repoPath);
    assert.throws(
      () => authorizeToolCall(initRepoSessionTool, {
        target_domain: targetDomain,
        target_repo: { root_path: repoPath },
        target_url: "https://example.com/",
      }),
      /exactly one of target_url or target_repo/,
    );
  });
});

test("session-authority bootstrap still accepts url-only arguments (regression)", () => {
  withTempHome(() => {
    const decision = authorizeToolCall(initSessionTool, {
      target_domain: "example.com",
      target_url: "https://example.com/",
    });
    assert.equal(decision.authority_result, "allowed");
    assert.equal(decision.authority_target_domain, "example.com");
  });
});

test("bob_init_session refuses target_repo with a redirect pointer", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    assert.throws(
      () => initSessionTool.handler({
        target_domain: deriveRepoTargetDomain(repoPath),
        target_repo: { root_path: repoPath },
      }),
      /bob_init_repo_session/,
    );
  });
});

test("readRepoSession round-trips the bound target_repo and repo_hash", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    const init = initRepoSession({ repo_path: repoPath });
    const read = readRepoSession(init.target_domain);
    assert.equal(read.target_domain, init.target_domain);
    assert.equal(read.target_repo.root_path, repoPath);
    assert.equal(read.repo_hash, init.repo_hash);
    assert.equal(read.nucleus_hash, init.nucleus_hash);
    assert.equal(read.lifecycle_state, "SETUP");
  });
});

test("explicit target_domain is accepted as a custom safe slug (supports --target-id override)", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    const customSlug = "repo-myproject-stable";
    const result = initRepoSession({ repo_path: repoPath, target_domain: customSlug });
    assert.equal(result.target_domain, customSlug);
  });
});

test("optional commit pins the repo_hash to the supplied commit", () => {
  withTempHome(() => {
    const repoPath = makeTempRepoDir();
    const commit = "abcdef1234567890abcdef1234567890abcdef12";
    const result = initRepoSession({ repo_path: repoPath, commit });
    assert.equal(result.repo_hash, commit.toLowerCase());
    const nucleus = readSessionNucleus(result.target_domain);
    assert.equal(nucleus.scope_policy.target_repo.commit, commit.toLowerCase());
    assert.equal(nucleus.repo_hash, commit.toLowerCase());
  });
});
