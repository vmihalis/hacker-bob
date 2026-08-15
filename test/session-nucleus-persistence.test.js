"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  initSession,
} = require("../mcp/core/session/session-state.js");
const {
  readSessionNucleus,
  readVerifiedSessionNucleus,
} = require("../mcp/core/governance/governance-store.js");
const {
  sessionDir,
  sessionEventsJsonlPath,
  sessionNucleusPath,
  sessionsRoot,
} = require("../mcp/core/io/paths.js");
const {
  readSessionEvents,
} = require("../mcp/core/session/session-events.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-session-nucleus-"));
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

test("init-session persists session-nucleus.json with a 64-hex nucleus_hash", () => {
  withTempHome(() => {
    const domain = "nucleus.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });

    const nucleusFile = sessionNucleusPath(domain);
    assert.ok(fs.existsSync(nucleusFile), "session-nucleus.json must be written on init");

    const persisted = JSON.parse(fs.readFileSync(nucleusFile, "utf8"));
    assert.equal(persisted.target_domain, domain);
    assert.equal(persisted.lifecycle_state, "SETUP");
    assert.match(persisted.nucleus_hash, /^[0-9a-f]{64}$/);

    const viaStore = readSessionNucleus(domain);
    assert.equal(viaStore.nucleus_hash, persisted.nucleus_hash);
    assert.deepEqual(readVerifiedSessionNucleus(domain), viaStore);
  });
});

test("verified nucleus reader rejects symlinks, hardlinks, and oversized files", () => {
  withTempHome((home) => {
    const domain = "nucleus-leaf-defense.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    const nucleusFile = sessionNucleusPath(domain);
    const externalFile = path.join(home, "external-session-nucleus.json");
    fs.copyFileSync(nucleusFile, externalFile);

    fs.unlinkSync(nucleusFile);
    fs.symlinkSync(externalFile, nucleusFile);
    assert.throws(
      () => readVerifiedSessionNucleus(domain),
      /session-nucleus\.json must not be a symbolic link/,
    );

    fs.unlinkSync(nucleusFile);
    fs.linkSync(externalFile, nucleusFile);
    assert.throws(
      () => readVerifiedSessionNucleus(domain),
      /session-nucleus\.json must be a single-link regular file/,
    );

    fs.unlinkSync(nucleusFile);
    fs.writeFileSync(nucleusFile, Buffer.alloc((1024 * 1024) + 1, 0x20));
    assert.throws(
      () => readVerifiedSessionNucleus(domain),
      /session-nucleus\.json exceeds the verified read cap/,
    );
  });
});

test("verified nucleus reader detects a path swap between lstat and open", () => {
  withTempHome(() => {
    const domain = "nucleus-preopen-swap.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });
    const nucleusFile = sessionNucleusPath(domain);
    const replacementFile = `${nucleusFile}.replacement`;
    const displacedFile = `${nucleusFile}.displaced`;
    fs.copyFileSync(nucleusFile, replacementFile);

    const originalOpenSync = fs.openSync;
    let swapped = false;
    fs.openSync = function injectedOpenSync(...args) {
      if (!swapped && args[0] === nucleusFile) {
        fs.renameSync(nucleusFile, displacedFile);
        fs.renameSync(replacementFile, nucleusFile);
        swapped = true;
      }
      return originalOpenSync.apply(fs, args);
    };
    try {
      assert.throws(
        () => readVerifiedSessionNucleus(domain),
        /session-nucleus\.json changed before verified read/,
      );
      assert.equal(swapped, true);
    } finally {
      fs.openSync = originalOpenSync;
      if (fs.existsSync(nucleusFile)) fs.unlinkSync(nucleusFile);
      if (fs.existsSync(displacedFile)) fs.renameSync(displacedFile, nucleusFile);
      try { fs.unlinkSync(replacementFile); } catch {}
    }
  });
});

test("verified nucleus reader detects path replacement and link-count drift while open", () => {
  for (const injectLinkDrift of [false, true]) {
    withTempHome(() => {
      const domain = injectLinkDrift
        ? "nucleus-open-link-drift.example.com"
        : "nucleus-open-path-swap.example.com";
      initSession({ target_domain: domain, target_url: `https://${domain}` });
      const nucleusFile = sessionNucleusPath(domain);
      const replacementFile = `${nucleusFile}.replacement`;
      const displacedFile = `${nucleusFile}.displaced`;
      const linkFile = `${nucleusFile}.link`;
      if (!injectLinkDrift) fs.copyFileSync(nucleusFile, replacementFile);

      const originalReadSync = fs.readSync;
      let injected = false;
      fs.readSync = function injectedReadSync(...args) {
        if (!injected) {
          if (injectLinkDrift) {
            fs.linkSync(nucleusFile, linkFile);
          } else {
            fs.renameSync(nucleusFile, displacedFile);
            fs.renameSync(replacementFile, nucleusFile);
          }
          injected = true;
        }
        return originalReadSync.apply(fs, args);
      };
      try {
        assert.throws(
          () => readVerifiedSessionNucleus(domain),
          injectLinkDrift
            ? /session-nucleus\.json changed while reading/
            : /session-nucleus\.json changed during verified read/,
        );
        assert.equal(injected, true);
      } finally {
        fs.readSync = originalReadSync;
        try { fs.unlinkSync(linkFile); } catch {}
        if (!injectLinkDrift) {
          if (fs.existsSync(nucleusFile)) fs.unlinkSync(nucleusFile);
          if (fs.existsSync(displacedFile)) fs.renameSync(displacedFile, nucleusFile);
          try { fs.unlinkSync(replacementFile); } catch {}
        }
      }
    });
  }
});

test("verified nucleus reader pins sessions-root and session-directory identities", () => {
  for (const changedDirectory of ["root", "session"]) {
    withTempHome(() => {
      const domain = `nucleus-${changedDirectory}-swap.example.com`;
      initSession({ target_domain: domain, target_url: `https://${domain}` });
      const nucleusFile = sessionNucleusPath(domain);
      const watchedDirectory = changedDirectory === "root" ? sessionsRoot() : sessionDir(domain);
      const originalOpenSync = fs.openSync;
      const originalLstatSync = fs.lstatSync;
      let nucleusOpened = false;
      fs.openSync = function injectedOpenSync(...args) {
        const descriptor = originalOpenSync.apply(fs, args);
        if (args[0] === nucleusFile) nucleusOpened = true;
        return descriptor;
      };
      fs.lstatSync = function injectedLstatSync(...args) {
        const stats = originalLstatSync.apply(fs, args);
        if (!nucleusOpened || args[0] !== watchedDirectory) return stats;
        return {
          dev: stats.dev,
          ino: stats.ino + 1,
          isDirectory: () => stats.isDirectory(),
          isSymbolicLink: () => stats.isSymbolicLink(),
        };
      };
      try {
        assert.throws(
          () => readVerifiedSessionNucleus(domain),
          changedDirectory === "root"
            ? /Hacker Bob sessions root changed during verified nucleus read/
            : /Hacker Bob session directory changed during verified nucleus read/,
        );
        assert.equal(nucleusOpened, true);
      } finally {
        fs.openSync = originalOpenSync;
        fs.lstatSync = originalLstatSync;
      }
    });
  }
});

test("init-session appends a governance.session.initialized event", () => {
  withTempHome(() => {
    const domain = "events.example.com";
    initSession({ target_domain: domain, target_url: `https://${domain}` });

    const eventsFile = sessionEventsJsonlPath(domain);
    assert.ok(fs.existsSync(eventsFile), "session-events.jsonl must be written on init");

    const events = readSessionEvents(domain);
    assert.equal(events.length, 1, "exactly one governance event after init");
    const [event] = events;
    assert.equal(event.kind, "governance.session.initialized");
    assert.equal(event.plane, "governance");
    assert.match(event.event_id, /^SE-/);
    assert.match(event.event_hash, /^[0-9a-f]{64}$/);

    const nucleus = readSessionNucleus(domain);
    assert.equal(event.nucleus_hash, nucleus.nucleus_hash);
    assert.equal(event.payload.nucleus_hash, nucleus.nucleus_hash);
    assert.match(event.payload.scope_policy_hash, /^[0-9a-f]{64}$/);
    assert.match(event.payload.egress_identity_hash, /^[0-9a-f]{64}$/);
    assert.match(event.payload.auth_context_hash, /^[0-9a-f]{64}$/);
    assert.match(event.payload.operator_constraint_hash, /^[0-9a-f]{64}$/);
  });
});

test("distinct target URLs produce distinct nucleus_hash values", () => {
  withTempHome(() => {
    const domainA = "alpha.example.com";
    const domainB = "beta.example.com";
    initSession({ target_domain: domainA, target_url: `https://${domainA}` });
    initSession({ target_domain: domainB, target_url: `https://${domainB}/api` });

    const nucleusA = readSessionNucleus(domainA);
    const nucleusB = readSessionNucleus(domainB);

    assert.notEqual(
      nucleusA.scope_policy.target_url,
      nucleusB.scope_policy.target_url,
      "test setup must drive distinct target URLs",
    );
    assert.notEqual(
      nucleusA.nucleus_hash,
      nucleusB.nucleus_hash,
      "scope-policy target_url change must produce a different nucleus_hash",
    );
  });
});
