"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  initSession,
} = require("../mcp/lib/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/lib/governance-store.js");
const {
  sessionEventsJsonlPath,
  sessionNucleusPath,
} = require("../mcp/lib/paths.js");
const {
  readSessionEvents,
} = require("../mcp/lib/session-events.js");

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
  });
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
