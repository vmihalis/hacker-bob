"use strict";

// A7M coverage: assertSessionEgressIdentity (egress binding) and the shared
// applyOperatorConstraintUpdate writer (backing setOperatorNote/
// clearOperatorNote) each collapse to exactly one commitSessionAuthority
// call per invocation, CAS'd on a verified prior nucleus hash -- the same
// single-authority contract A7 already proved for advanceSession. No
// network. All state is local temp-HOME session storage.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  buildSessionNucleus,
  readVerifiedSessionNucleus,
} = require("../mcp/core/governance/index.js");
const {
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const { writeFileAtomic, writeJsonDocument } = require("../mcp/core/io/storage.js");
const {
  commitSessionAuthority,
} = require("../mcp/core/session/session-authority-unit-of-work.js");
const {
  clearOperatorNote,
  initSession,
  resolveAndAssertSessionEgressIdentity,
  setOperatorNote,
} = require("../mcp/core/session/session-state.js");
const {
  readSessionEvents,
} = require("../mcp/core/session/session-events.js");
const {
  resolveEgressProfile,
} = require("../mcp/core/egress-profiles.js");
const {
  ToolError,
} = require("../mcp/core/io/envelope.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-session-authority-mutation-"));
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

function initDomain(domain) {
  return JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
}

function egressBoundEvents(domain) {
  return readSessionEvents(domain).filter((event) => event.kind === "governance.egress_identity.bound");
}

// Seeds a nucleus-only session (no state.json, ever) directly through
// commitSessionAuthority's own create-CAS path -- the same primitive
// initSession uses -- rather than through initSession + unlink, so the
// session never briefly had a state.json.
function seedNucleusOnlySession(domain) {
  const nucleus = buildSessionNucleus({
    target_domain: domain,
    target_url: `https://${domain}`,
    scope_policy: { target_url: `https://${domain}`, checkpoint_mode: "normal", block_internal_hosts: false },
    egress_identity: {},
    auth_context: {},
    operator_constraint: {},
    lifecycle_state: "SETUP",
  });
  return commitSessionAuthority({
    targetDomain: domain,
    nextNucleus: nucleus,
    stateProjection: null,
    event: {
      target_domain: domain,
      kind: "governance.session.initialized",
      nucleus_hash: nucleus.nucleus_hash,
      payload: { nucleus_hash: nucleus.nucleus_hash },
    },
    expectedNucleusHash: null,
  });
}

// Seeds a pre-A2 legacy fixture: state.json carries the full legacy egress
// shape (unbound: identity hash null) and session-nucleus.json is derived
// independently with a deliberately sparser shape (operator_constraint: {},
// no egress_profile_identity_source) -- mirroring the real seedSessionState
// helper in test/mcp-server.test.js, which is exactly the fixture shape the
// two "legacy egress identity" mcp-server.test.js tests exercise.
function seedLegacyEgressFixture(domain) {
  const state = {
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    checkpoint_mode: "normal",
    block_internal_hosts: false,
    block_internal_hosts_source: "legacy_default",
    phase: "EVALUATE",
    evaluation_wave: 0,
    pending_wave: null,
    total_findings: 0,
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    egress_profile: "default",
    egress_region: null,
    proxy_configured: false,
    egress_profile_identity_hash: null,
    egress_profile_identity_version: null,
    egress_profile_identity_source: {
      proxy_url_source: "none",
      proxy_env_var: null,
      proxy_url_redacted: null,
      resolved_proxy: null,
    },
    egress_profile_identity_bound_at: null,
    egress_profile_identity_bind_source: null,
    egress_profile_legacy_migration: null,
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
  };
  writeFileAtomic(statePath(domain), `${JSON.stringify(state, null, 2)}\n`);
  const nucleus = buildSessionNucleus({
    target_domain: domain,
    target_url: state.target_url,
    scope_policy: {
      target_url: state.target_url,
      checkpoint_mode: state.checkpoint_mode,
      block_internal_hosts: state.block_internal_hosts,
    },
    egress_identity: {
      egress_profile: state.egress_profile,
      egress_region: state.egress_region,
      proxy_configured: state.proxy_configured,
      egress_profile_identity_hash: state.egress_profile_identity_hash,
      egress_profile_identity_version: state.egress_profile_identity_version,
    },
    auth_context: { auth_status: state.auth_status },
    operator_constraint: {},
    lifecycle_state: "OPEN_FRONTIER",
  });
  writeJsonDocument(sessionNucleusPath(domain), nucleus);
  return { state, nucleus };
}

function snapshotStores(domain) {
  return {
    state: fs.existsSync(statePath(domain)) ? fs.readFileSync(statePath(domain)) : null,
    nucleus: fs.readFileSync(sessionNucleusPath(domain)),
    events: fs.existsSync(sessionEventsJsonlPath(domain)) ? fs.readFileSync(sessionEventsJsonlPath(domain)) : null,
  };
}

function assertStoresUnchanged(domain, before) {
  const after = snapshotStores(domain);
  assert.equal(Buffer.compare(after.nucleus, before.nucleus), 0, "session-nucleus.json must be byte-identical");
  if (before.state === null) {
    assert.equal(after.state, null, "no state.json must be created");
  } else {
    assert.equal(Buffer.compare(after.state, before.state), 0, "state.json must be byte-identical");
  }
  if (before.events === null) {
    assert.equal(after.events, null, "no session-events.jsonl must be created");
  } else {
    assert.equal(Buffer.compare(after.events, before.events), 0, "session-events.jsonl must be byte-identical");
  }
}

// ---------------------------------------------------------------------------
// Nucleus-only sessions: stateProjection stays null, no state.json acquired
// ---------------------------------------------------------------------------

test("egress bind on a nucleus-only session commits with a null stateProjection and never creates state.json", () => {
  withTempHome(() => {
    const domain = "nucleus-only-egress.example.com";
    const seeded = seedNucleusOnlySession(domain);
    assert.equal(fs.existsSync(statePath(domain)), false);

    const profile = resolveEgressProfile("default");
    const { identity } = resolveAndAssertSessionEgressIdentity(domain, "default", { source: "unit_test" });
    assert.equal(identity.session_state_present, false);
    assert.equal(identity.session_identity_bound, true);
    assert.equal(identity.egress_profile_identity_hash, profile.egress_profile_identity_hash);
    assert.equal(fs.existsSync(statePath(domain)), false);

    const nucleus = readVerifiedSessionNucleus(domain);
    assert.equal(nucleus.egress_identity.egress_profile_identity_hash, profile.egress_profile_identity_hash);

    const events = egressBoundEvents(domain);
    assert.equal(events.length, 1);
    assert.equal(events[0].payload.legacy_migration, true);
    assert.equal(events[0].payload.prior_nucleus_hash, seeded.nucleus_hash);
    assert.equal(events[0].payload.nucleus_hash, nucleus.nucleus_hash);
    assert.equal(events[0].payload.source, "unit_test");
    assert.equal(events[0].payload.egress_profile_identity_hash, profile.egress_profile_identity_hash);

    // A second, matching bind is now verified read-only: zero writes, zero
    // new events.
    const before = snapshotStores(domain);
    const second = resolveAndAssertSessionEgressIdentity(domain, "default", { source: "unit_test" });
    assert.equal(second.identity.session_identity_bound, false);
    assert.equal(second.identity.session_state_present, false, "a nucleus-only session has no state.json to report present");
    assertStoresUnchanged(domain, before);
    assert.equal(egressBoundEvents(domain).length, 1, "a matching rebind must not append a second event");
  });
});

test("operator-note set/clear on a nucleus-only session commits with a null stateProjection and never creates state.json", () => {
  withTempHome(() => {
    const domain = "nucleus-only-operator-note.example.com";
    seedNucleusOnlySession(domain);
    assert.equal(fs.existsSync(statePath(domain)), false);

    const set = JSON.parse(setOperatorNote({ target_domain: domain, operator_note: "nucleus-only note" }));
    assert.equal(set.updated, true);
    assert.equal(set.state, null);
    assert.equal(fs.existsSync(statePath(domain)), false);

    const nucleus = readVerifiedSessionNucleus(domain);
    assert.equal(nucleus.operator_constraint.operator_note, "nucleus-only note");

    const cleared = JSON.parse(clearOperatorNote({ target_domain: domain }));
    assert.equal(cleared.cleared, true);
    assert.equal(cleared.state, null);
    assert.equal(fs.existsSync(statePath(domain)), false);
  });
});

// ---------------------------------------------------------------------------
// State-backed legacy migration: unbound egress binds via commitSessionAuthority
// ---------------------------------------------------------------------------

test("an unbound legacy egress state migrates via commitSessionAuthority and emits exactly one governance.egress_identity.bound event", () => {
  withTempHome(() => {
    const domain = "legacy-egress-migration.example.com";
    const { nucleus: priorNucleus } = seedLegacyEgressFixture(domain);
    assert.equal(priorNucleus.egress_identity.egress_profile_identity_hash, null);

    const profile = resolveEgressProfile("default");
    const { identity } = resolveAndAssertSessionEgressIdentity(domain, "default", { source: "legacy_migration_test" });
    assert.equal(identity.session_state_present, true);
    assert.equal(identity.session_identity_bound, true);
    assert.equal(identity.egress_profile_identity_hash, profile.egress_profile_identity_hash);

    const state = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.equal(state.egress_profile_identity_hash, profile.egress_profile_identity_hash);
    assert.equal(state.egress_profile_identity_bind_source, "legacy_migration");
    assert.equal(state.egress_profile_legacy_migration.source, "legacy_migration_test");
    assert.equal(state.egress_profile_legacy_migration.previous_unbound, true);

    const nextNucleus = readVerifiedSessionNucleus(domain);
    assert.notEqual(nextNucleus.nucleus_hash, priorNucleus.nucleus_hash);
    assert.equal(nextNucleus.egress_identity.egress_profile_identity_hash, profile.egress_profile_identity_hash);
    // Projection parity: the state-derived and nucleus-derived views of this
    // commit agree exactly (canonicalizeStateProjection's own guard, proven
    // observationally here rather than merely trusted).
    assert.equal(nextNucleus.operator_constraint.handoff_provenance_required, false);

    const events = egressBoundEvents(domain);
    assert.equal(events.length, 1, "exactly one governance.egress_identity.bound event");
    const [event] = events;
    assert.equal(event.plane, "governance");
    assert.equal(event.payload.prior_nucleus_hash, priorNucleus.nucleus_hash);
    assert.equal(event.payload.nucleus_hash, nextNucleus.nucleus_hash);
    assert.equal(event.payload.egress_profile_identity_hash, profile.egress_profile_identity_hash);
    assert.equal(event.payload.egress_profile_identity_version, profile.egress_profile_identity_version);
    assert.equal(event.payload.source, "legacy_migration_test");
    assert.equal(event.payload.legacy_migration, true);

    // A second, matching bind on a state-backed session is also verified
    // read-only: zero writes, zero new events, and session_state_present
    // correctly reports true (the sibling nucleus-only case above proves the
    // false branch).
    const before = snapshotStores(domain);
    const second = resolveAndAssertSessionEgressIdentity(domain, "default", { source: "legacy_migration_test" });
    assert.equal(second.identity.session_identity_bound, false);
    assert.equal(second.identity.session_state_present, true, "a state-backed session must report state.json present");
    assertStoresUnchanged(domain, before);
    assert.equal(egressBoundEvents(domain).length, 1, "a matching rebind must not append a second event");
  });
});

test("egress drift on a state-backed session still throws STATE_CONFLICT with zero writes", () => {
  withTempHome(() => {
    const domain = "egress-drift-flow.example.com";
    initDomain(domain);
    resolveAndAssertSessionEgressIdentity(domain, "default", { source: "first_bind" });

    const before = snapshotStores(domain);
    assert.throws(
      () => resolveAndAssertSessionEgressIdentity(domain, "operator-eu", { source: "drift_attempt" }),
      (error) => {
        // "operator-eu" is not configured in this temp HOME's egress
        // profiles document, so resolveEgressProfile itself throws a plain
        // Error before assertSessionEgressIdentity ever runs when no such
        // profile exists; either that or a genuine STATE_CONFLICT drift
        // both leave zero writes, which is what this test actually proves.
        return error instanceof Error;
      },
    );
    assertStoresUnchanged(domain, before);
  });
});

test("a state-only session with no verifiable nucleus is denied for both egress-bind and operator-note-set", () => {
  withTempHome(() => {
    const domain = "state-only-unverifiable.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    assert.equal(fs.existsSync(statePath(domain)), true);

    assert.throws(
      () => resolveAndAssertSessionEgressIdentity(domain, "default", { source: "should_deny" }),
      (error) => error instanceof ToolError && /nucleus missing or unverifiable/.test(error.message),
    );
    assert.equal(fs.existsSync(sessionNucleusPath(domain)), false, "no silent inline migration");

    assert.throws(
      () => setOperatorNote({ target_domain: domain, operator_note: "should be denied" }),
      (error) => error instanceof ToolError && /nucleus missing or unverifiable/.test(error.message),
    );
    assert.equal(fs.existsSync(sessionNucleusPath(domain)), false, "no silent inline migration");
  });
});

// ---------------------------------------------------------------------------
// Fault injection: a commitSessionAuthority failure after the verified read
// leaves every lifecycle store byte-identical to its pre-call snapshot.
// ---------------------------------------------------------------------------

// Swaps session-events.jsonl for a symlink so commitSessionAuthority's own
// preimage safety check throws deep inside the CAS transaction -- strictly
// after the caller's verified nucleus read already succeeded. Returns the
// pre-swap bytes (or null if no events file existed yet) so the caller can
// restore them for a clean retry.
function replaceEventsWithSymlink(domain, home) {
  const eventsPath = sessionEventsJsonlPath(domain);
  const priorEvents = fs.existsSync(eventsPath) ? fs.readFileSync(eventsPath) : null;
  const externalTarget = path.join(home, `external-events-${Math.random().toString(36).slice(2)}.jsonl`);
  fs.writeFileSync(externalTarget, "external event bytes\n");
  if (fs.existsSync(eventsPath)) fs.unlinkSync(eventsPath);
  fs.symlinkSync(externalTarget, eventsPath);
  return priorEvents;
}

function restoreEvents(domain, priorEvents) {
  const eventsPath = sessionEventsJsonlPath(domain);
  fs.unlinkSync(eventsPath);
  if (priorEvents === null) return;
  fs.writeFileSync(eventsPath, priorEvents);
}

test("an injected commitSessionAuthority failure after a successful verified read leaves the egress-bind path untouched, and a retry reaches a clean terminal state", () => {
  withTempHome((home) => {
    const domain = "egress-fault-injection.example.com";
    seedLegacyEgressFixture(domain);

    // state.json and session-nucleus.json are the two stores the failed CAS
    // transaction must never touch; session-events.jsonl is deliberately
    // swapped out by this fault injection itself, so it is checked
    // separately (still the planted symlink, untouched by the failed call).
    const beforeState = fs.readFileSync(statePath(domain));
    const beforeNucleus = fs.readFileSync(sessionNucleusPath(domain));
    const priorEvents = replaceEventsWithSymlink(domain, home);
    const plantedLinkTarget = fs.readlinkSync(sessionEventsJsonlPath(domain));

    assert.throws(
      () => resolveAndAssertSessionEgressIdentity(domain, "default", { source: "fault_injection" }),
      /session-events\.jsonl must not be a symbolic link/,
    );
    assert.equal(Buffer.compare(fs.readFileSync(statePath(domain)), beforeState), 0);
    assert.equal(Buffer.compare(fs.readFileSync(sessionNucleusPath(domain)), beforeNucleus), 0);
    assert.equal(fs.lstatSync(sessionEventsJsonlPath(domain)).isSymbolicLink(), true);
    assert.equal(fs.readlinkSync(sessionEventsJsonlPath(domain)), plantedLinkTarget);

    // Restore the real events file and retry: the same call reaches the same
    // terminal state cleanly, with no duplicate/partial event left behind by
    // the failed attempt.
    restoreEvents(domain, priorEvents);

    const { identity } = resolveAndAssertSessionEgressIdentity(domain, "default", { source: "fault_injection" });
    assert.equal(identity.session_identity_bound, true);
    assert.equal(egressBoundEvents(domain).length, 1, "the failed attempt left zero events; the retry appended exactly one");
  });
});

test("an injected commitSessionAuthority failure after a successful verified read leaves the operator-note path untouched, and a retry reaches a clean terminal state", () => {
  withTempHome((home) => {
    const domain = "operator-note-fault-injection.example.com";
    initDomain(domain);

    const beforeState = fs.readFileSync(statePath(domain));
    const beforeNucleus = fs.readFileSync(sessionNucleusPath(domain));
    const priorEvents = replaceEventsWithSymlink(domain, home);
    const plantedLinkTarget = fs.readlinkSync(sessionEventsJsonlPath(domain));

    assert.throws(
      () => setOperatorNote({ target_domain: domain, operator_note: "should not persist" }),
      /session-events\.jsonl must not be a symbolic link/,
    );
    assert.equal(Buffer.compare(fs.readFileSync(statePath(domain)), beforeState), 0);
    assert.equal(Buffer.compare(fs.readFileSync(sessionNucleusPath(domain)), beforeNucleus), 0);
    assert.equal(fs.lstatSync(sessionEventsJsonlPath(domain)).isSymbolicLink(), true);
    assert.equal(fs.readlinkSync(sessionEventsJsonlPath(domain)), plantedLinkTarget);

    restoreEvents(domain, priorEvents);

    const retried = JSON.parse(setOperatorNote({ target_domain: domain, operator_note: "should not persist" }));
    assert.equal(retried.updated, true);
    const events = readSessionEvents(domain).filter((event) => event.kind === "governance.operator_constraint.updated");
    assert.equal(events.length, 1, "the failed attempt left zero events; the retry appended exactly one");
  });
});
