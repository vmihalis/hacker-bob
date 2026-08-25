"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  clearOperatorNote,
  initSession,
  setOperatorNote,
} = require("../mcp/core/session/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/core/governance/index.js");
const {
  readSessionEvents,
} = require("../mcp/core/session/session-events.js");
const {
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-operator-constraint-"));
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

function bootstrapDomain(domain) {
  initSession({ target_domain: domain, target_url: `https://${domain}/` });
}

function operatorConstraintEvents(domain) {
  return readSessionEvents(domain)
    .filter((event) => event.kind === "governance.operator_constraint.updated");
}

test("setOperatorNote re-emits session nucleus and appends governance.operator_constraint.updated event", () => {
  withTempHome(() => {
    const domain = "set-note.example.com";
    bootstrapDomain(domain);

    const initialNucleus = readSessionNucleus(domain);
    assert.match(initialNucleus.nucleus_hash, /^[0-9a-f]{64}$/);
    assert.equal(initialNucleus.operator_constraint.operator_note, undefined);

    const result = JSON.parse(setOperatorNote({
      target_domain: domain,
      operator_note: "test note for cycle G.3",
    }));
    assert.equal(result.updated, true);
    assert.equal(result.operator_note, "test note for cycle G.3");
    assert.match(result.nucleus_hash, /^[0-9a-f]{64}$/);
    assert.notEqual(result.nucleus_hash, initialNucleus.nucleus_hash);

    const persisted = readSessionNucleus(domain);
    assert.equal(persisted.nucleus_hash, result.nucleus_hash);
    assert.equal(persisted.operator_constraint.operator_note, "test note for cycle G.3");
    assert.equal(persisted.operator_constraint.handoff_provenance_required, true);

    const events = operatorConstraintEvents(domain);
    assert.equal(events.length, 1, "exactly one operator_constraint.updated event after set");
    const [event] = events;
    assert.equal(event.plane, "governance");
    assert.equal(event.nucleus_hash, persisted.nucleus_hash);
    assert.equal(event.payload.prior_nucleus_hash, initialNucleus.nucleus_hash);
    assert.equal(event.payload.nucleus_hash, persisted.nucleus_hash);
    assert.match(event.payload.operator_constraint_hash, /^[0-9a-f]{64}$/);
  });
});

test("clearOperatorNote re-emits session nucleus and appends another governance.operator_constraint.updated event", () => {
  withTempHome(() => {
    const domain = "clear-note.example.com";
    bootstrapDomain(domain);

    const setResult = JSON.parse(setOperatorNote({
      target_domain: domain,
      operator_note: "transient operator note",
    }));
    const afterSetNucleus = readSessionNucleus(domain);
    assert.equal(afterSetNucleus.nucleus_hash, setResult.nucleus_hash);

    const clearResult = JSON.parse(clearOperatorNote({ target_domain: domain }));
    assert.equal(clearResult.cleared, true);
    assert.equal(clearResult.operator_note, null);
    assert.match(clearResult.nucleus_hash, /^[0-9a-f]{64}$/);
    assert.notEqual(clearResult.nucleus_hash, setResult.nucleus_hash);

    const persisted = readSessionNucleus(domain);
    assert.equal(persisted.nucleus_hash, clearResult.nucleus_hash);
    assert.equal(persisted.operator_constraint.operator_note, undefined);
    assert.equal(persisted.operator_constraint.handoff_provenance_required, true);

    const events = operatorConstraintEvents(domain);
    assert.equal(events.length, 2, "set + clear produces exactly two operator_constraint.updated events");
    const [setEvent, clearEvent] = events;
    assert.equal(setEvent.payload.nucleus_hash, setResult.nucleus_hash);
    assert.equal(clearEvent.payload.prior_nucleus_hash, setResult.nucleus_hash);
    assert.equal(clearEvent.payload.nucleus_hash, clearResult.nucleus_hash);
    assert.notEqual(setEvent.payload.operator_constraint_hash, clearEvent.payload.operator_constraint_hash);
  });
});

test("setting the same operator note twice still re-emits the nucleus and event idempotently", () => {
  // The Cycle G.3 spec accepts either pure idempotence (no event on a repeat
  // set) or "still safe" (a second event with identical pre/post hashes). The
  // current implementation chooses the simpler invariant: every
  // set/clear call goes through the same write-then-emit path, so a repeat
  // call lands a second event whose prior_nucleus_hash equals its
  // nucleus_hash (no state change). Asserting that explicitly keeps the
  // append-only authority invariant from the Pact intact while documenting
  // the chosen behavior.
  withTempHome(() => {
    const domain = "repeat-set.example.com";
    bootstrapDomain(domain);

    const first = JSON.parse(setOperatorNote({
      target_domain: domain,
      operator_note: "stable note",
    }));
    const second = JSON.parse(setOperatorNote({
      target_domain: domain,
      operator_note: "stable note",
    }));

    assert.equal(first.nucleus_hash, second.nucleus_hash,
      "identical operator note content yields identical nucleus_hash by canonical hashing");

    const events = operatorConstraintEvents(domain);
    assert.equal(events.length, 2,
      "the chosen invariant emits one event per set/clear call; both events are safe because nucleus_hash is unchanged");
    const [firstEvent, secondEvent] = events;
    assert.equal(firstEvent.payload.nucleus_hash, first.nucleus_hash);
    assert.equal(secondEvent.payload.prior_nucleus_hash, first.nucleus_hash);
    assert.equal(secondEvent.payload.nucleus_hash, second.nucleus_hash);
    assert.equal(secondEvent.payload.prior_nucleus_hash, secondEvent.payload.nucleus_hash,
      "a no-op repeat set leaves prior_nucleus_hash == nucleus_hash, proving the nucleus did not drift");
  });
});

// A7M: setOperatorNote/clearOperatorNote now delegate to the shared
// applyOperatorConstraintUpdate writer, which collapses to a single
// commitSessionAuthority call (A2 CAS) instead of the prior independent
// writeJsonDocument + appendSessionEvent + writeSessionStateDocument triple.
// Prove a CAS-layer failure between the verified read and the commit leaves
// state.json/session-nucleus.json/session-events.jsonl byte-identical to
// their pre-call snapshots -- no partial nucleus-write-without-event or
// event-without-state split survives.
test("a commitSessionAuthority CAS failure through setOperatorNote/clearOperatorNote leaves all three stores untouched", () => {
  withTempHome((home) => {
    const domain = "cas-fault.example.com";
    bootstrapDomain(domain);

    const beforeState = fs.readFileSync(statePath(domain));
    const beforeNucleus = fs.readFileSync(sessionNucleusPath(domain));
    const beforeEvents = fs.readFileSync(sessionEventsJsonlPath(domain));

    // Replace session-events.jsonl with a symlink so commitSessionAuthority's
    // own preimage safety check throws deep inside the CAS transaction --
    // strictly after applyOperatorConstraintUpdate's verified nucleus read
    // already succeeded.
    const externalTarget = path.join(home, "external-events-target.jsonl");
    fs.writeFileSync(externalTarget, "external event bytes\n");
    fs.unlinkSync(sessionEventsJsonlPath(domain));
    fs.symlinkSync(externalTarget, sessionEventsJsonlPath(domain));

    assert.throws(
      () => setOperatorNote({ target_domain: domain, operator_note: "should not persist" }),
      /session-events\.jsonl must not be a symbolic link/,
    );
    assert.equal(fs.lstatSync(sessionEventsJsonlPath(domain)).isSymbolicLink(), true);
    assert.equal(Buffer.compare(fs.readFileSync(statePath(domain)), beforeState), 0);
    assert.equal(Buffer.compare(fs.readFileSync(sessionNucleusPath(domain)), beforeNucleus), 0);

    // Restore the real events file and retry: the same call reaches the same
    // terminal state cleanly, with no duplicate/partial event left behind by
    // the failed attempt.
    fs.unlinkSync(sessionEventsJsonlPath(domain));
    fs.writeFileSync(sessionEventsJsonlPath(domain), beforeEvents);

    const retried = JSON.parse(setOperatorNote({ target_domain: domain, operator_note: "should not persist" }));
    assert.equal(retried.updated, true);
    const events = operatorConstraintEvents(domain);
    assert.equal(events.length, 1, "the failed attempt left zero events; the retry appended exactly one");

    const clearBeforeState = fs.readFileSync(statePath(domain));
    const clearBeforeNucleus = fs.readFileSync(sessionNucleusPath(domain));
    fs.unlinkSync(sessionEventsJsonlPath(domain));
    fs.symlinkSync(externalTarget, sessionEventsJsonlPath(domain));

    assert.throws(
      () => clearOperatorNote({ target_domain: domain }),
      /session-events\.jsonl must not be a symbolic link/,
    );
    assert.equal(Buffer.compare(fs.readFileSync(statePath(domain)), clearBeforeState), 0);
    assert.equal(Buffer.compare(fs.readFileSync(sessionNucleusPath(domain)), clearBeforeNucleus), 0);
  });
});
