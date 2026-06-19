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
} = require("../mcp/lib/session-state.js");
const {
  readSessionNucleus,
} = require("../mcp/lib/governance-store.js");
const {
  readSessionEvents,
} = require("../mcp/lib/session-events.js");

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
