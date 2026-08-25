"use strict";

// A6L coverage: readSessionNucleus is legacy/best-effort and must never leak
// as a grant-adjacent default; readSessionNucleusProjection is the ONLY place
// the tagged {verified:false} legacy projection is assembled, for its tagged
// consumers (bob_read_session_nucleus and bob_read_session_summary, with no
// fixed caller count); migrateLegacySessionAuthority is the locked, idempotent,
// fail-closed entry point that binds a nucleus derived from validated prior
// history to a session that lost (or never had) session-nucleus.json.
//
// No network. All state is local temp-HOME session storage.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  buildSessionNucleus,
  readSessionNucleus,
  readSessionNucleusProjection,
  readVerifiedSessionNucleus,
} = require("../mcp/core/governance/index.js");
const {
  sessionDir,
  sessionEventsJsonlPath,
  sessionNucleusPath,
  statePath,
} = require("../mcp/core/io/paths.js");
const {
  initSession,
  advanceSession,
  setOperatorNote,
} = require("../mcp/core/session/session-state.js");
const {
  readSessionEvents,
} = require("../mcp/core/session/session-events.js");
const {
  MIGRATION_EVENT_KIND,
  migrateLegacySessionAuthority,
} = require("../mcp/core/session/session-authority-migration.js");
const {
  ToolError,
} = require("../mcp/core/io/envelope.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-legacy-authority-migration-"));
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
  return JSON.parse(initSession({
    target_domain: domain,
    target_url: `https://${domain}`,
  }));
}

// ---------------------------------------------------------------------------
// Legacy reads never grant
// ---------------------------------------------------------------------------

test("readSessionNucleusProjection is the only place the legacy fallback is assembled, always tagged verified:false", () => {
  withTempHome(() => {
    const domain = "projection-tag.example.com";
    initDomain(domain);
    const verifiedProjection = readSessionNucleusProjection(domain);
    assert.equal(verifiedProjection.verified, true, "a genuine session must project verified:true");

    fs.unlinkSync(sessionNucleusPath(domain));
    const fallbackProjection = readSessionNucleusProjection(domain);
    assert.equal(fallbackProjection.verified, false, "an absent nucleus must project verified:false");
    assert.equal(fallbackProjection.nucleus.target_domain, domain);
    // The fallback never trusts a leftover/forged on-disk blob — it derives
    // fresh from state.json. Prove this by planting a forged nucleus blob
    // that readSessionNucleus (legacy) WOULD read verbatim, and confirming
    // the projection's fallback still only fires when verification fails,
    // deriving from state rather than the forged file.
    fs.writeFileSync(
      sessionNucleusPath(domain),
      `${JSON.stringify({ nucleus_hash: "forged", target_domain: domain, lifecycle_state: "GRADE" }, null, 2)}\n`,
      "utf8",
    );
    const forgedProjection = readSessionNucleusProjection(domain);
    assert.equal(forgedProjection.verified, false);
    assert.notEqual(forgedProjection.nucleus.lifecycle_state, "GRADE", "must never surface the forged blob's content");
  });
});

test("bob_read_session_nucleus surfaces the tagged legacy projection instead of throwing", () => {
  withTempHome(() => {
    const domain = "read-tool-tag.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    const readSessionNucleusTool = require("../mcp/tools/read-session-nucleus.js");
    const result = JSON.parse(readSessionNucleusTool.handler({ target_domain: domain }));
    assert.equal(result.verified, false);
    assert.equal(result.nucleus.target_domain, domain);
  });
});

test("bob_read_session_state surfaces a verified boolean without re-deriving a duplicate nucleus read", () => {
  withTempHome(() => {
    const domain = "read-state-tag.example.com";
    initDomain(domain);
    const { readSessionState } = require("../mcp/core/session/session-state.js");
    const verifiedResult = JSON.parse(readSessionState({ target_domain: domain }));
    assert.equal(verifiedResult.verified, true);

    fs.unlinkSync(sessionNucleusPath(domain));
    const unverifiedResult = JSON.parse(readSessionState({ target_domain: domain }));
    assert.equal(unverifiedResult.verified, false);
    // state itself is still readable/servable even when the nucleus is gone —
    // this tool's job is state, not nucleus authority.
    assert.equal(unverifiedResult.state.target, domain);
  });
});

test("applyOperatorConstraintUpdate (bob_set_operator_note) fails closed when the nucleus is unverifiable", () => {
  withTempHome(() => {
    const domain = "operator-note-fail-closed.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    assert.throws(
      () => setOperatorNote({ target_domain: domain, operator_note: "hello" }),
      (error) => error instanceof ToolError && /nucleus missing or unverifiable/.test(error.message),
    );
    // No silent write happened either.
    assert.equal(fs.existsSync(sessionNucleusPath(domain)), false);
  });
});

test("advanceSession fails closed when the nucleus is unverifiable, never derives the transition from state.json", () => {
  withTempHome(() => {
    const domain = "advance-fail-closed.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    assert.throws(
      () => advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }),
      (error) => error instanceof ToolError && /nucleus missing or unverifiable/.test(error.message),
    );
  });
});

test("repo-target readRepoSession fails closed when the nucleus is unverifiable", () => {
  withTempHome(() => {
    const repoRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-legacy-migration-repo-"));
    try {
      const { initRepoSession, readRepoSession } = require("../mcp/domains/repo/repo-target.js");
      const created = initRepoSession({ repo_path: repoRoot });
      const domain = created.target_domain;
      fs.unlinkSync(sessionNucleusPath(domain));
      assert.throws(
        () => readRepoSession(domain),
        (error) => error instanceof ToolError && /no verified session nucleus/.test(error.message),
      );
    } finally {
      fs.rmSync(repoRoot, { recursive: true, force: true });
    }
  });
});

test("evidence-marker gating (agent-run-completion) fails closed when the nucleus is unverifiable", () => {
  // Full REPORT-window ALLOW/BLOCK coverage lives in
  // test/evidence-gate-lifecycle.test.js; this only re-confirms the A6L
  // fail-closed contract from this node's own suite.
  withTempHome(() => {
    const domain = "evidence-gate-fail-closed.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    const { evaluateEvidenceCompletion } = require("../mcp/core/session/agent-run-completion.js");
    const result = evaluateEvidenceCompletion({ target_domain: domain });
    assert.equal(result.ok, false);
    assert.equal(result.block_code, "evidence_nucleus_unverified");
  });
});

// ---------------------------------------------------------------------------
// Migration: fresh, repair, idempotency, malformed audit
// ---------------------------------------------------------------------------

test("migration binds a fresh nucleus when the session has state + events but no nucleus file", () => {
  withTempHome(() => {
    const domain = "migrate-fresh-with-events.example.com";
    initDomain(domain);
    const beforeEventsCount = readSessionEvents(domain).length;
    fs.unlinkSync(sessionNucleusPath(domain));
    assert.throws(() => readVerifiedSessionNucleus(domain));

    const result = migrateLegacySessionAuthority(domain);
    assert.equal(result.migrated, true);
    assert.equal(result.repaired, false);
    assert.ok(result.event_id);

    const verified = readVerifiedSessionNucleus(domain);
    assert.equal(verified.nucleus_hash, result.nucleus_hash);

    const events = readSessionEvents(domain);
    assert.equal(events.length, beforeEventsCount + 1);
    assert.equal(events[events.length - 1].kind, MIGRATION_EVENT_KIND);
    assert.equal(events[events.length - 1].nucleus_hash, result.nucleus_hash);
  });
});

test("migration binds a fresh nucleus AND creates session-events.jsonl when neither existed (ancient legacy)", () => {
  withTempHome(() => {
    const domain = "migrate-fresh-no-events.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    fs.unlinkSync(sessionEventsJsonlPath(domain));
    assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), false);

    const result = migrateLegacySessionAuthority(domain);
    assert.equal(result.migrated, true);
    assert.equal(fs.existsSync(sessionEventsJsonlPath(domain)), true);
    const events = readSessionEvents(domain);
    assert.equal(events.length, 1);
    assert.equal(events[0].kind, MIGRATION_EVENT_KIND);
    assert.equal(readVerifiedSessionNucleus(domain).nucleus_hash, result.nucleus_hash);
  });
});

test("migration is idempotent on an already-migrated, hash-bound session (no writes, event_id null)", () => {
  withTempHome(() => {
    const domain = "migrate-idempotent.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    const first = migrateLegacySessionAuthority(domain);

    const nucleusBytes = fs.readFileSync(sessionNucleusPath(domain));
    const eventsBytes = fs.readFileSync(sessionEventsJsonlPath(domain));

    const second = migrateLegacySessionAuthority(domain);
    assert.equal(second.migrated, false);
    assert.equal(second.repaired, false);
    assert.equal(second.event_id, null);
    assert.equal(second.nucleus_hash, first.nucleus_hash);
    assert.equal(Buffer.compare(fs.readFileSync(sessionNucleusPath(domain)), nucleusBytes), 0);
    assert.equal(Buffer.compare(fs.readFileSync(sessionEventsJsonlPath(domain)), eventsBytes), 0);
  });
});

test("migration on an ordinary already-verified session (never legacy) is also idempotent", () => {
  withTempHome(() => {
    const domain = "migrate-already-current.example.com";
    initDomain(domain);
    const beforeHash = readVerifiedSessionNucleus(domain).nucleus_hash;
    const result = migrateLegacySessionAuthority(domain);
    assert.equal(result.migrated, false);
    assert.equal(result.repaired, false);
    assert.equal(result.nucleus_hash, beforeHash);
  });
});

test("migration repairs a present-but-hash-mismatched nucleus (valid state drift, not corruption)", () => {
  withTempHome(() => {
    const domain = "migrate-repair-mismatch.example.com";
    initDomain(domain);
    const beforeHash = readVerifiedSessionNucleus(domain).nucleus_hash;

    // Directly drift state.json (bypassing the normal operator-constraint
    // path) so the nucleus file, though perfectly well-formed, no longer
    // matches what state.json would derive.
    const stateDoc = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    stateDoc.operator_note = "drifted directly";
    fs.writeFileSync(statePath(domain), `${JSON.stringify(stateDoc, null, 2)}\n`, "utf8");

    const result = migrateLegacySessionAuthority(domain);
    assert.equal(result.migrated, false);
    assert.equal(result.repaired, true);
    assert.notEqual(result.nucleus_hash, beforeHash);
    assert.equal(readVerifiedSessionNucleus(domain).nucleus_hash, result.nucleus_hash);

    const events = readSessionEvents(domain);
    assert.equal(events[events.length - 1].kind, MIGRATION_EVENT_KIND);
  });
});

test("migration aborts with zero writes when session-nucleus.json is present but malformed/tampered", () => {
  withTempHome(() => {
    const domain = "migrate-tampered-nucleus.example.com";
    initDomain(domain);
    const nucleus = JSON.parse(fs.readFileSync(sessionNucleusPath(domain), "utf8"));
    nucleus.lifecycle_state = "VERIFY"; // mutate without recomputing nucleus_hash
    fs.writeFileSync(sessionNucleusPath(domain), `${JSON.stringify(nucleus, null, 2)}\n`, "utf8");

    const beforeNucleusBytes = fs.readFileSync(sessionNucleusPath(domain));
    const beforeEventsBytes = fs.readFileSync(sessionEventsJsonlPath(domain));

    assert.throws(
      () => migrateLegacySessionAuthority(domain),
      /nucleus_hash does not match its canonical content/,
    );
    assert.equal(Buffer.compare(fs.readFileSync(sessionNucleusPath(domain)), beforeNucleusBytes), 0);
    assert.equal(Buffer.compare(fs.readFileSync(sessionEventsJsonlPath(domain)), beforeEventsBytes), 0);
  });
});

test("migration aborts with zero writes when session-nucleus.json is a symbolic link", () => {
  withTempHome(() => {
    const domain = "migrate-symlink-nucleus.example.com";
    initDomain(domain);
    const beforeEventsBytes = fs.readFileSync(sessionEventsJsonlPath(domain));
    fs.unlinkSync(sessionNucleusPath(domain));
    fs.symlinkSync(statePath(domain), sessionNucleusPath(domain));

    assert.throws(
      () => migrateLegacySessionAuthority(domain),
      /symbolic link/,
    );
    assert.equal(fs.lstatSync(sessionNucleusPath(domain)).isSymbolicLink(), true, "the symlink itself must survive untouched");
    assert.equal(Buffer.compare(fs.readFileSync(sessionEventsJsonlPath(domain)), beforeEventsBytes), 0);
  });
});

test("migration aborts with zero writes on a single malformed session-events.jsonl record", () => {
  withTempHome(() => {
    const domain = "migrate-malformed-jsonl.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    fs.appendFileSync(sessionEventsJsonlPath(domain), "not-json-at-all\n");

    const beforeEventsBytes = fs.readFileSync(sessionEventsJsonlPath(domain));
    assert.throws(
      () => migrateLegacySessionAuthority(domain),
      /session-authority migration aborted/,
    );
    assert.equal(fs.existsSync(sessionNucleusPath(domain)), false, "no nucleus must be created on a malformed audit");
    assert.equal(Buffer.compare(fs.readFileSync(sessionEventsJsonlPath(domain)), beforeEventsBytes), 0);
  });
});

test("migration aborts with zero writes on a forged event_hash in session-events.jsonl", () => {
  withTempHome(() => {
    const domain = "migrate-forged-event-hash.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    const events = fs.readFileSync(sessionEventsJsonlPath(domain), "utf8").trim().split("\n").map((line) => JSON.parse(line));
    events[0].payload.forged = true; // mutate content without recomputing event_hash
    fs.writeFileSync(sessionEventsJsonlPath(domain), `${events.map((e) => JSON.stringify(e)).join("\n")}\n`, "utf8");

    assert.throws(
      () => migrateLegacySessionAuthority(domain),
      /hash does not match its canonical content/,
    );
    assert.equal(fs.existsSync(sessionNucleusPath(domain)), false);
  });
});

test("migration tolerates a valid-but-unterminated trailing line in session-events.jsonl and appends on its own line", () => {
  withTempHome(() => {
    const domain = "migrate-unterminated-tail.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    const eventsFile = sessionEventsJsonlPath(domain);
    const raw = fs.readFileSync(eventsFile, "utf8");
    assert.ok(raw.endsWith("\n"));
    fs.writeFileSync(eventsFile, raw.replace(/\n$/, ""));

    const result = migrateLegacySessionAuthority(domain);
    assert.equal(result.migrated, true);

    const finalRaw = fs.readFileSync(eventsFile, "utf8");
    const lines = finalRaw.split("\n").filter((line) => line.trim());
    assert.equal(lines.length, 2);
    for (const line of lines) {
      assert.doesNotThrow(() => JSON.parse(line), "every line must be independently valid JSON");
    }
    assert.equal(readVerifiedSessionNucleus(domain).nucleus_hash, result.nucleus_hash);
  });
});

test("migration preserves session-events.jsonl retention at SESSION_EVENTS_MAX_RECORDS and keeps the new event last", () => {
  withTempHome(() => {
    const domain = "migrate-retention.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    const { SESSION_EVENTS_MAX_RECORDS } = require("../mcp/core/session/session-events.js");
    const eventsFile = sessionEventsJsonlPath(domain);
    const existing = fs.readFileSync(eventsFile, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    const filler = [];
    for (let i = 0; filler.length + existing.length <= SESSION_EVENTS_MAX_RECORDS; i += 1) {
      filler.push({
        ...existing[0],
        event_id: `SE-filler-${i}`,
        event_hash: existing[0].event_hash, // not re-verified by this direct write; retention only cares about line count
      });
    }
    const combined = [...existing, ...filler];
    fs.writeFileSync(eventsFile, `${combined.map((e) => JSON.stringify(e)).join("\n")}\n`, "utf8");
    assert.ok(combined.length > SESSION_EVENTS_MAX_RECORDS);

    // Filler lines are not canonically valid events (shared event_hash), so
    // this exercises the retention TRIM behavior of a write path, not the
    // migration audit validator — bypass validation by calling the low-level
    // commit primitive directly the way the migration module does, using a
    // legitimately-derived nucleus and event.
    const { sessionNucleusFromState } = require("../mcp/core/governance/index.js");
    const { readSessionStateStrict } = require("../mcp/core/session/session-state-store.js");
    const { commitLegacySessionAuthorityMigration } = require("../mcp/core/session/session-authority-unit-of-work.js");
    const { normalizeSessionEvent } = require("../mcp/core/session/session-events.js");
    const derivedNucleus = sessionNucleusFromState(readSessionStateStrict(domain).state);
    const migrationEvent = normalizeSessionEvent({
      target_domain: domain,
      kind: MIGRATION_EVENT_KIND,
      nucleus_hash: derivedNucleus.nucleus_hash,
      payload: { nucleus_hash: derivedNucleus.nucleus_hash },
    }, { targetDomain: domain });
    commitLegacySessionAuthorityMigration({
      domain,
      derivedNucleus,
      migrationEvent,
      priorEvents: [],
      bindingEventKinds: [],
    });

    const finalLines = fs.readFileSync(eventsFile, "utf8").trim().split("\n");
    assert.equal(finalLines.length, SESSION_EVENTS_MAX_RECORDS);
    const finalEvents = finalLines.map((line) => JSON.parse(line));
    assert.equal(finalEvents[finalEvents.length - 1].kind, MIGRATION_EVENT_KIND);
    assert.equal(finalEvents[finalEvents.length - 1].event_id, migrationEvent.event_id);
  });
});

test("migration CAS-guards the nucleus replace: a stale precondition snapshot is rejected, never silently overwritten", () => {
  withTempHome(() => {
    const domain = "migrate-cas-race.example.com";
    initDomain(domain);

    // Capture a snapshot of the CURRENT (about-to-be-stale) nucleus bytes,
    // then let the file actually change underneath it — modeling a
    // concurrent writer racing the migration between its read and its write.
    const nucleusFile = sessionNucleusPath(domain);
    const staleBytes = fs.readFileSync(nucleusFile);
    const staleStats = fs.lstatSync(nucleusFile);
    const staleSnapshot = { exists: true, bytes: staleBytes, dev: staleStats.dev, ino: staleStats.ino };

    const stateDoc = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    stateDoc.operator_note = "raced concurrently";
    fs.writeFileSync(statePath(domain), `${JSON.stringify(stateDoc, null, 2)}\n`, "utf8");
    const { sessionNucleusFromState, buildSessionNucleus: build } = require("../mcp/core/governance/index.js");
    const { readSessionStateStrict } = require("../mcp/core/session/session-state-store.js");
    const racedNucleus = build(sessionNucleusFromState(readSessionStateStrict(domain).state));
    fs.writeFileSync(nucleusFile, `${JSON.stringify(racedNucleus, null, 2)}\n`, "utf8");

    // A write bound to the now-stale snapshot must be rejected by the same
    // CAS primitive commitLegacySessionAuthorityMigration uses — proving the
    // "Mismatch/race/nonregular fails" contract for the migration write shape.
    const { writeFileCasAtomicReceipt } = require("../mcp/core/io/storage.js");
    const receipt = writeFileCasAtomicReceipt(nucleusFile, "should-not-land", staleSnapshot);
    assert.notEqual(receipt.status, "created");
    assert.notEqual(receipt.status, "replaced");
    assert.equal(
      fs.readFileSync(nucleusFile, "utf8"),
      `${JSON.stringify(racedNucleus, null, 2)}\n`,
      "the concurrently-written nucleus must survive the rejected stale write untouched",
    );
  });
});

// ---------------------------------------------------------------------------
// readSessionNucleus stays legacy/internal (not asserted deprecated, just
// never grant-adjacent) — governance-store.js keeps exporting it for
// callers that have not migrated. bob_read_session_summary is NOT one of
// those callers: it reads through readSessionNucleusProjection like
// bob_read_session_nucleus and surfaces the same `verified` tag, so it is a
// tagged additional projection consumer rather than an untagged leak.
// bob_read_session_state is unrelated to this wrapper: it derives its own
// `verified` flag independently via sessionNucleusIsVerified /
// readVerifiedSessionNucleus (strict, no fallback).
// ---------------------------------------------------------------------------

test("readSessionNucleus (legacy accessor) still synthesizes from state.json when the nucleus is absent", () => {
  withTempHome(() => {
    const domain = "legacy-accessor-still-works.example.com";
    initDomain(domain);
    fs.unlinkSync(sessionNucleusPath(domain));
    const nucleus = readSessionNucleus(domain);
    assert.equal(nucleus.target_domain, domain);
  });
});

test("bob_read_session_summary surfaces a verified boolean and never trusts a tampered on-disk nucleus", () => {
  withTempHome(() => {
    const domain = "summary-projection-tag.example.com";
    initDomain(domain);
    const { readSessionSummary } = require("../mcp/core/session/session-summary.js");

    const verifiedResult = JSON.parse(readSessionSummary({ target_domain: domain }));
    assert.equal(verifiedResult.summary.verified, true, "a genuine session must project verified:true");
    assert.equal(typeof verifiedResult.summary.nucleus_hash, "string");
    assert.equal(typeof verifiedResult.summary.lifecycle_state, "string");

    // Forge the on-disk nucleus blob the way readSessionNucleus (legacy)
    // would read verbatim, then confirm bob_read_session_summary does not
    // throw and does not surface the forged content: it must derive
    // lifecycle_state/nucleus_hash fresh from state.json and tag verified:false.
    fs.writeFileSync(
      sessionNucleusPath(domain),
      `${JSON.stringify({ nucleus_hash: "forged", target_domain: domain, lifecycle_state: "GRADE" }, null, 2)}\n`,
      "utf8",
    );
    const tamperedResult = JSON.parse(readSessionSummary({ target_domain: domain }));
    assert.equal(tamperedResult.summary.verified, false);
    assert.notEqual(tamperedResult.summary.nucleus_hash, "forged", "must never surface the tampered blob's hash");
    assert.notEqual(tamperedResult.summary.lifecycle_state, "GRADE", "must never surface the tampered blob's lifecycle_state");
  });
});
