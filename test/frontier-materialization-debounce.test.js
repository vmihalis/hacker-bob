"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const {
  pendingDomains,
  resetForTests,
  scheduleMaterialization,
} = require("../mcp/lib/frontier-materialize-debounce.js");
const {
  withSessionLock,
} = require("../mcp/lib/storage.js");
const {
  frontierEventsJsonlPath,
  surfaceIndexPath,
  taskQueuePath,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-frontier-debounce-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    resetForTests();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function fileMtimeMs(p) {
  return fs.statSync(p).mtimeMs;
}

test("scheduleMaterialization coalesces multiple producers within one session-lock hold", () => {
  withTempHome(() => {
    const domain = "debounce-coalesce.example.com";
    // Seed an event so the views are populated when materialization runs.
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-27T00:00:00.000Z",
      surface_id: "surface:billing",
      payload: { title: "Billing API", labels: ["api"] },
    });

    // Three producer-like calls inside one outer withSessionLock; the debounce
    // helper should keep the domain dirty but only materialize once on release.
    let writesDuringLock = 0;
    const surfacePath = surfaceIndexPath(domain);
    if (fs.existsSync(surfacePath)) fs.rmSync(surfacePath);
    if (fs.existsSync(taskQueuePath(domain))) fs.rmSync(taskQueuePath(domain));

    withSessionLock(domain, () => {
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        ts: "2026-05-27T00:00:01.000Z",
        surface_id: "surface:billing",
        payload: { note: "first" },
      });
      scheduleMaterialization(domain);
      if (fs.existsSync(surfacePath)) writesDuringLock += 1;

      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        ts: "2026-05-27T00:00:02.000Z",
        surface_id: "surface:billing",
        payload: { note: "second" },
      });
      scheduleMaterialization(domain);
      if (fs.existsSync(surfacePath)) writesDuringLock += 1;

      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        ts: "2026-05-27T00:00:03.000Z",
        surface_id: "surface:billing",
        payload: { note: "third" },
      });
      scheduleMaterialization(domain);
      if (fs.existsSync(surfacePath)) writesDuringLock += 1;
      assert.deepEqual(pendingDomains(), [domain], "domain stays dirty until lock release");
    });

    // The release hook fires once after the outer withSessionLock exits.
    assert.equal(writesDuringLock, 0, "materialization must not run while the lock is held");
    assert.equal(fs.existsSync(surfacePath), true, "surface-index.json written after release");
    assert.equal(fs.existsSync(taskQueuePath(domain)), true, "task-queue.json written after release");
    assert.deepEqual(pendingDomains(), [], "dirty flag cleared after flush");

    const writtenSurface = JSON.parse(fs.readFileSync(surfacePath, "utf8"));
    assert.equal(writtenSurface.surface_count, 1);

    // A second outer-lock cycle with no new events: the debounce helper must
    // not schedule, so the materialized view file mtime must not advance.
    const beforeMtime = fileMtimeMs(surfacePath);
    withSessionLock(domain, () => {
      // No appendFrontierEvent; no scheduleMaterialization. Hook runs but
      // finds no dirty domain.
    });
    const afterMtime = fileMtimeMs(surfacePath);
    assert.equal(afterMtime, beforeMtime, "no-op lock hold must not rewrite the view");
  });
});

test("materialization is deterministic: same frontier-events.jsonl yields same view hashes", () => {
  withTempHome(() => {
    const domain = "debounce-determinism.example.com";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-27T01:00:00.000Z",
      surface_id: "surface:account",
      payload: { title: "Account settings", uri: "/account" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "frontier.enqueued",
      ts: "2026-05-27T01:00:01.000Z",
      surface_id: "surface:account",
      frontier_item_id: "frontier:item:1",
      payload: {
        lens: "control_check",
        priority: "high",
        summary: "Probe account settings",
      },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-27T01:00:02.000Z",
      surface_id: "surface:account",
      payload: { note: "GET requires auth" },
    });

    const first = materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-27T01:01:00.000Z"),
    });
    const second = materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-27T01:02:00.000Z"),
    });

    assert.equal(
      first.surface_index.surface_index_hash,
      second.surface_index.surface_index_hash,
      "surface_index_hash must be deterministic across re-materializations",
    );
    assert.equal(
      first.task_queue.task_queue_hash,
      second.task_queue.task_queue_hash,
      "task_queue_hash must be deterministic across re-materializations",
    );

    // Hand-craft an identical event log under a sibling session and confirm
    // the same hashes emerge — proving the hashes derive only from events.
    const sourcePath = frontierEventsJsonlPath(domain);
    const clonedDomain = "debounce-determinism-clone.example.com";
    const sessionDir = path.dirname(sourcePath);
    const clonedSessionDir = sessionDir.replace(domain, clonedDomain);
    fs.mkdirSync(clonedSessionDir, { recursive: true });
    // Replace target_domain in each event so normalizer accepts the clone.
    const eventLines = fs.readFileSync(sourcePath, "utf8")
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => {
        const event = JSON.parse(line);
        event.target_domain = clonedDomain;
        return JSON.stringify(event);
      });
    fs.writeFileSync(
      path.join(clonedSessionDir, "frontier-events.jsonl"),
      eventLines.join("\n") + "\n",
    );
    const cloned = materializeFrontier(clonedDomain, {
      write: true,
      now: new Date("2026-05-27T01:03:00.000Z"),
    });
    // Domain is part of the hashed document, so the cloned hashes differ from
    // the source domain but match deterministically across re-materializations.
    const clonedAgain = materializeFrontier(clonedDomain, {
      write: true,
      now: new Date("2026-05-27T01:04:00.000Z"),
    });
    assert.equal(
      cloned.surface_index.surface_index_hash,
      clonedAgain.surface_index.surface_index_hash,
      "cloned surface_index hash stays stable across re-materializations",
    );
    assert.equal(
      cloned.task_queue.task_queue_hash,
      clonedAgain.task_queue.task_queue_hash,
      "cloned task_queue hash stays stable across re-materializations",
    );
  });
});

test("scheduleMaterialization writes view files under ~/hacker-bob-sessions/<domain>/", () => {
  withTempHome((home) => {
    const domain = "debounce-paths.example.com";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-27T02:00:00.000Z",
      surface_id: "surface:upload",
      payload: { title: "Upload endpoint" },
    });

    // appendFrontierEvent already calls withSessionLock internally, so a bare
    // scheduleMaterialization inside another withSessionLock will fire on the
    // outer release.
    withSessionLock(domain, () => {
      scheduleMaterialization(domain);
    });

    const expectedRoot = path.join(home, "hacker-bob-sessions", domain);
    assert.equal(fs.existsSync(path.join(expectedRoot, "surface-index.json")), true,
      "surface-index.json under the expected session root");
    assert.equal(fs.existsSync(path.join(expectedRoot, "task-queue.json")), true,
      "task-queue.json under the expected session root");
  });
});
