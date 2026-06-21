"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  frontierEventsJsonlPath,
  pipelineEventsJsonlPath,
} = require("../mcp/lib/paths.js");
const { normalizePipelineEvent } = require("../mcp/lib/pipeline-events.js");
const {
  MAX_FRAME_BYTES,
  readSessionEventFrames,
  framesAfter,
  readJsonlTolerant,
} = require("../mcp/lib/dashboard-event-tail.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-event-tail-test-"));
  process.env.HOME = tempHome;
  const cleanup = () => {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  };
  try {
    const result = fn(tempHome);
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

function writeFrontier(domain, records) {
  const filePath = frontierEventsJsonlPath(domain);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, records.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8");
}

function writePipeline(domain, events) {
  const filePath = pipelineEventsJsonlPath(domain);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, events.map((e) => JSON.stringify(e)).join("\n") + "\n", "utf8");
}

function frontierRecord(eventId, ts, kind, payload) {
  return { event_id: eventId, ts, kind, target_domain: "tail.example", payload: payload || {} };
}

test("readSessionEventFrames folds + orders both ledgers (frontier before pipeline on ts tie)", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-1", "2026-06-21T10:00:00.000Z", "surface.observed", { surface_type: "web_route" }),
      frontierRecord("FE-2", "2026-06-21T10:00:02.000Z", "frontier.enqueued", {}),
    ]);
    writePipeline(domain, [
      normalizePipelineEvent(domain, "finding_recorded", { ts: "2026-06-21T10:00:01.000Z", surface_id: "S-1" }),
      normalizePipelineEvent(domain, "wave_started", { ts: "2026-06-21T10:00:00.000Z", wave: 1 }),
    ]);

    const frames = readSessionEventFrames(domain);
    assert.equal(frames.length, 4);
    assert.deepEqual(
      frames.map((f) => [f.source, f.ts]),
      [
        ["frontier", "2026-06-21T10:00:00.000Z"], // tie → frontier rank 0 first
        ["pipeline", "2026-06-21T10:00:00.000Z"],
        ["pipeline", "2026-06-21T10:00:01.000Z"],
        ["frontier", "2026-06-21T10:00:02.000Z"],
      ],
    );
  });
});

test("frame ids are content-addressed: FE- preserved, PE- synthesized, id = ts|source|recordId", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [frontierRecord("FE-keep", "2026-06-21T10:00:00.000Z", "surface.observed", {})]);
    writePipeline(domain, [normalizePipelineEvent(domain, "grade_written", { ts: "2026-06-21T10:00:01.000Z" })]);

    const frames = readSessionEventFrames(domain);
    const frontier = frames.find((f) => f.source === "frontier");
    const pipeline = frames.find((f) => f.source === "pipeline");
    assert.equal(frontier.record_id, "FE-keep");
    assert.match(pipeline.record_id, /^PE-[0-9a-f]{24}$/);
    assert.equal(frontier.id, `${frontier.ts}|frontier|FE-keep`);
    assert.equal(pipeline.id, `${pipeline.ts}|pipeline|${pipeline.record_id}`);
  });
});

test("readJsonlTolerant + readSessionEventFrames skip a partial/corrupt trailing line, never throw", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [frontierRecord("FE-good", "2026-06-21T10:00:00.000Z", "surface.observed", {})]);
    // simulate a concurrent half-written append
    fs.appendFileSync(frontierEventsJsonlPath(domain), '{"event_id":"FE-partial","ts":"2026', "utf8");

    const raw = readJsonlTolerant(frontierEventsJsonlPath(domain));
    assert.equal(raw.length, 1, "tolerant reader keeps the one valid record");
    const frames = readSessionEventFrames(domain);
    assert.equal(frames.length, 1);
    assert.equal(frames[0].record_id, "FE-good");
  });
});

test("missing ledgers yield an empty stream (no throw)", () => {
  withTempHome(() => {
    assert.deepEqual(readSessionEventFrames("never-seeded.example"), []);
  });
});

test("compaction drops nested payload objects so no raw body can leak", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-x", "2026-06-21T10:00:00.000Z", "observation.recorded", {
        surface_type: "web_route",
        count: 3,
        nested: { secret: "SHOULD_NOT_LEAK" },
        list: ["SHOULD_NOT_LEAK_TOO"],
      }),
    ]);
    const frames = readSessionEventFrames(domain);
    const serialized = JSON.stringify(frames[0].event);
    assert.ok(!serialized.includes("SHOULD_NOT_LEAK"), "nested object dropped");
    assert.ok(!serialized.includes("SHOULD_NOT_LEAK_TOO"), "array dropped");
    assert.equal(frames[0].event.payload.surface_type, "web_route");
    assert.equal(frames[0].event.payload.count, 3);
  });
});

test("oversized frames are truncated under MAX_FRAME_BYTES with a _truncated flag", () => {
  withTempHome(() => {
    const domain = "tail.example";
    const payload = {};
    for (let i = 0; i < 40; i += 1) payload[`k${i}`] = "x".repeat(200);
    writeFrontier(domain, [frontierRecord("FE-big", "2026-06-21T10:00:00.000Z", "observation.recorded", payload)]);

    const frames = readSessionEventFrames(domain);
    assert.equal(frames[0].event._truncated, true);
    assert.equal(frames[0].event.event_id, "FE-big");
    assert.ok(JSON.stringify(frames[0].event).length <= MAX_FRAME_BYTES);
  });
});

test("framesAfter resumes strictly after a present Last-Event-ID (no dup, no gap, no resync)", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-1", "2026-06-21T10:00:00.000Z", "surface.observed", {}),
      frontierRecord("FE-2", "2026-06-21T10:00:01.000Z", "surface.observed", {}),
      frontierRecord("FE-3", "2026-06-21T10:00:02.000Z", "surface.observed", {}),
    ]);
    const frames = readSessionEventFrames(domain);
    const resumed = framesAfter(frames, frames[0].id);
    assert.equal(resumed.resync, false);
    assert.deepEqual(resumed.frames.map((f) => f.record_id), ["FE-2", "FE-3"]);
  });
});

test("framesAfter flags resync when the cursor was trimmed off the front", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [
      frontierRecord("FE-2", "2026-06-21T10:00:01.000Z", "surface.observed", {}),
      frontierRecord("FE-3", "2026-06-21T10:00:02.000Z", "surface.observed", {}),
    ]);
    const frames = readSessionEventFrames(domain);
    // cursor older than everything present (its frame was trimmed away)
    const resumed = framesAfter(frames, "2026-06-21T09:59:00.000Z|frontier|FE-1");
    assert.equal(resumed.resync, true);
    assert.equal(resumed.frames.length, 2);
  });
});

test("framesAfter with no cursor returns all frames and no resync", () => {
  withTempHome(() => {
    const domain = "tail.example";
    writeFrontier(domain, [frontierRecord("FE-1", "2026-06-21T10:00:00.000Z", "surface.observed", {})]);
    const frames = readSessionEventFrames(domain);
    const resumed = framesAfter(frames, undefined);
    assert.equal(resumed.resync, false);
    assert.equal(resumed.frames.length, 1);
  });
});
