const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const {
  normalizeTask,
} = require("../mcp/lib/tasks.js");
const {
  normalizeQueuePolicy,
} = require("../mcp/lib/queue-policy.js");
const {
  surfaceIndexPath,
  taskQueuePath,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-frontier-fabric-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("frontier events materialize surface and queue views", () => {
  withTempHome(() => {
    const domain = "fabric.example.com";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-26T00:00:00.000Z",
      surface_id: "surface:billing-profile",
      payload: {
        title: "Billing profile API",
        uri: "/api/billing/:id",
        labels: ["api", "tenant-boundary"],
      },
    });
    const queued = appendFrontierEvent({
      target_domain: domain,
      kind: "frontier.enqueued",
      ts: "2026-05-26T00:01:00.000Z",
      surface_id: "surface:billing-profile",
      frontier_item_id: "frontier:item:1",
      payload: {
        lens: "control_check",
        priority: "high",
        summary: "Check account boundary behavior.",
        budget: { max_steps: 3, max_context_tokens: 8000 },
      },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-05-26T00:02:00.000Z",
      surface_id: "surface:billing-profile",
      payload: { note: "Identifier changes alter account scope." },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      ts: "2026-05-26T00:03:00.000Z",
      surface_id: "surface:billing-profile",
      frontier_item_id: "frontier:item:1",
      payload: { code: "needs-second-account" },
    });

    const events = readFrontierEvents(domain);
    assert.equal(events.length, 4);
    assert.match(events[0].event_id, /^FE-/);
    assert.equal(events[1].event_id, queued.event_id);

    const views = materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-26T00:04:00.000Z"),
    });
    assert.equal(views.surface_index.surface_count, 1);
    assert.equal(views.surface_index.surfaces[0].surface_id, "surface:billing-profile");
    assert.equal(views.surface_index.surfaces[0].state, "blocked");
    assert.deepEqual(views.surface_index.surfaces[0].labels, ["api", "tenant-boundary"]);
    assert.equal(views.task_queue.task_count, 1);
    assert.equal(views.task_queue.tasks[0].status, "blocked");
    assert.equal(views.task_queue.tasks[0].lens, "control_check");
    assert.deepEqual(views.task_queue.tasks[0].blocker_event_ids, [events[3].event_id]);
    assert.equal(fs.existsSync(surfaceIndexPath(domain)), true);
    assert.equal(fs.existsSync(taskQueuePath(domain)), true);

    const writtenQueue = JSON.parse(fs.readFileSync(taskQueuePath(domain), "utf8"));
    assert.equal(writtenQueue.task_queue_hash, views.task_queue.task_queue_hash);
  });
});

test("task and queue contracts reject unknown lenses and compact policy duplicates", () => {
  assert.throws(
    () => normalizeTask({
      target_domain: "fabric.example.com",
      surface_id: "surface:alpha",
      lens: "unknown_lens",
    }, { now: new Date("2026-05-26T00:00:00.000Z") }),
    /lens must be one of/,
  );

  const policy = normalizeQueuePolicy({
    priority_order: ["high", "high", "low"],
    max_parallel_tasks: 2,
  });
  assert.deepEqual(policy.priority_order, ["high", "low"]);
  assert.equal(policy.max_parallel_tasks, 2);
});
