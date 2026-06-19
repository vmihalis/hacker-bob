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
  readSchedulerDecisions,
  scheduleTasksFromQueue,
} = require("../mcp/lib/scheduler-decisions.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-scheduler-decisions-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("scheduler decisions carry task lens and budget into assignments", () => {
  withTempHome(() => {
    const domain = "scheduler.example.com";
    appendFrontierEvent({
      target_domain: domain,
      kind: "surface.observed",
      ts: "2026-05-26T03:00:00.000Z",
      surface_id: "surface:account-settings",
      payload: { title: "Account settings API" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "frontier.enqueued",
      ts: "2026-05-26T03:01:00.000Z",
      surface_id: "surface:account-settings",
      frontier_item_id: "frontier:item:scheduler-1",
      payload: {
        lens: "behavior_probe",
        priority: "critical",
        budget: { max_steps: 4, max_context_tokens: 12000 },
      },
    });
    materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-26T03:02:00.000Z"),
    });

    const decision = scheduleTasksFromQueue(domain, {
      write: true,
      now: new Date("2026-05-26T03:03:00.000Z"),
    });

    assert.equal(decision.assignment_count, 1);
    assert.equal(decision.assignments[0].task_lens, "behavior_probe");
    assert.deepEqual(decision.assignments[0].budget, { max_steps: 4, max_context_tokens: 12000 });
    assert.equal(decision.assignments[0].context_slice.task_lens, "behavior_probe");
    assert.match(decision.assignments[0].assignment_hash, /^[0-9a-f]{64}$/);
    assert.match(decision.scheduler_decision_hash, /^[0-9a-f]{64}$/);
    assert.equal(readSchedulerDecisions(domain)[0].scheduler_decision_id, decision.scheduler_decision_id);
  });
});

test("scheduler decisions apply default budget and queue limit", () => {
  const decision = scheduleTasksFromQueue("scheduler-limit.example.com", {
    maxAssignments: 1,
    now: new Date("2026-05-26T04:00:00.000Z"),
    taskQueue: {
      version: 1,
      target_domain: "scheduler-limit.example.com",
      task_queue_hash: "f".repeat(64),
      policy: { max_parallel_tasks: 4 },
      tasks: [
        {
          task_id: "T-high",
          target_domain: "scheduler-limit.example.com",
          surface_id: "surface:high",
          lens: "control_check",
          priority: "high",
          status: "queued",
          created_at: "2026-05-26T03:00:00.000Z",
        },
        {
          task_id: "T-low",
          target_domain: "scheduler-limit.example.com",
          surface_id: "surface:low",
          lens: "surface_scout",
          priority: "low",
          status: "queued",
          created_at: "2026-05-26T03:00:00.000Z",
        },
      ],
    },
  });

  assert.deepEqual(decision.selected_task_ids, ["T-high"]);
  assert.deepEqual(decision.skipped_task_ids, ["T-low"]);
  assert.deepEqual(decision.assignments[0].budget, { max_steps: 6, max_context_tokens: 24000 });
});
