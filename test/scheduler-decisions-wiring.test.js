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
  appendSchedulerDecision,
  findSchedulerDecisionByAssignmentBatchId,
  normalizeSchedulerDecision,
  readCurrentTaskQueueHash,
  readSchedulerDecisions,
  scheduleTasksFromQueue,
} = require("../mcp/lib/scheduler-decisions.js");
const scheduleTasksTool = require("../mcp/lib/tools/schedule-tasks.js");
const {
  taskQueuePath,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-scheduler-decisions-wiring-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedFrontier(domain) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-28T03:00:00.000Z",
    surface_id: "surface:billing",
    payload: { title: "Billing API" },
  });
  appendFrontierEvent({
    target_domain: domain,
    kind: "frontier.enqueued",
    ts: "2026-05-28T03:00:01.000Z",
    surface_id: "surface:billing",
    frontier_item_id: "frontier:item:billing-1",
    payload: {
      lens: "control_check",
      priority: "critical",
      budget: { max_steps: 6, max_context_tokens: 24000 },
    },
  });
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-28T03:00:02.000Z",
    surface_id: "surface:account",
    payload: { title: "Account API" },
  });
  appendFrontierEvent({
    target_domain: domain,
    kind: "frontier.enqueued",
    ts: "2026-05-28T03:00:03.000Z",
    surface_id: "surface:account",
    frontier_item_id: "frontier:item:account-1",
    payload: {
      lens: "behavior_probe",
      priority: "high",
      budget: { max_steps: 6, max_context_tokens: 24000 },
    },
  });
}

test("bob_schedule_tasks appends a SchedulerDecision row with the expected fields", () => {
  withTempHome(() => {
    const domain = "schedule-tasks-tool.example.com";
    seedFrontier(domain);
    materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-28T03:00:10.000Z"),
    });

    const result = JSON.parse(scheduleTasksTool.handler({
      target_domain: domain,
      decision_kind: "wave_start",
    }));

    assert.equal(result.target_domain, domain);
    assert.equal(result.decision_kind, "wave_start");
    assert.match(result.scheduler_decision_id, /^SD-[0-9a-f]{24}$/);
    assert.match(result.assignment_batch_id, /^AB-[0-9a-f]{24}$/);
    assert.match(result.queue_policy_hash, /^[0-9a-f]{64}$/);
    assert.deepEqual(result.selected_task_ids.length > 0, true);

    const persisted = readSchedulerDecisions(domain);
    assert.equal(persisted.length, 1);
    const row = persisted[0];
    assert.equal(row.scheduler_decision_id, result.scheduler_decision_id);
    assert.equal(row.assignment_batch_id, result.assignment_batch_id);
    assert.equal(row.decision_kind, "wave_start");
    assert.equal(row.target_domain, domain);
    assert.equal(typeof row.source_task_queue_hash, "string");
    assert.equal(row.queue_policy_hash, result.queue_policy_hash);
    assert.equal(row.selected_task_ids.length, result.selected_task_ids.length);
    assert.equal(row.skipped_task_ids.length, result.skipped_task_ids.length);
    assert.match(row.scheduler_decision_hash, /^[0-9a-f]{64}$/);
  });
});

test("queue-hash drift after the decision is detectable via findSchedulerDecisionByAssignmentBatchId + readCurrentTaskQueueHash", () => {
  withTempHome(() => {
    const domain = "schedule-tasks-drift.example.com";
    seedFrontier(domain);
    materializeFrontier(domain, {
      write: true,
      now: new Date("2026-05-28T04:00:00.000Z"),
    });

    const decision = scheduleTasksFromQueue(domain, {
      write: true,
      decisionKind: "wave_start",
      now: new Date("2026-05-28T04:00:01.000Z"),
    });
    const originalQueueHash = readCurrentTaskQueueHash(domain);
    assert.equal(originalQueueHash, decision.source_task_queue_hash);

    // Mutate task-queue.json AFTER the decision so a re-schedule from the same
    // decision_id surfaces queue-hash drift. We rewrite the file with a
    // changed task_queue_hash literal — the drift detector compares stored
    // source_task_queue_hash on the SchedulerDecision row against the current
    // task_queue.json hash.
    const queuePath = taskQueuePath(domain);
    const queueDoc = JSON.parse(fs.readFileSync(queuePath, "utf8"));
    queueDoc.task_queue_hash = "f".repeat(64);
    queueDoc.tasks = (queueDoc.tasks || []).map((task) => ({
      ...task,
      status: "queued",
      created_at: "2026-05-28T05:00:00.000Z",
    }));
    fs.writeFileSync(queuePath, `${JSON.stringify(queueDoc, null, 2)}\n`);

    const driftedQueueHash = readCurrentTaskQueueHash(domain);
    assert.notEqual(driftedQueueHash, decision.source_task_queue_hash);

    const ledgerRow = findSchedulerDecisionByAssignmentBatchId(domain, decision.assignment_batch_id);
    assert.ok(ledgerRow, "stored decision should be locatable by assignment_batch_id");
    assert.equal(ledgerRow.scheduler_decision_id, decision.scheduler_decision_id);
    assert.notEqual(ledgerRow.source_task_queue_hash, driftedQueueHash);

    // Re-schedule from the same decision_id (caller passes the original
    // assignment_batch_id) — confirm the new decision is also written and the
    // ledger preserves both rows. The drift is detectable by comparing
    // ledgerRow.source_task_queue_hash against the current queue hash.
    const reScheduled = scheduleTasksFromQueue(domain, {
      write: true,
      decisionKind: "wave_start",
      assignmentBatchId: decision.assignment_batch_id,
      now: new Date("2026-05-28T04:00:02.000Z"),
    });
    assert.equal(reScheduled.assignment_batch_id, decision.assignment_batch_id);
    assert.equal(reScheduled.source_task_queue_hash, driftedQueueHash);

    const allDecisions = readSchedulerDecisions(domain);
    assert.equal(allDecisions.length, 2);
    assert.notEqual(allDecisions[0].source_task_queue_hash, allDecisions[1].source_task_queue_hash);
  });
});

test("scheduler_decision_id and assignment_batch_id are stable for the same selection input", () => {
  // Determinism check: a decision normalized from the same canonical inputs
  // produces the same scheduler_decision_id, scheduler_decision_hash, and
  // assignment_batch_id. Important for the append-only ledger's auditability.
  const a = normalizeSchedulerDecision({
    target_domain: "stable-decision.example.com",
    created_at: "2026-05-28T06:00:00.000Z",
    decision_kind: "wave_start",
    policy: { max_parallel_tasks: 4 },
    source_task_queue_hash: "a".repeat(64),
    skipped_task_ids: ["T-skipped"],
    assignments: [
      {
        task_id: "T-1",
        target_domain: "stable-decision.example.com",
        surface_id: "surface:s1",
        task_lens: "surface_scout",
        priority: "high",
      },
    ],
  }, { targetDomain: "stable-decision.example.com" });
  const b = normalizeSchedulerDecision({
    target_domain: "stable-decision.example.com",
    created_at: "2026-05-28T06:00:00.000Z",
    decision_kind: "wave_start",
    policy: { max_parallel_tasks: 4 },
    source_task_queue_hash: "a".repeat(64),
    skipped_task_ids: ["T-skipped"],
    assignments: [
      {
        task_id: "T-1",
        target_domain: "stable-decision.example.com",
        surface_id: "surface:s1",
        task_lens: "surface_scout",
        priority: "high",
      },
    ],
  }, { targetDomain: "stable-decision.example.com" });
  assert.equal(a.scheduler_decision_id, b.scheduler_decision_id);
  assert.equal(a.scheduler_decision_hash, b.scheduler_decision_hash);
  assert.equal(a.assignment_batch_id, b.assignment_batch_id);
});

test("appendSchedulerDecision validates decision_kind against the enum", () => {
  withTempHome(() => {
    assert.throws(
      () => appendSchedulerDecision({
        target_domain: "bad-kind.example.com",
        created_at: "2026-05-28T07:00:00.000Z",
        decision_kind: "scribble",
        policy: {},
        assignments: [],
      }),
      /decision_kind must be one of/,
    );
  });
});
