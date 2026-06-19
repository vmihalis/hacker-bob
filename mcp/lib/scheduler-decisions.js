"use strict";

const fs = require("fs");
const {
  assertSafeDomain,
  schedulerDecisionsJsonlPath,
  taskQueuePath,
} = require("./paths.js");
const {
  appendJsonlLine,
  readJsonFile,
  withSessionLock,
} = require("./storage.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalObject,
  normalizePositiveInteger,
  readJsonlStrict,
  withDocumentHash,
} = require("./fabric-common.js");
const {
  normalizeTaskLens,
} = require("./task-lenses.js");
const {
  compareQueuedTasks,
  normalizeQueuePolicy,
  normalizeTaskPriority,
} = require("./queue-policy.js");
const {
  normalizeTaskBudget,
} = require("./tasks.js");

const SCHEDULER_DECISION_VERSION = 1;
const SCHEDULER_DECISIONS_MAX_RECORDS = 10000;
const DEFAULT_ASSIGNMENT_BUDGET = Object.freeze({
  max_steps: 6,
  max_context_tokens: 24000,
});

// Decision kinds describe the scheduling caller surface so downstream consumers
// (wave-merge integrity checks, telemetry, debug) can distinguish a wave-driven
// scheduler call from a direct operator dispatch.
//
// Plane X Cycle X.9 extends this enum with `schedule_graph_nodes` — the
// graph-walking scheduler's decision kind. The wave-driven kinds
// (schedule_work, wave_start, manual_dispatch) keep their task-shaped
// payload; the graph-scheduler-driven kind carries a node-shaped payload
// normalized through `normalizeGraphSchedulerDecision` (separate
// normalizer; same JSONL ledger). The kind discriminator routes both
// at-rest reads and at-append-time normalization.
const SCHEDULER_DECISION_KIND_VALUES = Object.freeze([
  "schedule_work",
  "wave_start",
  "manual_dispatch",
  "schedule_graph_nodes",
]);

// Graph-decision kinds. Any decision with `decision_kind` in this set
// is routed through `normalizeGraphSchedulerDecision` rather than the
// task-shaped `normalizeSchedulerDecision`. The split keeps two
// orthogonal shapes on the same ledger without forcing one shape to
// accommodate fields the other doesn't carry (task vs node).
const GRAPH_SCHEDULER_DECISION_KIND_VALUES = Object.freeze([
  "schedule_graph_nodes",
]);

function isGraphSchedulerDecisionKind(value) {
  return typeof value === "string"
    && GRAPH_SCHEDULER_DECISION_KIND_VALUES.includes(value);
}

function normalizeSchedulerDecisionKind(value, fieldName = "decision_kind") {
  if (value == null) return "schedule_work";
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  const trimmed = value.trim();
  if (!SCHEDULER_DECISION_KIND_VALUES.includes(trimmed)) {
    throw new Error(`${fieldName} must be one of ${SCHEDULER_DECISION_KIND_VALUES.join(", ")}`);
  }
  return trimmed;
}

function generatedSchedulerDecisionId(fields) {
  return `SD-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function generatedAssignmentBatchId(fields) {
  return `AB-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function generatedAssignmentId(fields) {
  return `A-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function normalizeAssignmentBudget(value) {
  return normalizeTaskBudget(value) || { ...DEFAULT_ASSIGNMENT_BUDGET };
}

function readTaskQueueDocument(domain) {
  const filePath = taskQueuePath(domain);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing task queue: ${filePath}`);
  }
  const document = readJsonFile(filePath, { label: "task-queue.json" });
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error(`Malformed task queue: ${filePath} (expected object)`);
  }
  if (!Array.isArray(document.tasks)) {
    throw new Error(`Malformed task queue: ${filePath} (tasks must be an array)`);
  }
  return document;
}

function normalizeSchedulerAssignment(input, { targetDomain, createdAt, index }) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("scheduler assignment must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const taskId = normalizeId(input.task_id, "task_id");
  const surfaceId = normalizeId(input.surface_id, "surface_id");
  const taskLens = normalizeTaskLens(input.task_lens || input.lens);
  const budget = normalizeAssignmentBudget(input.budget);
  const agent = normalizeId(input.agent || `a${index + 1}`, "agent");
  const priority = normalizeTaskPriority(input.priority);
  const assignmentBase = {
    version: 1,
    target_domain: domain,
    assignment_id: normalizeOptionalId(input.assignment_id, "assignment_id")
      || generatedAssignmentId({
        target_domain: domain,
        task_id: taskId,
        agent,
        created_at: createdAt,
      }),
    task_id: taskId,
    surface_id: surfaceId,
    task_lens: taskLens,
    budget,
    agent,
    priority,
    status: input.status || "assigned",
    created_at: createdAt,
  };
  const frontierItemId = normalizeOptionalId(input.frontier_item_id, "frontier_item_id");
  const sourceEventId = normalizeOptionalId(input.source_event_id, "source_event_id");
  const contextSlice = normalizeOptionalObject(input.context_slice, "context_slice");
  if (frontierItemId) assignmentBase.frontier_item_id = frontierItemId;
  if (sourceEventId) assignmentBase.source_event_id = sourceEventId;
  if (contextSlice) assignmentBase.context_slice = contextSlice;
  return withDocumentHash(assignmentBase, "assignment_hash");
}

function taskToSchedulerAssignment(task, { targetDomain, createdAt, index }) {
  return normalizeSchedulerAssignment({
    target_domain: targetDomain,
    task_id: task.task_id,
    surface_id: task.surface_id,
    task_lens: task.lens,
    budget: task.budget,
    priority: task.priority,
    frontier_item_id: task.frontier_item_id,
    source_event_id: task.source_event_id,
    context_slice: {
      version: 1,
      task_id: task.task_id,
      surface_id: task.surface_id,
      task_lens: task.lens,
      projection_refs: [
        { kind: "surface_index" },
        { kind: "task_queue" },
      ],
    },
  }, { targetDomain, createdAt, index });
}

function normalizeSchedulerDecision(input, { targetDomain = null, now = new Date() } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("scheduler decision must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const createdAt = normalizeIsoTimestamp(input.created_at || input.ts, "created_at", now);
  const policy = normalizeQueuePolicy(input.policy || {});
  const decisionKind = normalizeSchedulerDecisionKind(input.decision_kind);
  const assignments = Array.isArray(input.assignments)
    ? input.assignments.map((assignment, index) =>
        normalizeSchedulerAssignment(assignment, { targetDomain: domain, createdAt, index }))
    : [];
  const selectedTaskIds = assignments.map((assignment) => assignment.task_id);
  const skippedTaskIds = Array.isArray(input.skipped_task_ids)
    ? input.skipped_task_ids.map((taskId, index) => normalizeId(taskId, `skipped_task_ids[${index}]`))
    : [];
  const sourceQueueHash = normalizeOptionalId(input.source_task_queue_hash, "source_task_queue_hash");
  // queue_policy_hash is hash-of-policy at decision time. If absent, compute a
  // deterministic digest of the normalized policy via withDocumentHash so the
  // ledger row can be reasoned about against the queue-policy.json at-rest
  // hash later.
  const queuePolicyHash = normalizeOptionalId(input.queue_policy_hash, "queue_policy_hash")
    || withDocumentHash({ ...policy }, "queue_policy_hash").queue_policy_hash;
  const assignmentBatchId = normalizeOptionalId(input.assignment_batch_id, "assignment_batch_id")
    || generatedAssignmentBatchId({
      target_domain: domain,
      created_at: createdAt,
      selected_task_ids: selectedTaskIds,
      source_task_queue_hash: sourceQueueHash,
    });
  const decision = {
    version: SCHEDULER_DECISION_VERSION,
    target_domain: domain,
    created_at: createdAt,
    decision_kind: decisionKind,
    policy,
    queue_policy_hash: queuePolicyHash,
    assignment_batch_id: assignmentBatchId,
    selected_task_ids: selectedTaskIds,
    skipped_task_ids: skippedTaskIds,
    assignment_count: assignments.length,
    assignments,
  };
  if (sourceQueueHash) decision.source_task_queue_hash = sourceQueueHash;
  const decisionId = normalizeOptionalId(input.scheduler_decision_id, "scheduler_decision_id")
    || generatedSchedulerDecisionId({
      target_domain: domain,
      created_at: createdAt,
      decision_kind: decisionKind,
      selected_task_ids: selectedTaskIds,
      skipped_task_ids: skippedTaskIds,
      source_task_queue_hash: sourceQueueHash,
      assignment_batch_id: assignmentBatchId,
    });
  return withDocumentHash({
    scheduler_decision_id: decisionId,
    ...decision,
  }, "scheduler_decision_hash");
}

function scheduleTasksFromQueue(targetDomain, {
  taskQueue = null,
  maxAssignments = null,
  now = new Date(),
  write = false,
  decisionKind = "schedule_work",
  assignmentBatchId = null,
} = {}) {
  const domain = assertSafeDomain(targetDomain);
  const queue = taskQueue || readTaskQueueDocument(domain);
  const createdAt = normalizeIsoTimestamp(now, "created_at", null);
  const policy = normalizeQueuePolicy(queue.policy || {});
  const limit = normalizePositiveInteger(maxAssignments, "max_assignments", {
    defaultValue: policy.max_parallel_tasks,
    max: 128,
  });
  const runnable = (Array.isArray(queue.tasks) ? queue.tasks : [])
    .filter((task) => task && task.status === "queued")
    .sort((a, b) => compareQueuedTasks(a, b, policy));
  const selected = runnable.slice(0, limit);
  const skipped = runnable.slice(limit);
  const decision = normalizeSchedulerDecision({
    target_domain: domain,
    created_at: createdAt,
    policy,
    decision_kind: decisionKind,
    assignment_batch_id: assignmentBatchId,
    source_task_queue_hash: queue.task_queue_hash,
    skipped_task_ids: skipped.map((task) => task.task_id),
    assignments: selected.map((task, index) =>
      taskToSchedulerAssignment(task, { targetDomain: domain, createdAt, index })),
  }, { targetDomain: domain, now: new Date(createdAt) });

  if (write) {
    appendSchedulerDecision(decision);
  }
  return decision;
}

// Recompute a SchedulerDecision against the current task-queue.json to detect
// drift between the time a decision was recorded and a later wave merge. The
// helper does NOT mutate the ledger; callers (apply-wave-merge integrity
// check) use it to compare the live queue hash against the stored
// source_task_queue_hash and decide whether to log a warning during the dual-
// write window.
function readCurrentTaskQueueHash(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const queue = readTaskQueueDocument(domain);
  if (typeof queue.task_queue_hash === "string" && queue.task_queue_hash) {
    return queue.task_queue_hash;
  }
  return null;
}

function findSchedulerDecisionById(targetDomain, schedulerDecisionId) {
  if (!schedulerDecisionId) return null;
  const decisions = readSchedulerDecisions(targetDomain);
  for (let i = decisions.length - 1; i >= 0; i -= 1) {
    if (decisions[i] && decisions[i].scheduler_decision_id === schedulerDecisionId) {
      return decisions[i];
    }
  }
  return null;
}

function findSchedulerDecisionByAssignmentBatchId(targetDomain, assignmentBatchId) {
  if (!assignmentBatchId) return null;
  const decisions = readSchedulerDecisions(targetDomain);
  for (let i = decisions.length - 1; i >= 0; i -= 1) {
    if (decisions[i] && decisions[i].assignment_batch_id === assignmentBatchId) {
      return decisions[i];
    }
  }
  return null;
}

function appendSchedulerDecision(input, options = {}) {
  const decision = normalizeSchedulerDecision(input, options);
  return withSessionLock(decision.target_domain, () => {
    appendJsonlLine(schedulerDecisionsJsonlPath(decision.target_domain), decision, {
      maxRecords: options.maxRecords == null ? SCHEDULER_DECISIONS_MAX_RECORDS : options.maxRecords,
    });
    return decision;
  });
}

// X.9 — GraphSchedulerDecision shape.
//
// {
//   version: 1,
//   target_domain,
//   created_at,
//   decision_kind: "schedule_graph_nodes",
//   source_graph_hash,         // sha256 of materialized task-graph at selection
//   selected_node_ids: [TG-...],
//   skipped_node_ids: [TG-...],
//   capacity_used,             // count actually selected (≤ capacity_limit)
//   capacity_limit,            // configured cap at selection time
//   policy,                    // normalized queue_policy snapshot
//   queue_policy_hash,         // deterministic digest of policy
//   considered_count,          // total eligible candidates before capacity cap
//   selected_nodes: [{node_id, kind, state, priority, severity_floor, ts_first}],
//   skipped_nodes:  [{node_id, kind, state, priority, severity_floor, ts_first}],
// } + scheduler_decision_id + scheduler_decision_hash (document hash).
//
// Lives on the SAME scheduler-decisions.jsonl ledger as task decisions;
// reads route through the kind discriminator so the two shapes coexist
// without collision.
function generatedGraphSchedulerDecisionId(fields) {
  return `GSD-${hashCanonicalJson(fields).slice(0, 24)}`;
}

// Like normalizePositiveInteger but accepts 0 (the X.9 GraphSchedulerDecision
// records empty selections — capacity_used and considered_count can both be
// zero). Validates the type + range and rejects floats / negatives. The
// helper is local to the graph-decision normalizer because no other shape
// in this module needs the non-negative-integer shape today.
function normalizeNonNegativeInteger(value, fieldName, { defaultValue = 0, max = undefined } = {}) {
  if (value == null) return defaultValue;
  if (typeof value !== "number" || !Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
    throw new Error(`${fieldName} must be a non-negative integer (received: ${String(value)})`);
  }
  if (max != null && value > max) {
    throw new Error(`${fieldName} must be ≤ ${max} (received: ${value})`);
  }
  return value;
}

function normalizeNodeIdArray(input, fieldName) {
  if (input == null) return [];
  if (!Array.isArray(input)) {
    throw new Error(`${fieldName} must be an array`);
  }
  return input.map((value, index) => normalizeId(value, `${fieldName}[${index}]`));
}

function normalizeSelectedNodeRecords(input, fieldName) {
  if (input == null) return [];
  if (!Array.isArray(input)) {
    throw new Error(`${fieldName} must be an array`);
  }
  return input.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${fieldName}[${index}] must be an object`);
    }
    const out = {
      node_id: normalizeId(entry.node_id, `${fieldName}[${index}].node_id`),
      kind: typeof entry.kind === "string" && entry.kind.trim() ? entry.kind.trim() : null,
      state: typeof entry.state === "string" && entry.state.trim() ? entry.state.trim() : null,
      priority: typeof entry.priority === "string" && entry.priority.trim()
        ? entry.priority.trim()
        : "medium",
    };
    if (entry.severity_floor != null) {
      out.severity_floor = typeof entry.severity_floor === "string"
        ? entry.severity_floor.trim() || null
        : null;
    }
    if (entry.ts_first != null) {
      out.ts_first = typeof entry.ts_first === "string" ? entry.ts_first : null;
    }
    return out;
  });
}

function normalizeGraphSchedulerDecision(input, { targetDomain = null, now = new Date() } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("graph scheduler decision must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const createdAt = normalizeIsoTimestamp(input.created_at || input.ts, "created_at", now);
  const decisionKind = normalizeSchedulerDecisionKind(input.decision_kind || "schedule_graph_nodes");
  if (!isGraphSchedulerDecisionKind(decisionKind)) {
    throw new Error(
      `decision_kind must be one of ${GRAPH_SCHEDULER_DECISION_KIND_VALUES.join(", ")} `
      + `for graph scheduler decisions (received: ${decisionKind})`,
    );
  }
  const policy = normalizeQueuePolicy(input.policy || {});
  const queuePolicyHash = normalizeOptionalId(input.queue_policy_hash, "queue_policy_hash")
    || withDocumentHash({ ...policy }, "queue_policy_hash").queue_policy_hash;
  const sourceGraphHash = normalizeOptionalId(input.source_graph_hash, "source_graph_hash");
  if (!sourceGraphHash) {
    throw new Error("source_graph_hash is required for graph scheduler decisions");
  }
  const selectedNodes = normalizeSelectedNodeRecords(input.selected_nodes, "selected_nodes");
  const skippedNodes = normalizeSelectedNodeRecords(input.skipped_nodes, "skipped_nodes");
  const selectedNodeIds = input.selected_node_ids != null
    ? normalizeNodeIdArray(input.selected_node_ids, "selected_node_ids")
    : selectedNodes.map((entry) => entry.node_id);
  const skippedNodeIds = input.skipped_node_ids != null
    ? normalizeNodeIdArray(input.skipped_node_ids, "skipped_node_ids")
    : skippedNodes.map((entry) => entry.node_id);
  // Cross-check the bag of ids against the node detail records when both
  // are present so a malformed caller cannot record selected_node_ids
  // that disagree with selected_nodes[].node_id.
  if (input.selected_node_ids != null && selectedNodes.length > 0) {
    const detailIds = selectedNodes.map((entry) => entry.node_id);
    if (JSON.stringify(detailIds) !== JSON.stringify(selectedNodeIds)) {
      throw new Error("selected_node_ids must match selected_nodes[].node_id ordering");
    }
  }

  // capacity_limit must be ≥1 (you can't schedule with zero capacity).
  const capacityLimit = normalizePositiveInteger(
    input.capacity_limit,
    "capacity_limit",
    { defaultValue: policy.max_parallel_tasks, max: 128 },
  );
  // capacity_used and considered_count CAN be zero (empty selections
  // are a useful telemetry signal — the scheduler ran and found nothing
  // to dispatch). normalizePositiveInteger refuses 0 so we use a
  // non-negative helper.
  const capacityUsed = normalizeNonNegativeInteger(
    input.capacity_used,
    "capacity_used",
    { defaultValue: selectedNodeIds.length, max: capacityLimit },
  );
  if (capacityUsed !== selectedNodeIds.length) {
    throw new Error(
      `capacity_used (${capacityUsed}) must equal selected_node_ids.length (${selectedNodeIds.length})`,
    );
  }
  const consideredCount = normalizeNonNegativeInteger(
    input.considered_count,
    "considered_count",
    { defaultValue: selectedNodeIds.length + skippedNodeIds.length, max: 100000 },
  );

  const decision = {
    version: SCHEDULER_DECISION_VERSION,
    target_domain: domain,
    created_at: createdAt,
    decision_kind: decisionKind,
    policy,
    queue_policy_hash: queuePolicyHash,
    source_graph_hash: sourceGraphHash,
    capacity_used: capacityUsed,
    capacity_limit: capacityLimit,
    considered_count: consideredCount,
    selected_node_ids: selectedNodeIds,
    skipped_node_ids: skippedNodeIds,
    selected_nodes: selectedNodes,
    skipped_nodes: skippedNodes,
  };

  const decisionId = normalizeOptionalId(input.scheduler_decision_id, "scheduler_decision_id")
    || generatedGraphSchedulerDecisionId({
      target_domain: domain,
      created_at: createdAt,
      decision_kind: decisionKind,
      source_graph_hash: sourceGraphHash,
      selected_node_ids: selectedNodeIds,
      skipped_node_ids: skippedNodeIds,
    });

  return withDocumentHash({
    scheduler_decision_id: decisionId,
    ...decision,
  }, "scheduler_decision_hash");
}

function appendGraphSchedulerDecision(input, options = {}) {
  const decision = normalizeGraphSchedulerDecision(input, options);
  return withSessionLock(decision.target_domain, () => {
    appendJsonlLine(schedulerDecisionsJsonlPath(decision.target_domain), decision, {
      maxRecords: options.maxRecords == null ? SCHEDULER_DECISIONS_MAX_RECORDS : options.maxRecords,
    });
    return decision;
  });
}

function normalizeAnySchedulerDecision(record, context = {}) {
  if (record && typeof record === "object" && isGraphSchedulerDecisionKind(record.decision_kind)) {
    return normalizeGraphSchedulerDecision(record, context);
  }
  return normalizeSchedulerDecision(record, context);
}

function readSchedulerDecisions(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return readJsonlStrict(
    schedulerDecisionsJsonlPath(domain),
    "scheduler-decisions.jsonl",
    (record) => normalizeAnySchedulerDecision(record, { targetDomain: domain, now: null }),
  );
}

function readGraphSchedulerDecisions(targetDomain) {
  return readSchedulerDecisions(targetDomain)
    .filter((decision) => isGraphSchedulerDecisionKind(decision.decision_kind));
}

module.exports = {
  DEFAULT_ASSIGNMENT_BUDGET,
  GRAPH_SCHEDULER_DECISION_KIND_VALUES,
  SCHEDULER_DECISIONS_MAX_RECORDS,
  SCHEDULER_DECISION_KIND_VALUES,
  SCHEDULER_DECISION_VERSION,
  appendGraphSchedulerDecision,
  appendSchedulerDecision,
  findSchedulerDecisionByAssignmentBatchId,
  findSchedulerDecisionById,
  generatedAssignmentBatchId,
  generatedAssignmentId,
  generatedGraphSchedulerDecisionId,
  generatedSchedulerDecisionId,
  isGraphSchedulerDecisionKind,
  normalizeAnySchedulerDecision,
  normalizeGraphSchedulerDecision,
  normalizeSchedulerAssignment,
  normalizeSchedulerDecision,
  normalizeSchedulerDecisionKind,
  readCurrentTaskQueueHash,
  readGraphSchedulerDecisions,
  readSchedulerDecisions,
  scheduleTasksFromQueue,
};
