"use strict";

const {
  assertSafeDomain,
} = require("./paths.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  normalizeOptionalText,
} = require("./validation.js");
const {
  normalizeId,
  normalizeIsoTimestamp,
  normalizeOptionalId,
  normalizeOptionalObject,
  normalizeOptionalTextArray,
  normalizePositiveInteger,
  normalizeReferenceArray,
  withDocumentHash,
} = require("./fabric-common.js");
const {
  normalizeTaskLens,
} = require("./task-lenses.js");
const {
  normalizeQueueStatus,
  normalizeTaskPriority,
} = require("./queue-policy.js");

const TASK_VERSION = 1;

function generatedTaskId(fields) {
  return `T-${hashCanonicalJson(fields).slice(0, 24)}`;
}

function normalizeTaskBudget(value) {
  if (value == null) return null;
  const budget = normalizeOptionalObject(value, "budget");
  const normalized = {};
  const maxSteps = normalizePositiveInteger(budget.max_steps, "budget.max_steps", { defaultValue: null });
  const maxMinutes = normalizePositiveInteger(budget.max_minutes, "budget.max_minutes", { defaultValue: null });
  const maxContextTokens = normalizePositiveInteger(budget.max_context_tokens, "budget.max_context_tokens", {
    defaultValue: null,
  });
  if (maxSteps != null) normalized.max_steps = maxSteps;
  if (maxMinutes != null) normalized.max_minutes = maxMinutes;
  if (maxContextTokens != null) normalized.max_context_tokens = maxContextTokens;
  return Object.keys(normalized).length > 0 ? normalized : null;
}

function normalizeTask(input, { targetDomain = null, now = new Date() } = {}) {
  if (input == null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("task must be an object");
  }
  const domain = assertSafeDomain(input.target_domain || targetDomain);
  const surfaceId = normalizeId(input.surface_id, "surface_id");
  const lens = normalizeTaskLens(input.lens);
  const priority = normalizeTaskPriority(input.priority);
  const createdAt = normalizeIsoTimestamp(input.created_at || input.ts, "created_at", now);
  const dedupeKey = normalizeOptionalText(input.dedupe_key, "dedupe_key");
  const taskId = normalizeOptionalId(input.task_id, "task_id")
    || generatedTaskId({
      target_domain: domain,
      surface_id: surfaceId,
      lens,
      dedupe_key: dedupeKey,
    });

  const task = {
    version: TASK_VERSION,
    task_id: taskId,
    target_domain: domain,
    surface_id: surfaceId,
    lens,
    priority,
    status: normalizeQueueStatus(input.status),
    created_at: createdAt,
  };

  const assignedAgent = normalizeOptionalText(input.assigned_agent, "assigned_agent");
  const assignmentId = normalizeOptionalId(input.assignment_id, "assignment_id");
  const sourceEventId = normalizeOptionalId(input.source_event_id, "source_event_id");
  const frontierItemId = normalizeOptionalId(input.frontier_item_id, "frontier_item_id");
  const summary = normalizeOptionalText(input.summary, "summary");
  const policyReason = normalizeOptionalText(input.policy_reason, "policy_reason");
  const budget = normalizeTaskBudget(input.budget);
  const tags = normalizeOptionalTextArray(input.tags, "tags");
  const blockerEventIds = normalizeOptionalTextArray(input.blocker_event_ids, "blocker_event_ids");
  const closureEventIds = normalizeOptionalTextArray(input.closure_event_ids, "closure_event_ids");
  const refs = normalizeReferenceArray(input.refs, "refs");
  const payload = normalizeOptionalObject(input.payload, "payload");

  if (assignedAgent) task.assigned_agent = assignedAgent;
  if (assignmentId) task.assignment_id = assignmentId;
  if (sourceEventId) task.source_event_id = sourceEventId;
  if (frontierItemId) task.frontier_item_id = frontierItemId;
  if (summary) task.summary = summary;
  if (policyReason) task.policy_reason = policyReason;
  if (budget) task.budget = budget;
  if (dedupeKey) task.dedupe_key = dedupeKey;
  if (tags.length > 0) task.tags = tags;
  if (blockerEventIds.length > 0) task.blocker_event_ids = blockerEventIds;
  if (closureEventIds.length > 0) task.closure_event_ids = closureEventIds;
  if (refs.length > 0) task.refs = refs;
  if (payload) task.payload = payload;

  return withDocumentHash(task, "task_hash");
}

function taskQueueKey(task) {
  return task.frontier_item_id || task.task_id;
}

module.exports = {
  TASK_VERSION,
  generatedTaskId,
  normalizeTask,
  normalizeTaskBudget,
  taskQueueKey,
};
