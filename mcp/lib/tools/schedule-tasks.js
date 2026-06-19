"use strict";

const {
  assertNonEmptyString,
} = require("../validation.js");
const {
  SCHEDULER_DECISION_KIND_VALUES,
  scheduleTasksFromQueue,
} = require("../scheduler-decisions.js");

function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const options = {
    write: args.write == null ? true : args.write === true,
    decisionKind: args.decision_kind == null ? "schedule_work" : args.decision_kind,
    assignmentBatchId: args.assignment_batch_id == null ? null : args.assignment_batch_id,
  };
  if (args.max_assignments != null) options.maxAssignments = args.max_assignments;

  const decision = scheduleTasksFromQueue(domain, options);
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    scheduler_decision_id: decision.scheduler_decision_id,
    scheduler_decision_hash: decision.scheduler_decision_hash,
    assignment_batch_id: decision.assignment_batch_id,
    decision_kind: decision.decision_kind,
    queue_policy_hash: decision.queue_policy_hash,
    source_task_queue_hash: decision.source_task_queue_hash || null,
    selected_task_ids: decision.selected_task_ids,
    skipped_task_ids: decision.skipped_task_ids,
    assignment_count: decision.assignment_count,
  });
}

module.exports = Object.freeze({
  name: "bob_schedule_tasks",
  description:
    "Fold task-queue.json into a SchedulerDecision and append it to " +
    "scheduler-decisions.jsonl. Selection follows the QueuePolicy " +
    "(priority_order + max_parallel_tasks); the produced decision carries " +
    "scheduler_decision_id, assignment_batch_id, decision_kind, " +
    "queue_policy_hash, source_task_queue_hash, selected_task_ids[], " +
    "skipped_task_ids[], and the per-task assignment payloads. The wave " +
    "scheduler is a thin caller of this tool; downstream wave-internal verbs " +
    "consume assignment_batch_id rather than recomputing selection.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: {
        type: "string",
      },
      decision_kind: {
        type: "string",
        enum: [...SCHEDULER_DECISION_KIND_VALUES],
        description:
          "Caller surface for telemetry and integrity checks. Defaults to " +
          "schedule_work; wave-driven callers pass wave_start.",
      },
      max_assignments: {
        type: "integer",
        description:
          "Optional cap on the number of selected tasks; defaults to the " +
          "policy max_parallel_tasks.",
      },
      assignment_batch_id: {
        type: "string",
        description:
          "Optional caller-supplied assignment_batch_id; auto-generated when " +
          "omitted.",
      },
      write: {
        type: "boolean",
        description:
          "When true (default) the decision is appended to " +
          "scheduler-decisions.jsonl; when false the decision is computed and " +
          "returned without persistence.",
      },
    },
    required: ["target_domain"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["scheduler-decisions.jsonl"],
});
