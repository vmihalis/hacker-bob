"use strict";

const fs = require("fs");
const {
  sessionDir,
  waveAssignmentsPath,
} = require("./paths.js");
const {
  assertNonEmptyString,
  parseAgentId,
} = require("./validation.js");
const {
  normalizeTaskLens,
} = require("./task-lenses.js");
const {
  normalizeTaskBudget,
} = require("./tasks.js");
const {
  readJsonFile,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  normalizeAssignmentRouteMetadata,
} = require("./capability-packs.js");

const DEFAULT_ASSIGNMENT_TASK_LENS = "surface_scout";
const DEFAULT_ASSIGNMENT_BUDGET = Object.freeze({
  max_steps: 6,
  max_context_tokens: 24000,
});

function normalizeAssignmentBudget(value) {
  return normalizeTaskBudget(value) || { ...DEFAULT_ASSIGNMENT_BUDGET };
}

function loadWaveAssignments(domain, waveNumber) {
  const dir = sessionDir(domain);
  const assignmentsPath = waveAssignmentsPath(domain, waveNumber);

  if (!fs.existsSync(assignmentsPath)) {
    throw new Error(`Missing assignment file: ${assignmentsPath}`);
  }

  const assignmentsDoc = readJsonFile(assignmentsPath);
  if (assignmentsDoc == null || typeof assignmentsDoc !== "object" || Array.isArray(assignmentsDoc)) {
    throw new Error(`Invalid assignment file: ${assignmentsPath}`);
  }
  if (assignmentsDoc.wave_number !== waveNumber) {
    throw new Error(`Assignment file wave_number mismatch in ${assignmentsPath}`);
  }
  if (!Array.isArray(assignmentsDoc.assignments)) {
    throw new Error(`Assignment file assignments must be an array in ${assignmentsPath}`);
  }
  const documentRequiresHandoffTokens = assignmentsDoc.handoff_tokens_required === true;

  const assignments = [];
  const assignmentByAgent = new Map();
  for (const assignment of assignmentsDoc.assignments) {
    if (assignment == null || typeof assignment !== "object" || Array.isArray(assignment)) {
      throw new Error(`Invalid assignment entry in ${assignmentsPath}`);
    }
    const agent = parseAgentId(assignment.agent);
    const surfaceId = assertNonEmptyString(assignment.surface_id, "surface_id");
    const taskLens = normalizeTaskLens(assignment.task_lens || assignment.lens || DEFAULT_ASSIGNMENT_TASK_LENS, "task_lens");
    const budget = normalizeAssignmentBudget(assignment.budget);
    const handoffTokenSha256 = typeof assignment.handoff_token_sha256 === "string" && assignment.handoff_token_sha256.trim()
      ? assignment.handoff_token_sha256.trim()
      : null;
    const handoffTokenRequired = documentRequiresHandoffTokens || assignment.handoff_token_required === true || !!handoffTokenSha256;
    // surface_type is captured at start_wave time from attack_surface.json
    // and persisted in the (MCP-owned) assignment file. The completion gate
    // reads from here, not from the agent-writable attack_surface.json.
    const surfaceType = typeof assignment.surface_type === "string" && assignment.surface_type.trim() !== ""
      ? assignment.surface_type.trim()
      : null;
    const routeMetadata = normalizeAssignmentRouteMetadata(assignment);
    if (assignmentByAgent.has(agent)) {
      throw new Error(`Duplicate assignment for ${agent} in ${assignmentsPath}`);
    }
    const normalizedAssignment = { agent, surface_id: surfaceId, task_lens: taskLens, budget, ...routeMetadata };
    if (handoffTokenSha256) normalizedAssignment.handoff_token_sha256 = handoffTokenSha256;
    if (handoffTokenRequired) normalizedAssignment.handoff_token_required = true;
    if (surfaceType) normalizedAssignment.surface_type = surfaceType;
    assignments.push(normalizedAssignment);
    assignmentByAgent.set(agent, normalizedAssignment);
  }

  const schedulerDecisionId = typeof assignmentsDoc.scheduler_decision_id === "string"
    && assignmentsDoc.scheduler_decision_id.trim()
    ? assignmentsDoc.scheduler_decision_id.trim()
    : null;
  const assignmentBatchId = typeof assignmentsDoc.assignment_batch_id === "string"
    && assignmentsDoc.assignment_batch_id.trim()
    ? assignmentsDoc.assignment_batch_id.trim()
    : null;
  return {
    dir,
    wave: `w${waveNumber}`,
    assignmentsPath,
    assignments,
    assignmentByAgent,
    scheduler_decision_id: schedulerDecisionId,
    assignment_batch_id: assignmentBatchId,
  };
}

function normalizeWaveAssignmentsInput(assignments) {
  if (!Array.isArray(assignments) || assignments.length === 0) {
    throw new Error("assignments must be a non-empty array");
  }

  const normalizedAssignments = [];
  const seenAgents = new Set();
  const seenSurfaceIds = new Set();

  for (const assignment of assignments) {
    if (assignment == null || typeof assignment !== "object" || Array.isArray(assignment)) {
      throw new Error("assignments entries must be objects");
    }

    const agent = parseAgentId(assignment.agent);
    const surfaceId = assertNonEmptyString(assignment.surface_id, "surface_id");
    const taskLens = normalizeTaskLens(assignment.task_lens || assignment.lens || DEFAULT_ASSIGNMENT_TASK_LENS, "task_lens");
    const budget = normalizeAssignmentBudget(assignment.budget);

    if (seenAgents.has(agent)) {
      throw new Error(`Duplicate assignment for ${agent}`);
    }
    if (seenSurfaceIds.has(surfaceId)) {
      throw new Error(`Duplicate surface_id in assignments: ${surfaceId}`);
    }

    seenAgents.add(agent);
    seenSurfaceIds.add(surfaceId);
    normalizedAssignments.push({ agent, surface_id: surfaceId, task_lens: taskLens, budget });
  }

  return normalizedAssignments;
}

function validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId) {
  const waveNumber = Number(wave.slice(1));
  const { assignmentByAgent } = loadWaveAssignments(domain, waveNumber);
  const assignment = assignmentByAgent.get(agent);
  if (!assignment) {
    throw new ToolError(ERROR_CODES.NOT_FOUND, `Agent ${agent} is not assigned in wave ${wave}`);
  }
  if (assignment.surface_id !== surfaceId) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `Agent ${agent} is assigned surface ${assignment.surface_id}, not ${surfaceId}`);
  }
  return assignment;
}

module.exports = {
  DEFAULT_ASSIGNMENT_BUDGET,
  DEFAULT_ASSIGNMENT_TASK_LENS,
  loadWaveAssignments,
  normalizeAssignmentBudget,
  normalizeWaveAssignmentsInput,
  validateAssignedWaveAgentSurface,
};
