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
  readJsonFile,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");

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

  const assignments = [];
  const assignmentByAgent = new Map();
  for (const assignment of assignmentsDoc.assignments) {
    if (assignment == null || typeof assignment !== "object" || Array.isArray(assignment)) {
      throw new Error(`Invalid assignment entry in ${assignmentsPath}`);
    }
    const agent = parseAgentId(assignment.agent);
    const surfaceId = assertNonEmptyString(assignment.surface_id, "surface_id");
    const handoffTokenSha256 = typeof assignment.handoff_token_sha256 === "string" && assignment.handoff_token_sha256.trim()
      ? assignment.handoff_token_sha256.trim()
      : null;
    if (assignmentByAgent.has(agent)) {
      throw new Error(`Duplicate assignment for ${agent} in ${assignmentsPath}`);
    }
    const normalizedAssignment = handoffTokenSha256
      ? { agent, surface_id: surfaceId, handoff_token_sha256: handoffTokenSha256 }
      : { agent, surface_id: surfaceId };
    assignments.push(normalizedAssignment);
    assignmentByAgent.set(agent, normalizedAssignment);
  }

  return { dir, wave: `w${waveNumber}`, assignmentsPath, assignments, assignmentByAgent };
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

    if (seenAgents.has(agent)) {
      throw new Error(`Duplicate assignment for ${agent}`);
    }
    if (seenSurfaceIds.has(surfaceId)) {
      throw new Error(`Duplicate surface_id in assignments: ${surfaceId}`);
    }

    seenAgents.add(agent);
    seenSurfaceIds.add(surfaceId);
    normalizedAssignments.push({ agent, surface_id: surfaceId });
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
  loadWaveAssignments,
  normalizeWaveAssignmentsInput,
  validateAssignedWaveAgentSurface,
};
