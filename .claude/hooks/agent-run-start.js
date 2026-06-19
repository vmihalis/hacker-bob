#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

function readStdin() {
  try {
    return fs.readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function textFromValue(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(textFromValue).filter(Boolean).join("\n");
  if (!value || typeof value !== "object") return "";
  if (typeof value.text === "string") return value.text;
  if (typeof value.content === "string") return value.content;
  if (Array.isArray(value.content)) return textFromValue(value.content);
  if (typeof value.prompt === "string") return value.prompt;
  if (typeof value.message === "string") return value.message;
  return "";
}

// SubagentStart payloads vary by harness version. Claude Code surfaces the
// spawn prompt under tool_input.prompt; some adapters wrap it under a
// `subagent_request` key or as the top-level prompt string. Collect every
// candidate text so the marker regex can scan one unified blob.
function gatherSpawnText(payload) {
  if (!payload || typeof payload !== "object") return "";
  const parts = [];
  parts.push(textFromValue(payload.tool_input));
  parts.push(textFromValue(payload.subagent_request));
  parts.push(textFromValue(payload.prompt));
  parts.push(textFromValue(payload.spawn_prompt));
  parts.push(textFromValue(payload.input));
  parts.push(textFromValue(payload.message));
  return parts.filter(Boolean).join("\n");
}

// Evaluator spawn prompts (per bob-evaluate skill and agent contracts) always
// contain "Domain: <d>", "Wave: w<N>", "Agent: a<N>" lines. We do not parse
// surface_id from the spawn — the assignment file already pins surface_id by
// agent, and the AgentRun ledger row inserted at wave start carries the
// surface_id. The start hook only needs to mark `running` for the (domain,
// wave, agent) tuple. The SubagentStop hook fills in surface_id via the
// emitted BOB_AGENT_RUN_DONE marker.
function parseSpawnMarkers(text) {
  if (typeof text !== "string" || !text) return null;
  const domainMatch = text.match(/(?:^|\n)\s*Domain:\s*([^\s\n]+)/i)
    || text.match(/target_domain\s*[:=]\s*['"]?([A-Za-z0-9._-]+)['"]?/i);
  const waveMatch = text.match(/(?:^|\n)\s*Wave:\s*(w[1-9][0-9]*)/i)
    || text.match(/wave\s*[:=]\s*['"]?(w[1-9][0-9]*)['"]?/i);
  const agentMatch = text.match(/(?:^|\n)\s*Agent:\s*(a[1-9][0-9]*)/i)
    || text.match(/agent\s*[:=]\s*['"]?(a[1-9][0-9]*)['"]?/i);
  if (!domainMatch || !waveMatch || !agentMatch) return null;
  return {
    target_domain: domainMatch[1].trim(),
    wave: waveMatch[1].trim().toLowerCase(),
    agent: agentMatch[1].trim().toLowerCase(),
  };
}

function projectRoot() {
  return process.env.BOB_PROJECT_DIR || process.env.CLAUDE_PROJECT_DIR || path.resolve(__dirname, "..", "..");
}

function loadAgentRuns() {
  return require(path.join(projectRoot(), "mcp", "lib", "agent-runs.js"));
}

function loadAssignments() {
  return require(path.join(projectRoot(), "mcp", "lib", "assignments.js"));
}

// Look up the surface_id the orchestrator pinned to this agent at wave start.
// Returns null when the assignment file is missing or the agent is not
// listed (legacy session, pre-S.5 wave, or a non-evaluator subagent).
function lookupAssignmentSurfaceId({ targetDomain, wave, agent }) {
  if (!targetDomain || !wave || !agent) return null;
  let assignments;
  try {
    const { loadWaveAssignments } = loadAssignments();
    const waveNumber = Number(wave.slice(1));
    if (!Number.isInteger(waveNumber) || waveNumber < 1) return null;
    assignments = loadWaveAssignments(targetDomain, waveNumber);
  } catch {
    return null;
  }
  if (!assignments || !assignments.assignmentByAgent) return null;
  const assignment = assignments.assignmentByAgent.get(agent);
  return assignment && typeof assignment.surface_id === "string" ? assignment.surface_id : null;
}

function recordRunning({ targetDomain, wave, agent, surfaceId }) {
  try {
    const { markAgentRunRunning } = loadAgentRuns();
    markAgentRunRunning({
      targetDomain,
      wave,
      agent,
      surfaceId,
    });
    return true;
  } catch {
    return false;
  }
}

function main() {
  let payload = {};
  try {
    payload = JSON.parse(readStdin() || "{}");
  } catch {
    payload = {};
  }

  const spawnText = gatherSpawnText(payload);
  const markers = parseSpawnMarkers(spawnText);
  if (!markers) {
    // No identifiable wave/agent in the spawn prompt — likely a non-evaluator
    // subagent the matcher caught by mistake, or a free-form Task call. Exit
    // silently; the merge gate's file-presence fallback still protects us.
    process.exit(0);
  }

  const surfaceId = lookupAssignmentSurfaceId(markers);
  recordRunning({ ...markers, surfaceId });
  process.exit(0);
}

if (require.main === module) {
  try {
    main();
  } catch {
    // Hook failure must never block the subagent from starting. The ledger row
    // is best-effort; the merge gate's file-presence fallback (per Pact P2)
    // still catches missing settlement.
    process.exit(0);
  }
}

module.exports = {
  gatherSpawnText,
  parseSpawnMarkers,
  lookupAssignmentSurfaceId,
};
