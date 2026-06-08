"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_ROOT = path.join(__dirname, "..", "..");
const CAPABILITY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const PLAYBOOK_DIR = path.join("prompts", "playbooks");

function normalizeCapabilityId(capabilityId) {
  if (typeof capabilityId !== "string" || !CAPABILITY_ID_PATTERN.test(capabilityId)) {
    throw new Error(`invalid capability_id: ${capabilityId}`);
  }
  return capabilityId;
}

function capabilityPlaybookPath(capabilityId, { root = DEFAULT_ROOT } = {}) {
  return path.join(root, PLAYBOOK_DIR, `${normalizeCapabilityId(capabilityId)}.md`);
}

function readCapabilityPlaybook(capabilityId, { root = DEFAULT_ROOT } = {}) {
  const normalizedCapabilityId = normalizeCapabilityId(capabilityId);
  const filePath = capabilityPlaybookPath(normalizedCapabilityId, { root });
  if (!fs.existsSync(filePath)) {
    throw new Error(`unknown capability playbook: ${normalizedCapabilityId}`);
  }
  return {
    capability_id: normalizedCapabilityId,
    path: path.relative(root, filePath),
    playbook: fs.readFileSync(filePath, "utf8").replace(/^\n+/, ""),
  };
}

function listCapabilityPlaybooks({ root = DEFAULT_ROOT } = {}) {
  const dirPath = path.join(root, PLAYBOOK_DIR);
  if (!fs.existsSync(dirPath)) return [];
  return fs.readdirSync(dirPath, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
    .map((entry) => entry.name.slice(0, -3))
    .filter((capabilityId) => CAPABILITY_ID_PATTERN.test(capabilityId))
    .sort()
    .map((capabilityId) => readCapabilityPlaybook(capabilityId, { root }));
}

function renderCapabilityPlaybookAppendix({ root = DEFAULT_ROOT } = {}) {
  const playbooks = listCapabilityPlaybooks({ root });
  if (playbooks.length === 0) return "";
  const sections = [
    "",
    "## Optional: Differential Workflows",
    "Orchestrator-driven differentials run outside the wave/evaluator loop and feed `severity_class: \"security\"` rows into `bob_record_candidate_claim`.",
  ];
  for (const { capability_id, playbook } of playbooks) {
    sections.push("", `### ${capability_id}`, playbook.trimEnd());
  }
  return sections.join("\n");
}

module.exports = {
  CAPABILITY_ID_PATTERN,
  capabilityPlaybookPath,
  listCapabilityPlaybooks,
  normalizeCapabilityId,
  readCapabilityPlaybook,
  renderCapabilityPlaybookAppendix,
};
