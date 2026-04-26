#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  mcpPermissionForTool,
  permissionsForRoleBundle,
} = require("../adapters/claude/config.js");
const {
  CLAUDE_ROLE_SPECS,
  claudeAllowedToolsForRole,
  updateClaudeRoleFile,
} = require("./lib/claude-role-renderer.js");

const ROOT = path.join(__dirname, "..");
const AGENTS_DIR = path.join(ROOT, ".claude", "agents");

const AGENT_TOOL_SPECS = Object.freeze({
  "hunter-agent.md": {
    roleId: "hunter",
    roleBundles: ["hunter"],
    extras: ["Bash", "Read", "Grep", "Glob"],
  },
  "brutalist-verifier.md": {
    roleId: "brutalist-verifier",
    roleBundles: ["verifier"],
    extras: ["Bash", "Read"],
  },
  "balanced-verifier.md": {
    roleId: "balanced-verifier",
    roleBundles: ["verifier"],
    extras: ["Bash", "Read"],
  },
  "final-verifier.md": {
    roleId: "final-verifier",
    roleBundles: ["verifier"],
    extras: ["Bash"],
  },
  "grader.md": {
    roleId: "grader",
    roleBundles: ["grader"],
    extras: [],
  },
  "chain-builder.md": {
    roleId: "chain",
    roleBundles: ["chain"],
    extras: ["Write"],
  },
  "report-writer.md": {
    roleId: "reporter",
    roleBundles: ["reporter"],
    extras: ["Write"],
  },
});

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

function toolsForSpec(spec) {
  if (spec.roleId && CLAUDE_ROLE_SPECS[spec.roleId]) {
    return claudeAllowedToolsForRole(spec.roleId);
  }
  return uniqueStrings([
    ...spec.extras,
    ...spec.roleBundles.flatMap((roleBundle) => permissionsForRoleBundle(roleBundle)),
  ]);
}

function replaceToolsLine(document, tools) {
  const nextLine = `tools: ${tools.join(", ")}`;
  if (!/^---\n/.test(document)) {
    throw new Error("agent file is missing YAML frontmatter");
  }
  const frontmatterEnd = document.indexOf("\n---\n", 4);
  if (frontmatterEnd === -1) {
    throw new Error("agent file is missing YAML frontmatter terminator");
  }
  const frontmatter = document.slice(0, frontmatterEnd + 1);
  if (!/^tools: .*$/m.test(frontmatter)) {
    throw new Error("agent frontmatter is missing tools line");
  }
  return document.replace(/^tools: .*$/m, nextLine);
}

function updateAgentFile(fileName, { check = false } = {}) {
  const roleId = AGENT_TOOL_SPECS[fileName] && AGENT_TOOL_SPECS[fileName].roleId;
  if (roleId) return updateClaudeRoleFile(roleId, { check, root: ROOT });

  const filePath = path.join(AGENTS_DIR, fileName);
  const document = fs.readFileSync(filePath, "utf8");
  const nextDocument = replaceToolsLine(document, toolsForSpec(AGENT_TOOL_SPECS[fileName]));
  if (nextDocument === document) {
    return false;
  }
  if (check) {
    throw new Error(`${path.relative(ROOT, filePath)} tools frontmatter is stale`);
  }
  fs.writeFileSync(filePath, nextDocument, "utf8");
  return true;
}

function main() {
  const check = process.argv.includes("--check");
  let changed = false;
  for (const fileName of Object.keys(AGENT_TOOL_SPECS)) {
    changed = updateAgentFile(fileName, { check }) || changed;
  }
  if (!check && changed) {
    console.log("updated agent tools frontmatter");
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message || String(error));
    process.exit(1);
  }
}

module.exports = {
  AGENT_TOOL_SPECS,
  toolsForSpec,
  updateAgentFile,
  mcpPermissionForTool,
};
