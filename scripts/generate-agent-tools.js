#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const {
  mcpPermissionForTool,
  permissionsForRoleBundle,
} = require("../mcp/lib/claude-config.js");

const ROOT = path.join(__dirname, "..");
const AGENTS_DIR = path.join(ROOT, ".claude", "agents");

const AGENT_TOOL_SPECS = Object.freeze({
  "hunter-agent.md": {
    roleBundles: ["hunter"],
    extras: ["Bash", "Read", "Grep", "Glob"],
  },
  "brutalist-verifier.md": {
    roleBundles: ["verifier"],
    extras: ["Bash", "Read"],
  },
  "balanced-verifier.md": {
    roleBundles: ["verifier"],
    extras: ["Bash", "Read"],
  },
  "final-verifier.md": {
    roleBundles: ["verifier"],
    extras: ["Bash"],
  },
  "grader.md": {
    roleBundles: ["grader"],
    extras: [],
  },
  "chain-builder.md": {
    roleBundles: ["chain"],
    extras: [],
  },
  "report-writer.md": {
    roleBundles: ["reporter"],
    extras: ["Write"],
  },
});

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

function toolsForSpec(spec) {
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
