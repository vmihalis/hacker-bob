#!/usr/bin/env node
"use strict";

const update = require("./bob-update-lib.js");

function usage() {
  console.error(`Usage:
  node .claude/hooks/bob-update.js plan <project-dir> [--json]
  node .claude/hooks/bob-update.js status <project-dir> [--json]
  node .claude/hooks/bob-update.js check-update <project-dir> [--json]
  node .claude/hooks/bob-update.js clear-cache <project-dir>`);
}

function firstNonFlag(args) {
  return args.find((arg) => !arg.startsWith("-"));
}

async function main(argv) {
  const [command = "plan", ...args] = argv;
  const projectDir = firstNonFlag(args) || process.env.CLAUDE_PROJECT_DIR || process.cwd();

  if (command === "plan") {
    const result = await update.checkForUpdate(projectDir, { includeChangelog: true });
    if (args.includes("--json")) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(update.renderUpdatePlan(result));
    }
    return;
  }

  if (command === "status") {
    const cache = update.readUpdateCache(projectDir);
    if (args.includes("--json")) {
      process.stdout.write(`${JSON.stringify(cache || null, null, 2)}\n`);
    } else {
      process.stdout.write(update.renderUpdateSummary(cache));
    }
    return;
  }

  if (command === "check-update") {
    const result = await update.checkForUpdate(projectDir, { includeChangelog: !args.includes("--no-changelog") });
    if (args.includes("--json")) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(update.renderUpdateSummary(result));
    }
    return;
  }

  if (command === "clear-cache") {
    update.clearUpdateCache(projectDir);
    console.log("Hacker Bob update cache cleared.");
    return;
  }

  usage();
  process.exit(1);
}

main(process.argv.slice(2)).catch((error) => {
  console.error(error && error.message ? error.message : String(error));
  process.exit(1);
});
