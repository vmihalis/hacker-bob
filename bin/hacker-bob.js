#!/usr/bin/env node
"use strict";

const path = require("path");

const {
  installProject,
  printInstallSummary,
} = require("../scripts/install.js");
const update = require("../.claude/hooks/bob-update-lib.js");

function usageText() {
  return `Usage:
  hacker-bob install <project-dir>
  hacker-bob update <project-dir>
  hacker-bob check-update <project-dir> [--json]

Installs target exactly one Claude Code project directory per command.
Global npm install only adds this CLI to PATH; it does not install Bob into every project.`;
}

function usage(stream = process.stderr) {
  stream.write(`${usageText()}\n`);
}

function firstNonFlag(args) {
  return args.find((arg) => !arg.startsWith("-"));
}

async function main(argv) {
  const [command, ...args] = argv;
  if (!command || command === "-h" || command === "--help") {
    usage(command ? process.stdout : process.stderr);
    process.exit(command ? 0 : 1);
  }

  if (command === "install" || command === "update") {
    const projectDir = firstNonFlag(args);
    if (!projectDir) {
      usage();
      process.exit(1);
    }
    const source = args.includes("--source-install-sh") ? "install.sh" : command === "update" ? "cli-update" : "cli";
    const summary = installProject(path.resolve(projectDir), { installerSource: source });
    printInstallSummary(summary);
    if (command === "update") {
      update.clearUpdateCache(summary.targetAbs);
      console.log("");
      console.log("Update complete. Fully restart Claude Code in this project before continuing.");
    }
    return;
  }

  if (command === "check-update") {
    const projectDir = firstNonFlag(args);
    if (!projectDir) {
      usage();
      process.exit(1);
    }
    const result = await update.checkForUpdate(path.resolve(projectDir), {
      includeChangelog: !args.includes("--no-changelog"),
    });
    if (args.includes("--json")) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(update.renderUpdateSummary(result));
    }
    return;
  }

  usage();
  process.exit(1);
}

main(process.argv.slice(2)).catch((error) => {
  console.error(error && error.message ? error.message : String(error));
  process.exit(1);
});
