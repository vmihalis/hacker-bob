#!/usr/bin/env node
"use strict";

const path = require("path");

const {
  installProject,
  printInstallSummary,
} = require("../scripts/install.js");
const {
  doctorProject,
  printDoctorReport,
  printUninstallReport,
  uninstallProject,
} = require("../scripts/lifecycle.js");
const update = require("../mcp/lib/update-check.js");

function usageText() {
  return `Usage:
  hacker-bob install <project-dir> [--adapter claude|codex|generic-mcp|all]
  hacker-bob update <project-dir> [--adapter claude|codex|generic-mcp|all]
  hacker-bob check-update <project-dir> [--json]
  hacker-bob doctor <project-dir> [--adapter claude|codex|generic-mcp|all] [--json]
  hacker-bob uninstall <project-dir> [--adapter claude|codex|generic-mcp|all] [--dry-run] [--yes] [--json]

Installs Hacker Bob into one project directory per command. The default host adapter is Claude.
Use --adapter codex, --adapter generic-mcp, or --adapter all for other host surfaces.
Global npm install only adds this CLI to PATH; it does not install Bob into every project.
Uninstall defaults to dry-run; pass --yes to remove Bob-managed files and config entries.`;
}

function usage(stream = process.stderr) {
  stream.write(`${usageText()}\n`);
}

function parseArgs(args) {
  const parsed = {
    adapter: null,
    flags: new Set(),
    positionals: [],
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--adapter") {
      const value = args[index + 1];
      if (!value || value.startsWith("-")) throw new Error("--adapter requires a value");
      parsed.adapter = value;
      index += 1;
    } else if (arg.startsWith("--adapter=")) {
      parsed.adapter = arg.slice("--adapter=".length);
      if (!parsed.adapter) throw new Error("--adapter requires a value");
    } else if (arg.startsWith("-")) {
      parsed.flags.add(arg);
    } else {
      parsed.positionals.push(arg);
    }
  }
  return parsed;
}

async function main(argv) {
  const [command, ...args] = argv;
  if (!command || command === "-h" || command === "--help") {
    usage(command ? process.stdout : process.stderr);
    process.exit(command ? 0 : 1);
  }
  const parsed = parseArgs(args);

  if (command === "install" || command === "update") {
    const projectDir = parsed.positionals[0];
    if (!projectDir) {
      usage();
      process.exit(1);
    }
    const source = parsed.flags.has("--source-install-sh") ? "install.sh" : command === "update" ? "cli-update" : "cli";
    const summary = installProject(path.resolve(projectDir), {
      adapter: parsed.adapter,
      installerSource: source,
    });
    printInstallSummary(summary);
    if (command === "update") {
      update.clearUpdateCache(summary.targetAbs);
      console.log("");
      if (summary.adapters.length === 1 && summary.adapters[0] === "claude") {
        console.log("Update complete. Fully restart Claude Code in this project before continuing.");
      } else {
        console.log("Update complete. Restart the selected host adapter before continuing.");
      }
    }
    return;
  }

  if (command === "check-update") {
    const projectDir = parsed.positionals[0];
    if (!projectDir) {
      usage();
      process.exit(1);
    }
    const result = await update.checkForUpdate(path.resolve(projectDir), {
      includeChangelog: !parsed.flags.has("--no-changelog"),
    });
    if (parsed.flags.has("--json")) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(update.renderUpdateSummary(result));
    }
    return;
  }

  if (command === "doctor") {
    const projectDir = parsed.positionals[0];
    if (!projectDir) {
      usage();
      process.exit(1);
    }
    const result = doctorProject(path.resolve(projectDir), { adapter: parsed.adapter });
    if (parsed.flags.has("--json")) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      printDoctorReport(result);
    }
    if (!result.ok) process.exit(1);
    return;
  }

  if (command === "uninstall") {
    const projectDir = parsed.positionals[0];
    if (!projectDir) {
      usage();
      process.exit(1);
    }
    const dryRun = parsed.flags.has("--dry-run") || !parsed.flags.has("--yes");
    const result = uninstallProject(path.resolve(projectDir), {
      adapter: parsed.adapter,
      dryRun,
    });
    if (parsed.flags.has("--json")) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      printUninstallReport(result);
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
