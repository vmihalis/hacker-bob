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
const dashboard = require("../mcp/lib/dashboard.js");
const { sessionsRoot } = require("../mcp/lib/paths.js");
const update = require("../mcp/lib/update-check.js");

function usageText() {
  return `Usage:
  hacker-bob install <project-dir> [--adapter claude|codex|generic-mcp|kimi|opencode|all]
  hacker-bob update <project-dir> [--adapter claude|codex|generic-mcp|kimi|opencode|all]
  hacker-bob check-update <project-dir> [--json]
  hacker-bob doctor <project-dir> [--adapter claude|codex|generic-mcp|kimi|opencode|all] [--json]
  hacker-bob uninstall <project-dir> [--adapter claude|codex|generic-mcp|kimi|opencode|all] [--dry-run] [--yes] [--json]
  hacker-bob dashboard [--host 127.0.0.1] [--port 4873] [--repo-only] [--window-days 30] [--limit 50] [--json]

Installs Hacker Bob into one project directory per command. If --adapter is omitted,
Bob auto-selects based on (1) prior install metadata, (2) host env markers
($CLAUDE_PROJECT_DIR, $CODEX_HOME, $KIMI_PROJECT_DIR), (3) project files (.claude/, .codex/plugins/,
.agents/plugins/, .kimi/, opencode.json/.opencode/, .mcp.json), or (4) host CLI on PATH; the default host adapter is Claude.
The selected adapter and reason are logged to stderr; pass --adapter to override.
Use --adapter codex, --adapter generic-mcp, --adapter kimi, --adapter opencode, or --adapter all for other host surfaces.
Global npm install only adds this CLI to PATH; it does not install Bob into every project.
Uninstall defaults to dry-run; pass --yes to remove Bob-managed files and config entries.
Dashboard is a local read-only view over ~/bounty-agent-sessions; use --repo-only for OSS mode.`;
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

  if (command === "dashboard") {
    const options = dashboard.parseDashboardArgs(args);
    if (options.help) {
      process.stdout.write(`${dashboard.dashboardUsageText()}\n`);
      return;
    }
    if (options.json) {
      process.stdout.write(`${JSON.stringify(dashboard.buildDashboardSnapshot(options), null, 2)}\n`);
      return;
    }
    const started = await dashboard.startDashboardServer(options);
    process.stdout.write(`Hacker Bob dashboard listening on ${started.url}\n`);
    process.stdout.write(`Sessions root: ${sessionsRoot()}\n`);
    process.stdout.write("Press Ctrl+C to stop.\n");
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
