#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("path");

const {
  installProject,
  printInstallSummary,
  printPurgeLegacySessionRootReport,
  purgeLegacySessionRoot,
} = require("../scripts/install.js");
const {
  doctorProject,
  printDoctorReport,
  printUninstallReport,
  uninstallProject,
} = require("../scripts/lifecycle.js");
const {
  installOptionalProviderPackage,
  probeOptionalProviderPackage,
  uninstallOptionalProviderPackage,
  updateOptionalProviderPackage,
} = require("../scripts/lib/optional-provider-lifecycle.js");
const dashboard = require("../mcp/lib/dashboard.js");
const { sessionsRoot } = require("../mcp/lib/paths.js");
const update = require("../mcp/lib/update-check.js");

function usageText() {
  return `Usage:
  hacker-bob install <project-dir> [--adapter claude|codex|generic-mcp|kimi|all] [--purge-legacy-session-root [--include-legacy-telemetry] [--yes]]
  hacker-bob update <project-dir> [--adapter claude|codex|generic-mcp|kimi|all] [--purge-legacy-session-root [--include-legacy-telemetry] [--yes]]
  hacker-bob check-update <project-dir> [--json]
  hacker-bob doctor <project-dir> [--adapter claude|codex|generic-mcp|kimi|all] [--json]
  hacker-bob uninstall <project-dir> [--adapter claude|codex|generic-mcp|kimi|all] [--dry-run] [--yes] [--json]
  hacker-bob optional-provider <status|install|update|uninstall> <project-dir> --provider <id> --package <id> [--source <package-dir>] [--release-verification <json-file>] [--yes] [--json]
  hacker-bob dashboard [--host 127.0.0.1] [--port 4873] [--repo-only] [--window-days 30] [--limit 50] [--json]

Installs Hacker Bob into one project directory per command. If --adapter is omitted,
Bob auto-selects based on (1) prior install metadata, (2) host env markers
($CLAUDE_PROJECT_DIR, $CODEX_HOME, $KIMI_PROJECT_DIR), (3) project files (.claude/, .codex/plugins/,
.agents/plugins/, .kimi/, .mcp.json), or (4) host CLI on PATH; the default host adapter is Claude.
The selected adapter and reason are logged to stderr; pass --adapter to override.
Use --adapter codex, --adapter generic-mcp, --adapter kimi, or --adapter all for other host surfaces.
Global npm install only adds this CLI to PATH; it does not install Bob into every project.
Uninstall defaults to dry-run; pass --yes to remove Bob-managed files and config entries.
Optional-provider package operations are explicit, never activate a provider, and never probe hardware.
Install/update require --source; signed worker closures and native prebuilds additionally require
caller-supplied signed release verification JSON. Status accepts the same file to reverify the exact
installed closure as a non-authorizing diagnostic. Optional-provider uninstall defaults to dry-run
and requires --yes to remove.
--purge-legacy-session-root removes a leftover pre-v2.0 ~/bounty-agent-sessions root after the
install/update completes; it is dry-run unless --yes is passed, never touches the canonical
~/hacker-bob-sessions, and only removes ~/bounty-agent-telemetry when --include-legacy-telemetry is also passed.
Dashboard is a local read-only view over ~/hacker-bob-sessions; use --repo-only for OSS mode.`;
}

function usage(stream = process.stderr) {
  stream.write(`${usageText()}\n`);
}

function parseArgs(args) {
  const parsed = {
    adapter: null,
    package: null,
    provider: null,
    releaseVerification: null,
    source: null,
    flags: new Set(),
    positionals: [],
  };
  const valueOptions = new Map([
    ["--adapter", "adapter"],
    ["--package", "package"],
    ["--provider", "provider"],
    ["--release-verification", "releaseVerification"],
    ["--source", "source"],
  ]);
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (valueOptions.has(arg)) {
      const value = args[index + 1];
      if (!value || value.startsWith("-")) throw new Error(`${arg} requires a value`);
      parsed[valueOptions.get(arg)] = value;
      index += 1;
    } else if ([...valueOptions.keys()].some((name) => arg.startsWith(`${name}=`))) {
      const name = [...valueOptions.keys()].find((candidate) => arg.startsWith(`${candidate}=`));
      parsed[valueOptions.get(name)] = arg.slice(name.length + 1);
      if (!parsed[valueOptions.get(name)]) throw new Error(`${name} requires a value`);
    } else if (arg.startsWith("-")) {
      parsed.flags.add(arg);
    } else {
      parsed.positionals.push(arg);
    }
  }
  return parsed;
}

function readReleaseVerification(filePath, now) {
  if (!filePath) return null;
  const supplied = JSON.parse(fs.readFileSync(path.resolve(filePath), "utf8"));
  return {
    envelope: supplied && supplied.envelope,
    trust_policy: supplied && supplied.trust_policy,
    now,
  };
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
    if (parsed.flags.has("--purge-legacy-session-root")) {
      console.log("");
      const report = purgeLegacySessionRoot({
        dryRun: !parsed.flags.has("--yes"),
        confirmed: parsed.flags.has("--yes"),
        includeTelemetry: parsed.flags.has("--include-legacy-telemetry"),
      });
      printPurgeLegacySessionRootReport(report);
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
    if (!result.ok) process.exitCode = 1;
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

  if (command === "optional-provider") {
    const operation = parsed.positionals[0];
    const projectDir = parsed.positionals[1];
    if (!["status", "install", "update", "uninstall"].includes(operation)
        || !projectDir || !parsed.provider || !parsed.package) {
      usage();
      process.exit(1);
    }
    const targetAbs = path.resolve(projectDir);
    const operationNow = new Date().toISOString();
    let result;
    if (operation === "status") {
      result = probeOptionalProviderPackage({
        target_abs: targetAbs,
        provider_id: parsed.provider,
        package_id: parsed.package,
        host: null,
        qualification_input: readReleaseVerification(
          parsed.releaseVerification,
          operationNow,
        ),
      });
    } else if (operation === "uninstall") {
      result = uninstallOptionalProviderPackage({
        target_abs: targetAbs,
        provider_id: parsed.provider,
        package_id: parsed.package,
        dry_run: !parsed.flags.has("--yes"),
      });
    } else {
      if (!parsed.source) throw new Error("optional-provider install/update requires --source");
      const releaseVerification = readReleaseVerification(
        parsed.releaseVerification,
        operationNow,
      );
      const lifecycleInput = {
        target_abs: targetAbs,
        provider_id: parsed.provider,
        package_id: parsed.package,
        source_root: path.resolve(parsed.source),
        release_verification: releaseVerification,
        now: operationNow,
      };
      result = operation === "install"
        ? installOptionalProviderPackage(lifecycleInput)
        : updateOptionalProviderPackage(lifecycleInput);
    }
    if (parsed.flags.has("--json")) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      process.stdout.write(
        `Optional provider package ${result.provider_id}/${result.package_id}: `
        + `${result.status || result.operation}\n`,
      );
    }
    if (operation === "status" && result.status === "blocked") process.exitCode = 1;
    return;
  }

  usage();
  process.exit(1);
}

main(process.argv.slice(2)).catch((error) => {
  console.error(error && error.message ? error.message : String(error));
  process.exit(1);
});
