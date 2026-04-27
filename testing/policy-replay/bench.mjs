#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expandHome, parseArgs } from "./case-schema.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPLAY = path.join(__dirname, "replay.mjs");

function usage() {
  return `Usage:
  node testing/policy-replay/bench.mjs --cases-dir testing/policy-replay/cases --prompts-dir <dir> --n 3

Add --dry-run to validate case/prompt wiring without invoking Claude.`;
}

function listFiles(dir, suffix) {
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(suffix))
    .map((entry) => path.join(dir, entry.name))
    .sort();
}

function runReplay({ casePath, systemPath, dryRun }) {
  return new Promise((resolve) => {
    const replayArgs = [REPLAY, "--case", casePath, "--system", systemPath];
    if (dryRun) replayArgs.push("--dry-run");
    const child = spawn(process.execPath, replayArgs, {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("close", (code) => {
      let parsed = null;
      try {
        const lastJsonLine = stdout
          .trim()
          .split("\n")
          .reverse()
          .find((line) => line.startsWith("{"));
        if (lastJsonLine) parsed = JSON.parse(lastJsonLine);
      } catch {}
      resolve({ code, stdout, stderr, parsed });
    });
  });
}

function summarizeTrials(trials) {
  const count = trials.length;
  const passed = trials.filter((trial) => trial.parsed?.passed === true).length;
  const refused = trials.filter((trial) => trial.parsed?.refused === true).length;
  const unsafe = trials.filter(
    (trial) => trial.parsed?.unsafe_compliance_detected === true,
  ).length;
  const errors = trials.filter(
    (trial) => !trial.parsed || trial.parsed.error || trial.code !== 0,
  ).length;
  return {
    trials: count,
    passed,
    refused,
    unsafe_compliance_detected: unsafe,
    errors,
    pass_rate: count ? passed / count : 0,
    refusal_rate: count ? refused / count : 0,
  };
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help || args.h) {
    console.log(usage());
    return;
  }
  const casesDir = path.resolve(expandHome(args["cases-dir"] || "testing/policy-replay/cases"));
  const promptsDir = path.resolve(expandHome(args["prompts-dir"] || "testing/policy-replay/prompts"));
  const n = args.n ? Number.parseInt(args.n, 10) : 3;
  if (!Number.isInteger(n) || n < 1) {
    console.error("error: --n must be a positive integer");
    process.exit(2);
  }

  const cases = listFiles(casesDir, ".json");
  const prompts = listFiles(promptsDir, ".md").filter(
    (filePath) => path.basename(filePath) !== "README.md",
  );
  if (cases.length === 0) {
    console.error(`error: no *.json cases found in ${casesDir}`);
    process.exit(2);
  }
  if (prompts.length === 0) {
    console.error(`error: no *.md prompts found in ${promptsDir}`);
    process.exit(2);
  }

  const results = [];
  for (const casePath of cases) {
    for (const promptPath of prompts) {
      const trials = [];
      for (let trial = 1; trial <= n; trial++) {
        trials.push(
          await runReplay({
            casePath,
            systemPath: promptPath,
            dryRun: Boolean(args["dry-run"]),
          }),
        );
      }
      const summary = summarizeTrials(trials);
      results.push({
        case_path: casePath,
        prompt_path: promptPath,
        case_id: trials[0]?.parsed?.case_id || path.basename(casePath, ".json"),
        agent_type: trials[0]?.parsed?.agent_type || null,
        expected: trials[0]?.parsed?.expected || null,
        ...summary,
        trial_results: trials.map((trial, index) => ({
          trial: index + 1,
          code: trial.code,
          ok: trial.parsed?.ok ?? false,
          passed: trial.parsed?.passed ?? false,
          refused: trial.parsed?.refused ?? false,
          unsafe_compliance_detected:
            trial.parsed?.unsafe_compliance_detected ?? false,
          error: trial.parsed?.error || trial.stderr.trim() || null,
        })),
      });
    }
  }

  const output = {
    ok: results.every((result) => result.errors === 0),
    dry_run: Boolean(args["dry-run"]),
    cases_dir: casesDir,
    prompts_dir: promptsDir,
    trials_per_case_prompt: n,
    results,
  };
  console.log(JSON.stringify(output));
  if (!output.ok) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error?.stack || String(error));
  process.exit(1);
});
