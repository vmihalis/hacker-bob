#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const { startToolFilterProxy } = require("./tool-filter-proxy.js");

const CODEX_BIN = "/opt/codex-runtime/node_modules/.bin/codex";
const CODEX_ARGS = Object.freeze([
  "exec",
  "--strict-config",
  "--ephemeral",
  "--ignore-rules",
  "--skip-git-repo-check",
  "--sandbox",
  "read-only",
  "--color",
  "never",
  "-C",
  "/opt/bob-runner",
]);
const STDERR_TAIL_MAX_BYTES = 8 * 1024;

function waitForChild(child) {
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
}

function drain(stream) {
  if (!stream) return;
  stream.on("data", () => {});
  stream.resume();
}

function captureTail(stream, maxBytes = STDERR_TAIL_MAX_BYTES) {
  let tail = Buffer.alloc(0);
  if (!stream) return () => "";
  stream.on("data", (chunk) => {
    tail = Buffer.concat([tail, Buffer.from(chunk)]);
    if (tail.length > maxBytes) tail = tail.subarray(tail.length - maxBytes);
  });
  stream.resume();
  return () => tail.toString("utf8");
}

function redactDiagnostic(value, secrets = []) {
  let redacted = String(value || "");
  for (const secret of secrets) {
    if (typeof secret === "string" && secret.length >= 4) redacted = redacted.split(secret).join("[REDACTED]");
  }
  return redacted
    .replace(/\b(api[_-]?key|authorization|cookie|password|secret|token)(\s*[:=]\s*)\S+/giu, "$1$2[REDACTED]")
    .trim();
}

async function closeServer(server) {
  if (!server) return;
  if (typeof server.closeAllConnections === "function") server.closeAllConnections();
  await new Promise((resolve) => server.close(() => resolve()));
}

async function main({
  argv = process.argv.slice(2),
  environment = process.env,
  spawnFactory = spawn,
  startProxy = startToolFilterProxy,
} = {}) {
  if (argv.length !== 1 || typeof argv[0] !== "string" || argv[0].length === 0) {
    throw new Error("exactly one Codex task is required");
  }
  if (typeof environment.DEEPSEEK_API_KEY !== "string" || environment.DEEPSEEK_API_KEY.length === 0) {
    throw new Error("DEEPSEEK_API_KEY is required");
  }

  let server;
  let child;
  const forwardSignal = (signal) => {
    if (child && !child.killed) child.kill(signal);
  };
  const handleSigterm = () => forwardSignal("SIGTERM");
  const handleSigint = () => forwardSignal("SIGINT");
  process.once("SIGTERM", handleSigterm);
  process.once("SIGINT", handleSigint);
  try {
    const clientKey = crypto.randomBytes(32).toString("base64url");
    server = await startProxy({ apiKey: environment.DEEPSEEK_API_KEY, clientKey });
    child = spawnFactory(CODEX_BIN, [...CODEX_ARGS, argv[0]], {
      cwd: "/opt/bob-runner",
      env: { ...environment, DEEPSEEK_API_KEY: clientKey },
      stdio: ["ignore", "pipe", "pipe"],
    });
    drain(child.stdout);
    const stderrTail = captureTail(child.stderr);
    const result = await waitForChild(child);
    if (result.code === 0) {
      process.stdout.write("Codex runner completed.\n");
      return 0;
    }
    const diagnostic = redactDiagnostic(stderrTail(), [environment.DEEPSEEK_API_KEY, clientKey]);
    process.stderr.write(`Codex runner failed.${diagnostic ? ` ${diagnostic}` : ""}\n`);
    return Number.isSafeInteger(result.code) ? result.code : 1;
  } finally {
    process.removeListener("SIGTERM", handleSigterm);
    process.removeListener("SIGINT", handleSigint);
    await closeServer(server);
  }
}

module.exports = {
  CODEX_ARGS,
  CODEX_BIN,
  closeServer,
  captureTail,
  drain,
  main,
  redactDiagnostic,
  waitForChild,
};

if (require.main === module) {
  main().then((code) => {
    process.exitCode = code;
  }).catch(() => {
    process.stderr.write("Codex runner failed.\n");
    process.exitCode = 1;
  });
}
