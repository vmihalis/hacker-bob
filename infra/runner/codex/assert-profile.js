#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const { BOB_NAMESPACE, UPSTREAM_URL, startToolFilterProxy } = require("./tool-filter-proxy.js");
const { sanitizedMcpEnvironment } = require("./mcp-launcher.js");

const CODEX_HOME = "/opt/codex-home";
const CODEX_BIN = "/opt/codex-runtime/node_modules/.bin/codex";
const CODEX_PACKAGE = "/opt/codex-runtime/node_modules/@openai/codex/package.json";
const EXPECTED_CODEX_VERSION = "0.149.1";
const FORBIDDEN_MCP_ENV = Object.freeze([
  "BOB_CONVEX_URL",
  "BOB_PAYLOAD_JSON",
  "BOB_PROJECTION_KEY",
  "BOB_PROJECTION_URL",
  "DEEPSEEK_API_KEY",
  "OPENAI_API_KEY",
  "RUNNER_SECRET",
]);

function waitForExit(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Codex profile assertion timed out"));
    }, timeoutMs);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

function drain(stream, chunks) {
  if (!stream) return;
  stream.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
  stream.resume();
}

async function assertEffectiveToolSurface() {
  const forwarded = [];
  const proxy = await startToolFilterProxy({
    apiKey: "profile-assertion-key",
    fetchImpl: async (_url, options) => {
      forwarded.push(JSON.parse(String(options.body)));
      return new Response(JSON.stringify({
        error: { message: "profile assertion complete", type: "invalid_request_error" },
      }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const sessionsRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-codex-profile-"));
  let child;
  const output = [];
  let exitResult;
  try {
    child = spawn(CODEX_BIN, [
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
      "Use one Hacker Bob MCP status tool and then stop.",
    ], {
      cwd: "/opt/bob-runner",
      env: {
        PATH: "/opt/codex-runtime/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        HOME: "/workspace",
        CODEX_HOME,
        DEEPSEEK_API_KEY: "profile-assertion-key",
        BOB_SESSIONS_ROOT: sessionsRoot,
        BOB_RUN_SLUG: "run-profile-assertion",
        BOB_REPORT_SLUG: "run-profile-assertion-report",
        BOB_RUN_KIND: "assessment",
        BOB_RETEST_OF: "",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    drain(child.stdout, output);
    drain(child.stderr, output);
    exitResult = await waitForExit(child, 45_000);
  } finally {
    if (child && child.exitCode === null && !child.killed) child.kill("SIGKILL");
    if (typeof proxy.closeAllConnections === "function") proxy.closeAllConnections();
    await new Promise((resolve) => proxy.close(() => resolve()));
    fs.rmSync(sessionsRoot, { recursive: true, force: true });
  }

  const diagnostic = Buffer.concat(output).toString("utf8")
    .replaceAll("profile-assertion-key", "[REDACTED]")
    .replaceAll("P".repeat(43), "[REDACTED]")
    .replaceAll("runner-secret-assertion", "[REDACTED]")
    .slice(-4_096);
  assert.equal(
    forwarded.length,
    1,
    `Codex must make one assertion request (exit ${exitResult?.code}, signal ${exitResult?.signal}): ${diagnostic}`,
  );
  const request = forwarded[0];
  assert.equal(request.model, "deepseek-v4-pro");
  assert.equal(request.tool_choice, "auto");
  assert.match(request.instructions, /Hacker Bob/);
  assert.doesNotMatch(request.instructions, /\b(?:GPT-5|OpenAI)\b/i);
  const serializedRequest = JSON.stringify(request);
  for (const secret of ["profile-assertion-key", "P".repeat(43), "runner-secret-assertion"]) {
    assert.equal(serializedRequest.includes(secret), false, "a runner secret reached DeepSeek");
  }
  assert.equal(request.tools.length, 1, "only the Bob namespace may reach DeepSeek");
  const namespace = request.tools[0];
  assert.equal(namespace.type, "namespace");
  assert.equal(namespace.name, BOB_NAMESPACE);
  assert.ok(namespace.tools.length > 0, "Bob MCP must expose tools");
  assert.ok(namespace.tools.every((tool) => /^bob_[a-z0-9_]+$/.test(tool.name)));
  return namespace.tools.length;
}

async function main() {
  const runtimeManifest = JSON.parse(fs.readFileSync(CODEX_PACKAGE, "utf8"));
  assert.equal(runtimeManifest.version, EXPECTED_CODEX_VERSION);

  const config = fs.readFileSync(path.join(CODEX_HOME, "config.toml"), "utf8");
  assert.match(config, /^model = "deepseek-v4-pro"$/m);
  assert.match(config, /^model_provider = "deepseek"$/m);
  assert.match(config, /^base_url = "http:\/\/127\.0\.0\.1:48125\/"$/m);
  assert.match(config, /^env_key = "DEEPSEEK_API_KEY"$/m);
  assert.match(config, /^wire_api = "responses"$/m);
  assert.match(config, /^approval_policy = "never"$/m);
  assert.match(config, /^sandbox_mode = "read-only"$/m);
  assert.match(config, /^web_search = "disabled"$/m);
  assert.match(config, /^shell_tool = false$/m);
  assert.match(config, /^view_image = false$/m);
  assert.match(config, /^default_mode_request_user_input = false$/m);
  assert.match(config, /^enable_request_compression = false$/m);
  assert.match(config, /^\[agents\]\nenabled = false$/m);
  assert.equal((config.match(/^\[mcp_servers\./gm) || []).length, 1);
  assert.match(config, /^\[mcp_servers\."hacker-bob"\]$/m);
  assert.match(config, /^default_tools_approval_mode = "approve"$/m);
  assert.equal(UPSTREAM_URL, "https://api.deepseek.com/responses");

  const catalog = JSON.parse(fs.readFileSync(path.join(CODEX_HOME, "models.json"), "utf8"));
  const models = new Map(catalog.models.map((model) => [model.slug, model]));
  for (const slug of ["deepseek-v4-flash", "deepseek-v4-pro"]) {
    const model = models.get(slug);
    assert.ok(model, `missing ${slug}`);
    assert.equal(Object.hasOwn(model, "apply_patch_tool_type"), false);
    assert.equal(Object.hasOwn(model, "web_search_tool_type"), false);
    assert.equal(model.supports_search_tool, false);
  }

  const sanitized = sanitizedMcpEnvironment({
    BOB_SESSIONS_ROOT: "/workspace/sessions",
    BOB_PROJECTION_URL: "https://projection.example/api/findings",
    BOB_RUN_SLUG: "run-profile-assertion",
    BOB_PROJECTION_KEY: "P".repeat(43),
    BOB_RUN_KIND: "assessment",
    BOB_RETEST_OF: "",
    BOB_REPORT_SLUG: "run-profile-assertion-report",
    RUNNER_SECRET: "runner-secret",
    BOB_CONVEX_URL: "https://deployment.convex.cloud",
    BOB_PAYLOAD_JSON: "{}",
    DEEPSEEK_API_KEY: "model-secret",
    OPENAI_API_KEY: "unused-openai-secret",
  });
  for (const name of FORBIDDEN_MCP_ENV) assert.equal(Object.hasOwn(sanitized, name), false);
  assert.equal(sanitized.RUNNER_SECRET, undefined);
  assert.equal(sanitized.BOB_PROJECTION_KEY, undefined);
  assert.equal(sanitized.BOB_PROJECTION_URL, undefined);

  const toolCount = await assertEffectiveToolSurface();
  process.stdout.write(`bob Codex profile verified (${toolCount} Bob tools)\n`);
}

module.exports = {
  assertEffectiveToolSurface,
  main,
  waitForExit,
};

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error && error.stack ? error.stack : error}\n`);
    process.exitCode = 1;
  });
}
