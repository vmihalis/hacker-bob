#!/usr/bin/env node
"use strict";

const MCP_FORWARD_ENVIRONMENT = Object.freeze([
  "BOB_SESSIONS_ROOT",
  "BOB_PROJECTION_URL",
  "BOB_RUN_SLUG",
  "BOB_PROJECTION_KEY",
  "BOB_RUN_KIND",
  "BOB_RETEST_OF",
  "BOB_REPORT_SLUG",
  "RUNNER_SECRET",
]);

function sanitizedMcpEnvironment(environment = process.env) {
  const result = {
    HOME: "/workspace",
    NODE_ENV: "production",
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    PLAYWRIGHT_BROWSERS_PATH: "/opt/ms-playwright",
  };
  for (const name of MCP_FORWARD_ENVIRONMENT) {
    if (typeof environment[name] === "string" && environment[name].length > 0) {
      result[name] = environment[name];
    }
  }
  return result;
}

function main(environment = process.env) {
  const sanitized = sanitizedMcpEnvironment(environment);
  for (const name of Object.keys(process.env)) delete process.env[name];
  Object.assign(process.env, sanitized);
  require("/opt/hacker-bob/mcp/server.js").startServer();
}

module.exports = {
  MCP_FORWARD_ENVIRONMENT,
  sanitizedMcpEnvironment,
  main,
};

if (require.main === module) main();
