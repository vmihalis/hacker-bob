#!/usr/bin/env node
"use strict";

const path = require("path");

const projectRoot = path.resolve(__dirname, "..", "..");
const {
  COMMANDS,
  runCli,
} = require(path.join(projectRoot, "mcp", "core", "egress-cli.js"));

const args = process.argv.slice(2);
if (
  process.env.CLAUDE_PROJECT_DIR &&
  (!args[0] || args[0].startsWith("-") || COMMANDS.has(args[0]))
) {
  args.unshift(process.env.CLAUDE_PROJECT_DIR);
}

runCli(args);
