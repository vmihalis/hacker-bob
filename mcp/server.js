#!/usr/bin/env node
"use strict";

// Public MCP server facade: runtime tool registry, dispatch, and CLI startup.

const {
  executeTool,
} = require("./core/dispatch/dispatch.js");
const {
  TOOL_MANIFEST,
  TOOLS,
} = require("./tools/tool-registry.js");
const {
  startStdioServer,
} = require("./core/io/transport.js");
const {
  acquireEngineSingletonLock,
  releaseEngineSingletonLock,
} = require("./core/io/engine-lock.js");

// fx-gate-bypass defense 1: refuse to serve at all if another `node
// mcp/server.js` instance already holds the whole-engine singleton lock for
// this HOME/session root. This closes the "spawn a second, ungated engine"
// vector a prompt-injected model could otherwise use under
// `--dangerously-skip-permissions` (a rogue second instance controls its own
// subprocess env, so any BOB_AGENTCORE-keyed approval gate is inert on it —
// this lock never depends on that env var at all). See mcp/core/io/engine-lock.js
// for why this does NOT use an elapsed-time staleness policy. An exact
// same-host crash-left lock is recoverable only after the kernel reports its
// owner PID absent; a live or ambiguous owner is never displaced.
function startServer() {
  const acquired = acquireEngineSingletonLock();
  if (!acquired) {
    process.stderr.write(
      "hacker-bob MCP server: refusing to start -- another engine instance already "
      + "holds the singleton lock for this session root (~/hacker-bob-sessions/).\n",
    );
    process.exit(1);
    return;
  }

  let released = false;
  const releaseOnce = () => {
    if (released) return;
    released = true;
    releaseEngineSingletonLock();
  };
  process.on("exit", releaseOnce);
  process.on("SIGTERM", () => { releaseOnce(); process.exit(0); });
  process.on("SIGINT", () => { releaseOnce(); process.exit(0); });

  startStdioServer({ tools: TOOLS, executeTool });
}

module.exports = {
  TOOLS,
  TOOL_MANIFEST,
  executeTool,
  startServer,
};

if (require.main === module) {
  startServer();
}
