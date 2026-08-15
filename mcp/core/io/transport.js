const DEFAULT_MAX_FRAME_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_HEADER_BYTES = 64 * 1024;
const HEADER_DELIMITER = Buffer.from("\r\n\r\n");

// fx-gate-bypass defense 2 — caller-auth token shape. Mirrors
// agentcore-entrypoint.py's own hex-shape check for grade_verdict_hash
// (`re.fullmatch(r"[0-9a-f]{64}", candidate)`) and matches
// `secrets.token_hex(32)`'s output shape exactly (64 lowercase hex chars).
const CALLER_TOKEN_RE = /^[0-9a-f]{64}$/;

function hasResponseId(rpc) {
  return Object.prototype.hasOwnProperty.call(rpc || {}, "id");
}

// fx-gate-bypass defense 2 — a rogue second engine instance the model spawns
// directly via Bash (e.g. `env -u BOB_AGENTCORE node .../mcp/server.js`)
// inherits only the MODEL's own ambient env, never the mcp-config `env` block
// the CLI applies exclusively to the MCP-server child IT spawns. So
// agentcore-entrypoint.py mints a per-invocation random token and injects it
// ONLY into that mcp-config's `mcpServers.hacker-bob.env.BOB_MCP_CALLER_TOKEN`
// -- a rogue Bash-spawned instance never receives it. This checks for that
// token on the FIRST inbound message and refuses to proceed (exit non-zero,
// no response sent) if it is absent or malformed, but ONLY when enforcement
// is active (gated on the SAME BOB_AGENTCORE==="1" flag as the other two
// AgentCore-branch defenses, for consistency) -- fully inert off that flag,
// so local/dev/CI stdio usage requires no new env var and behaves
// identically to before this defense existed.
//
// Documented residual (this is defense-in-depth, NOT the root of trust): a
// model that reads the per-invocation mcp-config JSON via Bash/Read could in
// principle exfiltrate and replay the token into a rogue spawn. The true
// structural backstop is the INDEPENDENT export-tool chokepoint
// (mcp/tools/export-security-hub-finding.js's unconditional
// verifyApprovalArtifact call), which this defense does not weaken or
// replace.
function createCallerAuthGate({ stderr, env, exit }) {
  let checked = false;
  return function enforceCallerAuthOnce() {
    if (checked) return true;
    checked = true;
    if (env.BOB_AGENTCORE !== "1") return true;
    const token = env.BOB_MCP_CALLER_TOKEN;
    if (typeof token !== "string" || !CALLER_TOKEN_RE.test(token)) {
      stderr.write(
        "hacker-bob MCP server: refusing first request -- BOB_MCP_CALLER_TOKEN is "
        + "missing or malformed (expected 64 lowercase hex chars). A rogue engine "
        + "instance spawned outside the CLI's own --mcp-config wiring would lack "
        + "this token; see infra/runner/agentcore-entrypoint.py.\n",
      );
      exit(1);
      return false;
    }
    return true;
  };
}

function createMcpMessageHandler({
  tools,
  executeTool,
  send,
  stderr = process.stderr,
  env = process.env,
  exit = (code) => process.exit(code),
}) {
  const enforceCallerAuthOnce = createCallerAuthGate({ stderr, env, exit });

  return async function handleMessage(rpc) {
    if (!enforceCallerAuthOnce()) {
      return;
    }
    switch (rpc.method) {
      case "initialize":
        // The canonical MCP server name is `hacker-bob`. v1.x installs that
        // still carry the legacy `bountyagent` server key in their `.mcp.json`
        // are auto-rewritten on next install/update by the install-time
        // migration shim. See the host adapters' install scripts.
        send({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {
            protocolVersion: rpc.params?.protocolVersion || "2025-11-25",
            capabilities: { tools: {} },
            serverInfo: { name: "hacker-bob", version: "1.0.0" },
          },
        });
        break;

      case "ping":
        send({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {},
        });
        break;

      case "notifications/initialized":
        break;

      case "tools/list":
        send({
          jsonrpc: "2.0",
          id: rpc.id,
          result: { tools },
        });
        break;

      case "tools/call": {
        const { name, arguments: args } = rpc.params;
        try {
          const result = await executeTool(name, args || {});
          send({
            jsonrpc: "2.0",
            id: rpc.id,
            result: {
              content: [{ type: "text", text: JSON.stringify(result) }],
            },
          });
        } catch (e) {
          send({
            jsonrpc: "2.0",
            id: rpc.id,
            result: {
              content: [{ type: "text", text: JSON.stringify({
                ok: false,
                error: {
                  code: "INTERNAL_ERROR",
                  message: e.message || String(e),
                },
                meta: { tool: name, version: 1 },
              }) }],
            },
          });
        }
        break;
      }

      default:
        if (hasResponseId(rpc)) {
          send({
            jsonrpc: "2.0",
            id: rpc.id,
            error: { code: -32601, message: `Method not found: ${rpc.method}` },
          });
        }
        break;
    }
  };
}

function createStdioServer({
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  tools,
  executeTool,
  maxFrameBytes = DEFAULT_MAX_FRAME_BYTES,
  maxHeaderBytes = DEFAULT_MAX_HEADER_BYTES,
  // Test-only injection points for the fx-gate-bypass defense-2 caller-auth
  // gate (never overridden in production -- startStdioServer/mcp/server.js
  // never pass these, so real runs always use process.env / process.exit).
  env = process.env,
  exit = (code) => process.exit(code),
} = {}) {
  if (!Number.isInteger(maxFrameBytes) || maxFrameBytes < 1) {
    throw new Error("maxFrameBytes must be a positive integer");
  }
  if (!Number.isInteger(maxHeaderBytes) || maxHeaderBytes < 1) {
    throw new Error("maxHeaderBytes must be a positive integer");
  }

  let transportMode = "framed";
  let buffer = Buffer.alloc(0);
  let discardRemainingBytes = 0;

  function send(msg) {
    const json = JSON.stringify(msg);
    if (transportMode === "raw") {
      stdout.write(`${json}\n`);
      return;
    }
    stdout.write(`Content-Length: ${Buffer.byteLength(json)}\r\n\r\n${json}`);
  }

  const handleMessage = createMcpMessageHandler({ tools, executeTool, send, stderr, env, exit });

  function sendParseError(message = "Parse error") {
    send({ jsonrpc: "2.0", id: null, error: { code: -32700, message } });
  }

  function sendInvalidRequest(message) {
    send({ jsonrpc: "2.0", id: null, error: { code: -32600, message } });
  }

  function toChunkBuffer(chunk) {
    return Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
  }

  function maybeHandleRawBuffer() {
    const prefix = buffer.subarray(0, Math.min(buffer.length, 64)).toString("ascii");
    if (/^Content-Length:/i.test(prefix)) {
      return false;
    }

    const text = buffer.toString("utf8");
    const trimmed = text.trim();
    if (!trimmed) {
      return false;
    }

    try {
      const msg = JSON.parse(trimmed);
      transportMode = "raw";
      buffer = Buffer.alloc(0);
      handleMessage(msg);
      return true;
    } catch {}

    const firstNewline = buffer.indexOf(0x0a);
    if (firstNewline === -1) {
      return false;
    }

    let offset = 0;
    let parsedAny = false;
    while (offset < buffer.length) {
      const newline = buffer.indexOf(0x0a, offset);
      if (newline === -1) break;
      const line = buffer.subarray(offset, newline).toString("utf8").trim();
      offset = newline + 1;
      if (!line) continue;
      try {
        transportMode = "raw";
        handleMessage(JSON.parse(line));
        parsedAny = true;
      } catch {
        sendParseError();
      }
    }

    if (offset > 0) {
      buffer = buffer.subarray(offset);
      return parsedAny;
    }
    return false;
  }

  function handleChunk(chunk) {
    let incoming = toChunkBuffer(chunk);
    if (discardRemainingBytes > 0) {
      const consumed = Math.min(discardRemainingBytes, incoming.length);
      incoming = incoming.subarray(consumed);
      discardRemainingBytes -= consumed;
      if (incoming.length === 0) return;
    }

    buffer = Buffer.concat([buffer, incoming]);
    while (true) {
      const headerEnd = buffer.indexOf(HEADER_DELIMITER);
      if (headerEnd === -1) {
        if (maybeHandleRawBuffer()) {
          continue;
        }
        if (buffer.length > maxHeaderBytes && /^Content-Length:/i.test(buffer.subarray(0, 64).toString("ascii"))) {
          buffer = Buffer.alloc(0);
          sendInvalidRequest(`MCP frame header exceeds ${maxHeaderBytes} bytes`);
          continue;
        }
        if (buffer.length > maxFrameBytes) {
          buffer = Buffer.alloc(0);
          sendInvalidRequest(`Raw JSON-RPC message exceeds ${maxFrameBytes} bytes`);
          continue;
        }
        break;
      }

      if (headerEnd > maxHeaderBytes) {
        buffer = buffer.subarray(headerEnd + HEADER_DELIMITER.length);
        sendInvalidRequest(`MCP frame header exceeds ${maxHeaderBytes} bytes`);
        continue;
      }

      const headerPart = buffer.subarray(0, headerEnd).toString("ascii");
      const match = headerPart.match(/Content-Length:\s*(\d+)/i);
      if (!match) {
        buffer = buffer.subarray(headerEnd + HEADER_DELIMITER.length);
        sendParseError("Missing Content-Length header");
        continue;
      }

      const contentLength = parseInt(match[1], 10);
      transportMode = "framed";
      const bodyStart = headerEnd + HEADER_DELIMITER.length;
      if (contentLength > maxFrameBytes) {
        sendInvalidRequest(`MCP frame exceeds ${maxFrameBytes} bytes`);
        const frameEnd = bodyStart + contentLength;
        if (buffer.length >= frameEnd) {
          buffer = buffer.subarray(frameEnd);
          continue;
        }
        const availableBodyBytes = Math.max(0, buffer.length - bodyStart);
        discardRemainingBytes = Math.max(0, contentLength - availableBodyBytes);
        buffer = Buffer.alloc(0);
        break;
      }
      if (buffer.length < bodyStart + contentLength) break;

      const body = buffer.subarray(bodyStart, bodyStart + contentLength).toString("utf8");
      buffer = buffer.subarray(bodyStart + contentLength);

      try {
        const msg = JSON.parse(body);
        handleMessage(msg);
      } catch {
        sendParseError();
      }
    }
  }

  function start() {
    stdin.on("data", handleChunk);
    // Surface the canonical session root in the startup banner. Sessions
    // resolve only from `~/hacker-bob-sessions/`.
    stderr.write("hacker-bob MCP server running (stdio); sessions: ~/hacker-bob-sessions/\n");
  }

  return {
    handleChunk,
    handleMessage,
    send,
    start,
  };
}

function startStdioServer(options) {
  return createStdioServer(options).start();
}

module.exports = {
  DEFAULT_MAX_FRAME_BYTES,
  createMcpMessageHandler,
  createStdioServer,
  startStdioServer,
};
