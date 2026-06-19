const DEFAULT_MAX_FRAME_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_HEADER_BYTES = 64 * 1024;
const HEADER_DELIMITER = Buffer.from("\r\n\r\n");

function hasResponseId(rpc) {
  return Object.prototype.hasOwnProperty.call(rpc || {}, "id");
}

function createMcpMessageHandler({ tools, executeTool, send }) {
  return async function handleMessage(rpc) {
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

  const handleMessage = createMcpMessageHandler({ tools, executeTool, send });

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
    // Cycle P.2 / Risk R6: copy-preserve any legacy `~/bounty-agent-sessions/`
    // domain directories into the canonical `~/hacker-bob-sessions/` on
    // startup. The shim is idempotent and the legacy root is never deleted by
    // this call; explicit purge is reserved for the v2.1.0
    // `--purge-legacy-session-root` flag.
    try {
      require("./session-root-migration.js").migrateLegacySessionRoot();
    } catch (_) {
      // Migration failure must never prevent the MCP server from starting.
      // Sessions still resolve through `paths.sessionsRoot()`.
    }
    stdin.on("data", handleChunk);
    // Surface the canonical session root in the startup banner so operators
    // see the new `~/hacker-bob-sessions/` path; the legacy
    // `~/bounty-agent-sessions/` remains readable until v2.1.0.
    stderr.write("hacker-bob MCP server running (stdio); sessions: ~/hacker-bob-sessions/ (legacy: ~/bounty-agent-sessions/ read-fallback)\n");
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
