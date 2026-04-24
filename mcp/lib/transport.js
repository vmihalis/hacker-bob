function createMcpMessageHandler({ tools, executeTool, send }) {
  return async function handleMessage(rpc) {
    switch (rpc.method) {
      case "initialize":
        send({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {
            protocolVersion: rpc.params?.protocolVersion || "2025-11-25",
            capabilities: { tools: {} },
            serverInfo: { name: "bountyagent", version: "1.0.0" },
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
        if (rpc.id) {
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
} = {}) {
  let transportMode = "framed";
  let buffer = "";

  function send(msg) {
    const json = JSON.stringify(msg);
    if (transportMode === "raw") {
      stdout.write(`${json}\n`);
      return;
    }
    stdout.write(`Content-Length: ${Buffer.byteLength(json)}\r\n\r\n${json}`);
  }

  const handleMessage = createMcpMessageHandler({ tools, executeTool, send });

  function handleChunk(chunk) {
    buffer += chunk;
    while (true) {
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        const trimmed = buffer.trim();
        if (!trimmed) break;

        try {
          const msg = JSON.parse(trimmed);
          transportMode = "raw";
          buffer = "";
          handleMessage(msg);
          continue;
        } catch {
          if (buffer.includes("\n")) {
            const lines = buffer.split("\n");
            buffer = lines.pop() ?? "";
            let parsedAny = false;
            for (const line of lines.map((l) => l.trim()).filter(Boolean)) {
              try {
                transportMode = "raw";
                handleMessage(JSON.parse(line));
                parsedAny = true;
              } catch {
                buffer = `${line}\n${buffer}`;
              }
            }
            if (parsedAny) continue;
          }
        }
        break;
      }

      const headerPart = buffer.slice(0, headerEnd);
      const match = headerPart.match(/Content-Length:\s*(\d+)/i);
      if (!match) {
        try {
          const lines = buffer.split("\n").filter((line) => line.trim());
          for (const line of lines) {
            const msg = JSON.parse(line);
            handleMessage(msg);
          }
          buffer = "";
          return;
        } catch {
          buffer = buffer.slice(headerEnd + 4);
          continue;
        }
      }

      const contentLength = parseInt(match[1], 10);
      transportMode = "framed";
      const bodyStart = headerEnd + 4;
      if (buffer.length < bodyStart + contentLength) break;

      const body = buffer.slice(bodyStart, bodyStart + contentLength);
      buffer = buffer.slice(bodyStart + contentLength);

      try {
        const msg = JSON.parse(body);
        handleMessage(msg);
      } catch {
        send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      }
    }
  }

  function start() {
    stdin.setEncoding("utf8");
    stdin.on("data", handleChunk);
    stderr.write("bountyagent MCP server running (stdio)\n");
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
  createMcpMessageHandler,
  createStdioServer,
  startStdioServer,
};
