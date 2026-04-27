#!/usr/bin/env node
// Deprecated optional raw Anthropic API replay helper.
//
// Prefer testing/policy-replay/replay.mjs, which uses the Claude Agent SDK with
// local Claude OAuth and the maintained policy replay case format. This script
// is kept only for ad hoc comparisons where an API-key path is explicitly
// desired.
//
// Replay a Claude Code subagent transcript against the Anthropic API to test
// whether a candidate system prompt clears a previously-triggered refusal.
//
// Usage:
//   ANTHROPIC_API_KEY=sk-... node scripts/replay-refusal.js \
//     --transcript ~/.claude/projects/<proj>/<sess>/subagents/agent-<id>.jsonl \
//     [--system <path-to-md>] \
//     [--model claude-opus-4-7] \
//     [--cutoff <line-index-1-based>] \
//     [--n 1] \
//     [--dry-run]
//
// Defaults:
//   --system .claude/agents/hunter-agent.md (body, frontmatter stripped)
//   --model  claude-opus-4-7
//   --cutoff first assistant message with stop_reason="refusal"
//   --n      1
//
// --dry-run skips the API call and prints the assembled message shape so you
// can validate cutoff and normalization without burning tokens.
//
// Emits one JSON line per trial: { trial, stop_reason, output_preview, usage }.

const fs = require("fs");
const path = require("path");
const os = require("os");

const API_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
const DEFAULT_MODEL = "claude-opus-4-7";
const DEFAULT_SYSTEM = path.resolve(
  __dirname,
  "..",
  ".claude",
  "agents",
  "hunter-agent.md",
);

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const key = a.slice(2);
    const val = argv[i + 1];
    if (val === undefined || val.startsWith("--")) {
      args[key] = true;
    } else {
      args[key] = val;
      i++;
    }
  }
  return args;
}

function expandHome(p) {
  if (!p) return p;
  if (p.startsWith("~/")) return path.join(os.homedir(), p.slice(2));
  if (p === "~") return os.homedir();
  return p;
}

function loadTranscript(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  return raw
    .split("\n")
    .filter(Boolean)
    .map((l, i) => {
      try {
        return JSON.parse(l);
      } catch (e) {
        throw new Error(`transcript line ${i + 1} is not JSON: ${e.message}`);
      }
    });
}

function findRefusalIndex(events) {
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (
      e.type === "assistant" &&
      e.message &&
      e.message.stop_reason === "refusal"
    ) {
      return i;
    }
  }
  return -1;
}

// Normalize Claude Code transcript events → Anthropic API messages array.
// - Skips non-user/assistant events.
// - Wraps string content as a single text block.
// - Merges consecutive same-role events into one message (Claude Code splits
//   text + tool_use into two events; the API expects them in one message).
function normalizeMessages(events, cutoff) {
  const out = [];
  let cur = null;
  for (let i = 0; i < cutoff; i++) {
    const e = events[i];
    if (e.type !== "user" && e.type !== "assistant") continue;
    if (!e.message || !e.message.role) continue;
    let content = e.message.content;
    if (content == null) continue;
    if (typeof content === "string") {
      if (!content.length) continue;
      content = [{ type: "text", text: content }];
    }
    if (!Array.isArray(content) || content.length === 0) continue;
    const role = e.message.role;
    if (cur && cur.role === role) {
      cur.content.push(...content);
    } else {
      if (cur) out.push(cur);
      cur = { role, content: [...content] };
    }
  }
  if (cur) out.push(cur);
  return out;
}

// Strip text blocks that contain ONLY whitespace — the API rejects them.
// Also drop empty messages.
function pruneEmptyText(messages) {
  return messages
    .map((m) => ({
      role: m.role,
      content: m.content.filter((c) => {
        if (c.type === "text") return c.text && c.text.trim().length > 0;
        return true;
      }),
    }))
    .filter((m) => m.content.length > 0);
}

function extractToolStubs(events) {
  const names = new Set();
  for (const e of events) {
    if (e.type !== "assistant") continue;
    const content = e.message?.content;
    if (!Array.isArray(content)) continue;
    for (const block of content) {
      if (block.type === "tool_use" && block.name) names.add(block.name);
    }
  }
  return [...names].map((name) => ({
    name,
    description: `Stub for ${name} (replay harness)`,
    input_schema: { type: "object", properties: {}, additionalProperties: true },
  }));
}

function loadSystemPrompt(systemArg) {
  const p = expandHome(systemArg || DEFAULT_SYSTEM);
  const raw = fs.readFileSync(p, "utf8");
  // Strip YAML frontmatter if present.
  if (raw.startsWith("---")) {
    const end = raw.indexOf("\n---", 3);
    if (end !== -1) return raw.slice(end + 4).trimStart();
  }
  return raw;
}

async function callApi({ apiKey, model, system, messages, tools }) {
  const body = { model, max_tokens: 1024, system, messages };
  if (tools && tools.length) body.tools = tools;
  const res = await fetch(API_URL, {
    method: "POST",
    headers: {
      "x-api-key": apiKey,
      "anthropic-version": ANTHROPIC_VERSION,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }
  return { ok: res.ok, status: res.status, body: parsed };
}

function previewContent(content) {
  if (!Array.isArray(content)) return null;
  const parts = [];
  for (const c of content) {
    if (c.type === "text") parts.push(c.text);
    else if (c.type === "tool_use")
      parts.push(`[tool_use ${c.name} ${JSON.stringify(c.input).slice(0, 80)}]`);
    else parts.push(`[${c.type}]`);
  }
  return parts.join("\n").slice(0, 600);
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help || args.h) {
    console.log(fs.readFileSync(__filename, "utf8").slice(0, 1300));
    process.exit(0);
  }
  const transcriptPath = expandHome(args.transcript);
  if (!transcriptPath) {
    console.error("error: --transcript <path> is required");
    process.exit(2);
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey && !args["dry-run"]) {
    console.error(
      "error: ANTHROPIC_API_KEY env var is required. Get one from https://console.anthropic.com/settings/keys",
    );
    process.exit(2);
  }
  const events = loadTranscript(transcriptPath);
  let cutoff = args.cutoff ? parseInt(args.cutoff, 10) - 1 : findRefusalIndex(events);
  if (cutoff < 0) {
    console.error(
      "error: no refusal found in transcript and no --cutoff provided",
    );
    process.exit(2);
  }
  const messages = pruneEmptyText(normalizeMessages(events, cutoff));
  if (messages.length === 0) {
    console.error("error: no messages produced before cutoff");
    process.exit(2);
  }
  if (messages[messages.length - 1].role !== "user") {
    console.error(
      `warn: last message before cutoff is role=${messages[messages.length - 1].role}, API expects role=user; trimming`,
    );
    while (
      messages.length &&
      messages[messages.length - 1].role !== "user"
    ) {
      messages.pop();
    }
    if (messages.length === 0) {
      console.error("error: nothing to replay after trimming");
      process.exit(2);
    }
  }
  const tools = extractToolStubs(events);
  const system = loadSystemPrompt(args.system);
  const model = args.model || DEFAULT_MODEL;
  const n = args.n ? parseInt(args.n, 10) : 1;

  const meta = {
    transcript: transcriptPath,
    model,
    cutoff_index: cutoff,
    cutoff_event_ts: events[cutoff]?.timestamp,
    messages_count: messages.length,
    tools_count: tools.length,
    system_chars: system.length,
    system_source: expandHome(args.system || DEFAULT_SYSTEM),
    trials: n,
  };
  console.error(`# replay meta ${JSON.stringify(meta)}`);

  if (args["dry-run"]) {
    const shape = messages.map((m) => ({
      role: m.role,
      blocks: m.content.map((c) => ({
        type: c.type,
        ...(c.type === "text"
          ? { chars: c.text.length, preview: c.text.slice(0, 120) }
          : {}),
        ...(c.type === "tool_use"
          ? { name: c.name, input_keys: Object.keys(c.input || {}) }
          : {}),
        ...(c.type === "tool_result"
          ? {
              tool_use_id: c.tool_use_id,
              content_chars:
                typeof c.content === "string"
                  ? c.content.length
                  : JSON.stringify(c.content || "").length,
            }
          : {}),
      })),
    }));
    console.log(JSON.stringify({ dry_run: true, shape }, null, 2));
    return;
  }

  for (let i = 1; i <= n; i++) {
    const { ok, status, body } = await callApi({
      apiKey,
      model,
      system,
      messages,
      tools,
    });
    const out = {
      trial: i,
      ok,
      status,
      stop_reason: body?.stop_reason ?? null,
      type: body?.type ?? null,
      error: body?.error ?? null,
      output_preview: previewContent(body?.content),
      usage: body?.usage ?? null,
    };
    console.log(JSON.stringify(out));
  }
}

main().catch((e) => {
  console.error(e?.stack || String(e));
  process.exit(1);
});
