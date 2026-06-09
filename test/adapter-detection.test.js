"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { detectAdapterId } = require("../adapters/index.js");

function makeWorkspace() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bob-detect-"));
}

function never() { return false; }
function always() { return true; }
function only(...names) {
  return (cmd) => names.includes(cmd);
}

test("detection layer 1: $CLAUDE_PROJECT_DIR resolves to claude", () => {
  const result = detectAdapterId(null, {
    env: { CLAUDE_PROJECT_DIR: "/somewhere" },
    commandExists: never,
  });
  assert.equal(result.id, "claude");
  assert.equal(result.layer, "env");
  assert.equal(result.reason, "env_CLAUDE_PROJECT_DIR");
});

test("detection layer 1: $CODEX_HOME resolves to codex", () => {
  const result = detectAdapterId(null, {
    env: { CODEX_HOME: "/home/user/.codex" },
    commandExists: never,
  });
  assert.equal(result.id, "codex");
  assert.equal(result.layer, "env");
  assert.equal(result.reason, "env_CODEX_HOME");
});

test("detection layer 1: $KIMI_PROJECT_DIR resolves to kimi", () => {
  const result = detectAdapterId(null, {
    env: { KIMI_PROJECT_DIR: "/somewhere" },
    commandExists: never,
  });
  assert.equal(result.id, "kimi");
  assert.equal(result.layer, "env");
  assert.equal(result.reason, "env_KIMI_PROJECT_DIR");
});

test("detection layer 1: $CLAUDE_PROJECT_DIR wins over project artifacts and CLI", () => {
  const workspace = makeWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, ".codex", "plugins"), { recursive: true });
    const result = detectAdapterId(workspace, {
      env: { CLAUDE_PROJECT_DIR: "/somewhere" },
      commandExists: only("codex"),
    });
    assert.equal(result.id, "claude");
    assert.equal(result.layer, "env");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 1: $KIMI_PROJECT_DIR wins over project artifacts and CLI", () => {
  const workspace = makeWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });
    const result = detectAdapterId(workspace, {
      env: { KIMI_PROJECT_DIR: "/somewhere" },
      commandExists: only("claude"),
    });
    assert.equal(result.id, "kimi");
    assert.equal(result.layer, "env");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 2: .claude/ project artifact resolves to claude", () => {
  const workspace = makeWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });
    const result = detectAdapterId(workspace, { env: {}, commandExists: never });
    assert.equal(result.id, "claude");
    assert.equal(result.layer, "project");
    assert.equal(result.reason, "project_dot_claude");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 2: .kimi/ project artifact resolves to kimi", () => {
  const workspace = makeWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, ".kimi"), { recursive: true });
    const result = detectAdapterId(workspace, { env: {}, commandExists: never });
    assert.equal(result.id, "kimi");
    assert.equal(result.layer, "project");
    assert.equal(result.reason, "project_dot_kimi");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 2: .codex/plugins/ resolves to codex", () => {
  const workspace = makeWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, ".codex", "plugins"), { recursive: true });
    const result = detectAdapterId(workspace, { env: {}, commandExists: never });
    assert.equal(result.id, "codex");
    assert.equal(result.layer, "project");
    assert.equal(result.reason, "project_codex_plugins");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 2: .agents/plugins/ resolves to codex", () => {
  const workspace = makeWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, ".agents", "plugins"), { recursive: true });
    const result = detectAdapterId(workspace, { env: {}, commandExists: never });
    assert.equal(result.id, "codex");
    assert.equal(result.layer, "project");
    assert.equal(result.reason, "project_agents_plugins");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 2: bare .mcp.json resolves to generic-mcp", () => {
  const workspace = makeWorkspace();
  try {
    fs.writeFileSync(path.join(workspace, ".mcp.json"), "{}", "utf8");
    const result = detectAdapterId(workspace, { env: {}, commandExists: never });
    assert.equal(result.id, "generic-mcp");
    assert.equal(result.layer, "project");
    assert.equal(result.reason, "project_mcp_json");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 2: .kimi/ wins over .mcp.json (kimi is the host, mcp is just wiring)", () => {
  const workspace = makeWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, ".kimi"), { recursive: true });
    fs.writeFileSync(path.join(workspace, ".mcp.json"), "{}", "utf8");
    const result = detectAdapterId(workspace, { env: {}, commandExists: never });
    assert.equal(result.id, "kimi");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 2: .claude/ wins over .mcp.json (claude is the host, mcp is just wiring)", () => {
  const workspace = makeWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });
    fs.writeFileSync(path.join(workspace, ".mcp.json"), "{}", "utf8");
    const result = detectAdapterId(workspace, { env: {}, commandExists: never });
    assert.equal(result.id, "claude");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 2: opencode.json project artifact resolves to opencode", () => {
  const workspace = makeWorkspace();
  try {
    fs.writeFileSync(path.join(workspace, "opencode.json"), "{}", "utf8");
    const result = detectAdapterId(workspace, { env: {}, commandExists: never });
    assert.equal(result.id, "opencode");
    assert.equal(result.layer, "project");
    assert.equal(result.reason, "project_opencode_config");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 2: .opencode/ project artifact resolves to opencode", () => {
  const workspace = makeWorkspace();
  try {
    fs.mkdirSync(path.join(workspace, ".opencode"), { recursive: true });
    const result = detectAdapterId(workspace, { env: {}, commandExists: never });
    assert.equal(result.id, "opencode");
    assert.equal(result.layer, "project");
    assert.equal(result.reason, "project_opencode_config");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 2: opencode.json wins over .mcp.json (opencode is the host)", () => {
  const workspace = makeWorkspace();
  try {
    fs.writeFileSync(path.join(workspace, "opencode.json"), "{}", "utf8");
    fs.writeFileSync(path.join(workspace, ".mcp.json"), "{}", "utf8");
    const result = detectAdapterId(workspace, { env: {}, commandExists: never });
    assert.equal(result.id, "opencode");
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
});

test("detection layer 3: claude on PATH alone resolves to claude", () => {
  const result = detectAdapterId(null, {
    env: {},
    commandExists: only("claude"),
  });
  assert.equal(result.id, "claude");
  assert.equal(result.layer, "cli");
  assert.equal(result.reason, "cli_on_path_claude");
});

test("detection layer 3: codex on PATH alone resolves to codex", () => {
  const result = detectAdapterId(null, {
    env: {},
    commandExists: only("codex"),
  });
  assert.equal(result.id, "codex");
  assert.equal(result.layer, "cli");
  assert.equal(result.reason, "cli_on_path_codex");
});

test("detection layer 3: kimi on PATH alone resolves to kimi", () => {
  const result = detectAdapterId(null, {
    env: {},
    commandExists: only("kimi"),
  });
  assert.equal(result.id, "kimi");
  assert.equal(result.layer, "cli");
  assert.equal(result.reason, "cli_on_path_kimi");
});

test("detection layer 3: opencode on PATH alone resolves to opencode", () => {
  const result = detectAdapterId(null, {
    env: {},
    commandExists: only("opencode"),
  });
  assert.equal(result.id, "opencode");
  assert.equal(result.layer, "cli");
  assert.equal(result.reason, "cli_on_path_opencode");
});

test("detection layer 3: both CLIs on PATH falls through to fallback", () => {
  const result = detectAdapterId(null, {
    env: {},
    commandExists: always,
  });
  assert.equal(result.id, "claude");
  assert.equal(result.layer, "fallback");
  assert.equal(result.reason, "default_fallback");
});

test("detection layer 4: nothing detected resolves to claude default", () => {
  const result = detectAdapterId(null, {
    env: {},
    commandExists: never,
  });
  assert.equal(result.id, "claude");
  assert.equal(result.layer, "fallback");
  assert.equal(result.reason, "default_fallback");
});

test("detection: missing projectDir does not throw", () => {
  const result = detectAdapterId(undefined, { env: {}, commandExists: never });
  assert.equal(result.id, "claude");
});

test("detection: nonexistent projectDir does not throw and falls through", () => {
  const result = detectAdapterId("/nonexistent/path/that/does/not/exist", {
    env: {},
    commandExists: never,
  });
  assert.equal(result.id, "claude");
  assert.equal(result.layer, "fallback");
});
