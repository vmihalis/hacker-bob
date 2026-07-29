"use strict";

// Per-workspace session roots.
//
// mcp/lib/engine-lock.js elects exactly ONE engine per session root (the
// fx-gate-bypass defense: a second engine over the SAME session state would
// boot with fresh in-process gate state — circuit breakers, request budgets,
// terminal blocks — and could drive that state past gates the first engine is
// enforcing). That lock is root-level because a booting engine does not yet
// know its target domain.
//
// Two Claude Code workspaces therefore collide only because they SHARE a root.
// Give each installed workspace its own DISJOINT root and the defense holds by
// construction — the engines share no session state at all — while the lock
// stays exactly as strong WITHIN each root. This module owns the derivation of
// that per-workspace root and the shape of the `.mcp.json` server entry that
// carries it (BOB_SESSIONS_ROOT, read once at engine boot by
// mcp/lib/paths.js and frozen there).
//
// The root is OPERATOR configuration: it is written into the installer-managed
// `.mcp.json` env block (and mirrored into `.claude/settings.json` env so the
// host's hooks resolve the same root as the engine). An agent cannot change the
// engine's boot environment, and no MCP tool exposes the knob.

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const SESSIONS_ROOT_ENV_VAR = "BOB_SESSIONS_ROOT";
const SESSIONS_ROOT_BASENAME = "hacker-bob-sessions";

// 48 bits of the workspace-path digest. Long enough that two workspaces on one
// machine never collide; short enough that the directory name stays readable.
const WORKSPACE_DIGEST_LENGTH = 12;
const WORKSPACE_SLUG_MAX_LENGTH = 24;

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function homeDir(home) {
  return home || os.homedir();
}

function defaultSessionsRoot({ home } = {}) {
  return path.join(homeDir(home), SESSIONS_ROOT_BASENAME);
}

// The derivation input. realpath so that installing through a symlinked path
// and through the real path produce the SAME root (an unstable root would
// orphan the workspace's prior sessions on the next install). Falls back to the
// resolved path when the target does not exist yet.
function canonicalWorkspacePath(targetAbs) {
  const resolved = path.resolve(targetAbs);
  try {
    return fs.realpathSync(resolved);
  } catch {
    return resolved;
  }
}

function workspaceSlug(canonical) {
  const slug = path.basename(canonical)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, WORKSPACE_SLUG_MAX_LENGTH)
    .replace(/-+$/g, "");
  return slug;
}

// `~/hacker-bob-sessions-<workspace-slug>-<digest>`.
//
// Deterministic in the workspace path alone, so re-installing the same
// workspace always resolves to the same root. A SIBLING of the default root,
// never a child of it and never a parent: mcp/lib/paths.js refuses a root that
// is strictly nested with the default root, because a nested root shares
// session state with the root that contains it while electing a second engine.
// Distinct workspaces get distinct digests, so their roots are mutually
// disjoint too.
function workspaceSessionsRoot(targetAbs, { home } = {}) {
  const canonical = canonicalWorkspacePath(targetAbs);
  const digest = crypto.createHash("sha256")
    .update(canonical)
    .digest("hex")
    .slice(0, WORKSPACE_DIGEST_LENGTH);
  const slug = workspaceSlug(canonical);
  const basename = slug
    ? `${SESSIONS_ROOT_BASENAME}-${slug}-${digest}`
    : `${SESSIONS_ROOT_BASENAME}-${digest}`;
  return path.join(homeDir(home), basename);
}

// True when the shared default root holds at least one session directory.
// Session dirs are `<target-domain>/`; dotfiles (`.engine.lock`) and the empty
// root the installer pre-creates do not count.
function defaultSessionsRootHasSessions({ home } = {}) {
  let entries;
  try {
    entries = fs.readdirSync(defaultSessionsRoot({ home }), { withFileTypes: true });
  } catch {
    return false;
  }
  return entries.some((entry) => entry.isDirectory() && !entry.name.startsWith("."));
}

function firstPinnedSessionsRoot(candidates) {
  for (const candidate of candidates || []) {
    if (typeof candidate !== "string") continue;
    const trimmed = candidate.trim();
    if (trimmed && path.isAbsolute(trimmed)) return trimmed;
  }
  return null;
}

// Reads an already-configured BOB_SESSIONS_ROOT out of a host config document
// (`.mcp.json`, `.kimi/mcp.json`) so re-installs preserve it verbatim.
function pinnedSessionsRootFromMcpConfig(mcp) {
  if (!isPlainObject(mcp) || !isPlainObject(mcp.mcpServers)) return null;
  for (const key of ["hacker-bob", "bountyagent"]) {
    const entry = mcp.mcpServers[key];
    if (!isPlainObject(entry) || !isPlainObject(entry.env)) continue;
    const value = entry.env[SESSIONS_ROOT_ENV_VAR];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return null;
}

function pinnedSessionsRootFromSettings(settings) {
  if (!isPlainObject(settings) || !isPlainObject(settings.env)) return null;
  const value = settings.env[SESSIONS_ROOT_ENV_VAR];
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

// Decides which session root THIS install writes into the workspace config.
//
//   operator_pinned  — a BOB_SESSIONS_ROOT is already configured for this
//                      workspace. Preserved verbatim: operator config wins, and
//                      preserving it is what keeps the root stable across
//                      re-installs.
//   shared_default   — the workspace was already installed and the shared
//                      default root still holds sessions. Keep the default so a
//                      re-install never orphans work in flight. `sessionsRoot`
//                      is null: no env is written and behavior is byte-identical
//                      to pre-override installs.
//   derived          — everything else (fresh installs, and re-installs with
//                      nothing left in the default root). The workspace gets its
//                      own disjoint root and can run an engine concurrently with
//                      other workspaces.
function resolveWorkspaceSessionsRoot({
  targetAbs,
  pinned = [],
  previouslyInstalled = false,
  home,
} = {}) {
  const pin = firstPinnedSessionsRoot(pinned);
  if (pin) return { sessionsRoot: pin, source: "operator_pinned" };
  if (previouslyInstalled && defaultSessionsRootHasSessions({ home })) {
    return { sessionsRoot: null, source: "shared_default" };
  }
  return { sessionsRoot: workspaceSessionsRoot(targetAbs, { home }), source: "derived" };
}

// 0700 so the root passes the ownership/mode assertions mcp/lib/paths.js and
// mcp/lib/engine-lock.js apply before an engine writes a single audit-graded
// byte. Idempotent; never widens the mode of a directory that already exists.
function ensureSessionsRoot(sessionsRoot) {
  fs.mkdirSync(sessionsRoot, { recursive: true, mode: 0o700 });
  return sessionsRoot;
}

// The Bob-managed `mcpServers["hacker-bob"]` entry. With no sessionsRoot the
// shape is byte-identical to what Bob has always written.
function bobMcpServerEntry({ serverPath, sessionsRoot = null } = {}) {
  const entry = { command: "node", args: [serverPath] };
  if (sessionsRoot) entry.env = { [SESSIONS_ROOT_ENV_VAR]: sessionsRoot };
  return entry;
}

// "Is this entry Bob's to rewrite/remove?" — used by every adapter's doctor and
// uninstall. Structural rather than JSON-string equality so the optional env
// block does not make a Bob-managed entry look operator-owned. An entry
// carrying any OTHER env key or top-level field is NOT claimed: that is an
// operator edit, and uninstall must leave it alone.
function isBobManagedMcpServerEntry(entry, { serverPath } = {}) {
  if (!isPlainObject(entry)) return false;
  if (entry.command !== "node") return false;
  if (!Array.isArray(entry.args) || entry.args.length !== 1 || entry.args[0] !== serverPath) return false;
  for (const key of Object.keys(entry)) {
    if (key !== "command" && key !== "args" && key !== "env") return false;
  }
  if (entry.env === undefined) return true;
  if (!isPlainObject(entry.env)) return false;
  return Object.keys(entry.env).every((key) => key === SESSIONS_ROOT_ENV_VAR)
    && typeof entry.env[SESSIONS_ROOT_ENV_VAR] === "string";
}

module.exports = {
  SESSIONS_ROOT_BASENAME,
  SESSIONS_ROOT_ENV_VAR,
  bobMcpServerEntry,
  canonicalWorkspacePath,
  defaultSessionsRoot,
  defaultSessionsRootHasSessions,
  ensureSessionsRoot,
  isBobManagedMcpServerEntry,
  pinnedSessionsRootFromMcpConfig,
  pinnedSessionsRootFromSettings,
  resolveWorkspaceSessionsRoot,
  workspaceSessionsRoot,
};
