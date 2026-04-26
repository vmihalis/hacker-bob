"use strict";

const claude = require("./claude/index.js");
const codex = require("./codex/index.js");
const genericMcp = require("./generic-mcp/index.js");

const ADAPTERS = Object.freeze({
  [claude.id]: claude,
  [codex.id]: codex,
  [genericMcp.id]: genericMcp,
});
const DEFAULT_ADAPTER_ID = "claude";
const ALL_ADAPTER_IDS = Object.freeze(Object.keys(ADAPTERS));

function getAdapter(id) {
  const adapter = ADAPTERS[id];
  if (!adapter) throw new Error(`Unknown Bob adapter: ${id}`);
  return adapter;
}

function normalizeSelection(selection) {
  if (selection == null || selection === "") return [];
  if (Array.isArray(selection)) return selection.flatMap((value) => normalizeSelection(value));
  return String(selection)
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function adapterIdsForSelection(selection, options = {}) {
  const defaultIds = options.defaultIds || [DEFAULT_ADAPTER_ID];
  const rawIds = normalizeSelection(selection);
  const requested = rawIds.length === 0 ? defaultIds : rawIds;
  const expanded = requested.includes("all") ? ALL_ADAPTER_IDS : requested;
  const seen = new Set();
  const ids = [];
  for (const id of expanded) {
    getAdapter(id);
    if (seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
  }
  return ids;
}

module.exports = {
  ADAPTERS,
  ALL_ADAPTER_IDS,
  DEFAULT_ADAPTER_ID,
  adapterIdsForSelection,
  getAdapter,
};
