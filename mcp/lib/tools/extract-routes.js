"use strict";

const { extractRoutesFromFiles } = require("../route-extractor.js");
const { appendFrontierEvent } = require("../frontier-events.js");
const { scheduleMaterialization } = require("../frontier-materialize-debounce.js");

function extractRoutesHandler(args) {
  const routes = extractRoutesFromFiles(args.files);
  // Dual-write per Pact P2: each extracted route is a surface signal. Emit a
  // single observation.recorded event capturing the batch so the frontier
  // projection sees the static route surface without one event per row.
  if (routes.length > 0 && typeof args.target_domain === "string" && args.target_domain.trim()) {
    try {
      appendFrontierEvent({
        target_domain: args.target_domain,
        kind: "observation.recorded",
        payload: {
          observation_kind: "route_extraction",
          file_count: Array.isArray(args.files) ? args.files.length : 0,
          route_count: routes.length,
          frameworks: Array.from(new Set(routes.map((route) => route.framework))).sort(),
          methods: Array.from(new Set(routes.map((route) => route.method))).sort(),
        },
        source: { artifact: "route-extraction", tool: "bob_extract_routes" },
      });
      scheduleMaterialization(args.target_domain);
    } catch {
      // Frontier ledger is dual-write best-effort during the deprecation window.
    }
  }
  return {
    schema_version: 1,
    target_domain: args.target_domain,
    file_count: Array.isArray(args.files) ? args.files.length : 0,
    route_count: routes.length,
    routes,
  };
}

module.exports = Object.freeze({
  name: "bob_extract_routes",
  aliases: ["bounty_extract_routes"],
  description:
    "Run regex-based HTTP route extraction across one or more source files. Supports Express, Koa, Fastify, NestJS (JS/TS), Flask, Django (Python), and Spring (Java/Kotlin). Each emitted route carries (framework, method, path, file, line, handler_hint, edge_kind). Output sorted deterministically; tuple-deduped. Pass to bob_build_symbol_surface_index to derive the file:line -> surface index.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      files: {
        type: "array",
        description: "Array of {file, source, language?} entries. language auto-detects from file extension when omitted.",
        items: {
          type: "object",
          properties: {
            file: { type: "string" },
            source: { type: "string" },
            language: { type: "string" },
          },
          required: ["source"],
        },
      },
    },
    required: ["target_domain", "files"],
  },
  handler: extractRoutesHandler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
