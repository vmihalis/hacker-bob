"use strict";

const { httpScan } = require("../../core/http-scan.js");
const { runAuthDifferential } = require("../../core/auth-differential-runner.js");
const { makePerCallHttpScanFetcher } = require("../../core/http-scan-adapter.js");
const { listAuthProfiles } = require("../../core/auth/auth.js");
const { extractIds, bindLineage } = require("../../core/param-lineage.js");

// deriveLineageEndpoints({ seed_responses, id_bearing_templates, profiles }) -> sorted,
// deduped string[] of concrete in-path endpoints. For each principal that supplied prior
// 2xx seed material, harvest its OWN id-shaped values via extractIds, then fill THIS
// surface's already-resolved, route-frozen id_bearing_templates via bindLineage. The point:
// a principal's OWN id-bearing object joins the sweep so it can earn a live 2xx there and
// count as a validated principal under U1b, enabling a genuine cross-tenant flip on another
// principal's object instead of a false negative.
//
// HONESTY / FAIL-SAFE: reuses extractIds/bindLineage VERBATIM (both pure), so a value only
// appears if it was literally present in that principal's own supplied body. Absent
// seed_responses, a non-JSON/idless seed, or an empty/unresolvable template set each yield
// [] — no fabricated id, no forced arm. The frozen templates round-trip through
// templatizeIdBearingEndpoint (inside bindLineage), so every derived endpoint composes back
// into the runner's idBearingTemplateSet membership check; the seed influences endpoint
// SELECTION only and never the live 2xx/401 outcome, so U1b stays un-weakened.
function deriveLineageEndpoints({ seed_responses, id_bearing_templates, profiles } = {}) {
  if (!seed_responses || typeof seed_responses !== "object" || Array.isArray(seed_responses)) {
    return [];
  }
  const templates = Array.isArray(id_bearing_templates)
    ? id_bearing_templates.filter((t) => typeof t === "string" && t)
    : [];
  if (templates.length === 0) return [];
  const profileNames = Array.isArray(profiles) && profiles.some((p) => typeof p === "string" && p)
    ? profiles.filter((p) => typeof p === "string" && p)
    : Object.keys(seed_responses);
  const derived = new Set();
  for (const name of profileNames) {
    const seed = seed_responses[name];
    if (!seed || typeof seed !== "object" || Array.isArray(seed)) continue;
    const ids = extractIds(seed.body, { contentType: seed.content_type });
    for (const template of templates) {
      for (const endpoint of bindLineage(template, ids)) derived.add(endpoint);
    }
  }
  return Array.from(derived).sort();
}

const UNAUTH_PROFILE_NAMES = new Set([
  "anon",
  "anonymous",
  "guest",
  "noauth",
  "no-auth",
  "public",
  "unauth",
  "unauthenticated",
]);

function deriveDefaultProfileMetadata(authProfiles) {
  const metadata = {};
  for (const profile of authProfiles) {
    const lower = typeof profile === "string" ? profile.toLowerCase() : "";
    metadata[profile] = {
      sent_with_auth: !UNAUTH_PROFILE_NAMES.has(lower),
    };
  }
  return metadata;
}

async function runAuthDifferentialToolHandler(args) {
  const fetch_fn = makePerCallHttpScanFetcher({
    httpScanFn: httpScan,
    target_domain: args.target_domain,
    block_internal_hosts: args.block_internal_hosts,
    egress_profile: args.egress_profile,
    // The differential sweep opts IN to per-arm transport freshness (no-cache request headers) so
    // a cached/stale response can never stand in for a live cross-tenant arm. Other callers of
    // makePerCallHttpScanFetcher (composition-live-verifier, the belief probe) stay default-off.
    freshness: true,
  });
  const baseMetadata = args.profile_metadata && typeof args.profile_metadata === "object"
    ? args.profile_metadata
    : deriveDefaultProfileMetadata(args.auth_profiles);
  // Force the MCP-owned principal fingerprint onto each profile's metadata, OVERRIDING
  // any agent-supplied value, so the completion gate's distinct-principal check reads the
  // real auth identity (a 2-name/1-token sweep collapses to one fingerprint) and never an
  // agent-forgeable field.
  const fingerprintByProfile = {};
  try {
    const listed = JSON.parse(listAuthProfiles({ target_domain: args.target_domain }));
    for (const p of (listed && Array.isArray(listed.profiles) ? listed.profiles : [])) {
      if (p && typeof p.profile_name === "string") {
        fingerprintByProfile[p.profile_name] = typeof p.principal_fingerprint === "string" ? p.principal_fingerprint : null;
      }
    }
  } catch { /* no auth store -> fingerprints null -> gate stays fail-closed on distinctness */ }
  const profileMetadata = {};
  for (const name of args.auth_profiles) {
    profileMetadata[name] = {
      ...(baseMetadata[name] && typeof baseMetadata[name] === "object" ? baseMetadata[name] : {}),
      principal_fingerprint: fingerprintByProfile[name] || null,
    };
  }
  // Resolve THIS surface's FROZEN id-bearing endpoint templates from the MCP-owned route
  // (surface-routes.json) — the SAME source and shape the grade-time gate reads
  // (claims.js:1954-1965) — and hand them to the runner so a principal counts as validated-for-
  // flip only on a 2xx against one of this surface's gated id-bearing endpoints. Fall back to []
  // on any unreadable/missing route so the flip FAILS CLOSED (an unresolvable set validates no
  // principal) instead of admitting a public-endpoint 2xx. Mirrors claims.js exactly so the
  // runner and the gate never drift on what counts as an id-bearing endpoint.
  let idBearingTemplates = [];
  try {
    const { readSurfaceRoutesStrict } = require("../../core/frontier/surface-router.js");
    for (const route of (readSurfaceRoutesStrict(args.target_domain).document.routes || [])) {
      if (route && route.surface_id === args.surface_id) {
        idBearingTemplates = Array.isArray(route.id_bearing_endpoints)
          ? route.id_bearing_endpoints.filter((e) => typeof e === "string" && e)
          : [];
        break;
      }
    }
  } catch { /* routes unreadable/absent -> [] -> id-bearing flip arm fails closed */ }
  // Wire param-lineage into the sweep prep: derive each principal's OWN id-bearing object
  // (extractIds -> bindLineage over the SAME frozen idBearingTemplates resolved above) from
  // its supplied prior 2xx material and merge those concrete endpoints into the sweep, so the
  // attacker arm can 2xx its own object and validate under U1b -> a real cross-tenant flip
  // instead of a false negative. Dedupe derived paths by (endpoint, method) against agent-
  // supplied endpoints so a lineage path the agent also passed does not mint a duplicate row;
  // derived entries default to GET (read BOLA probe). Fail-safe: no seed / non-JSON / idless /
  // empty templates -> derivedEndpoints is [] and mergedEndpoints is byte-equivalent to
  // args.endpoints (behavior identical to omitting seed_responses).
  const derivedEndpoints = deriveLineageEndpoints({
    seed_responses: args.seed_responses,
    id_bearing_templates: idBearingTemplates,
    profiles: args.auth_profiles,
  });
  const mergedEndpoints = Array.isArray(args.endpoints) ? args.endpoints.slice() : args.endpoints;
  if (Array.isArray(mergedEndpoints) && derivedEndpoints.length > 0) {
    const seenEndpointKeys = new Set();
    for (const entry of mergedEndpoints) {
      if (typeof entry === "string" && entry) {
        seenEndpointKeys.add(`${entry}\tGET`);
      } else if (entry && typeof entry === "object" && typeof entry.endpoint === "string") {
        const method = typeof entry.method === "string" && entry.method ? entry.method.toUpperCase() : "GET";
        seenEndpointKeys.add(`${entry.endpoint}\t${method}`);
      }
    }
    for (const endpoint of derivedEndpoints) {
      const key = `${endpoint}\tGET`;
      if (!seenEndpointKeys.has(key)) {
        seenEndpointKeys.add(key);
        mergedEndpoints.push(endpoint);
      }
    }
  }
  const result = await runAuthDifferential({
    target_domain: args.target_domain,
    base_url: args.base_url,
    endpoints: mergedEndpoints,
    auth_profiles: args.auth_profiles,
    fetch_fn,
    profile_metadata: profileMetadata,
    run_id: args.run_id,
    limit: args.limit,
    surface_id: args.surface_id,
    id_bearing_templates: idBearingTemplates,
    deadline_ms: args.sweep_deadline_ms,
  });
  return {
    schema_version: result.schema_version,
    summary: result.summary,
    results_hash: result.results_hash,
    results_path: "auth-differential-results.json",
  };
}

const toolDescriptor = {
  name: "bob_run_auth_differential",
  capability_id: "C4_multi_account_differential",
  description:
    "Run a multi-account differential across the supplied endpoints. For each endpoint, issues a request via bob_http_scan once per auth_profile, classifies divergences (status, response class, body shape, body length, sensitive-field count, unauth-success-with-auth-blocked), and writes auth-differential-results.json. Provide profile_metadata to flag genuine auth bypass; otherwise the tool auto-derives sent_with_auth: false for profile names matching guest/anon/noauth/etc.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      surface_id: {
        type: "string",
        description: "The surface this sweep is run for. Pass it so the completion gate binds this coverage to the surface actually tested (an id-bearing surface only earns completion via a sweep stamped with ITS surface_id on ITS id-bearing endpoint).",
      },
      base_url: {
        type: "string",
        description: "Base URL the endpoint paths are joined onto.",
      },
      endpoints: {
        type: "array",
        items: {
          oneOf: [
            { type: "string" },
            {
              type: "object",
              properties: {
                endpoint: { type: "string" },
                method: { type: "string" },
              },
              required: ["endpoint"],
            },
          ],
        },
        description: "Endpoints to differential-test. Each entry is either a path string (defaults to GET) or {endpoint, method}.",
      },
      auth_profiles: {
        type: "array",
        items: { type: "string" },
        minItems: 2,
        description: "Two or more auth profile names to compare. Names like guest/anon/noauth auto-flag sent_with_auth: false unless profile_metadata overrides.",
      },
      profile_metadata: {
        type: "object",
        description: "Optional per-profile metadata. Keyed by profile name; supports sent_with_auth boolean and role string.",
      },
      seed_responses: {
        type: "object",
        description: "Optional per-profile prior 2xx material, keyed by profile name -> { body: string|object, content_type?: string }. Each principal's OWN id-bearing object is derived from its seed via param-lineage (extractIds+bindLineage over this surface's frozen id_bearing_endpoints) and merged into the sweep, so the attacker arm can 2xx its own object and validate for a real cross-tenant flip. An absent/non-JSON/idless seed contributes nothing (no fabricated id); omitting this field is byte-identical to today's sweep.",
      },
      run_id: {
        type: "string",
        description: "Optional opaque identifier captured in the result summary.",
      },
      limit: {
        type: "integer",
        minimum: 1,
        maximum: 1000,
        description: "Max endpoints to test in this run. Defaults to the runner's internal cap.",
      },
      sweep_deadline_ms: {
        type: "integer",
        minimum: 1000,
        description: "Optional sweep-wide wall-clock budget (ms). When the elapsed time reaches it, the sweep STOPS issuing further arms and leaves remaining endpoints un-run (no row, so they can never flip) — an honest partial, never a forced flip. Omitted: no deadline (today's behavior). This is an additive total-runtime guard on top of the per-request timeout.",
      },
      block_internal_hosts: {
        type: "boolean",
        description: "Forwarded to bob_http_scan. When omitted, the session's persisted effective policy is used by bob_http_scan.",
      },
      egress_profile: {
        type: "string",
        pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        description: "Forwarded to bob_http_scan when set.",
      },
    },
    required: ["target_domain", "base_url", "endpoints", "auth_profiles", "surface_id"],
  },
  handler: runAuthDifferentialToolHandler,
  role_bundles: ["orchestrator", "evaluator-web"],
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: true,
  scope_url_fields: ["base_url"],
  sensitive_output: true,
 session_artifacts_written: ["auth-differential-results.json"],
  required_session_axes: ["url"],
};

// Expose the pure lineage-derivation helper to tests/callers WITHOUT polluting the
// tool-registry descriptor shape: a non-enumerable property is invisible to defineTool's
// `{...entry}` spread and every Object.keys/JSON path, so the registry entry and
// mcp-server.test.js tool-name/schema assertions are unaffected.
Object.defineProperty(toolDescriptor, "deriveLineageEndpoints", {
  value: deriveLineageEndpoints,
  enumerable: false,
});

module.exports = Object.freeze(toolDescriptor);
