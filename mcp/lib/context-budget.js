"use strict";

const {
  assertNonEmptyString,
  normalizeOptionalText,
} = require("./validation.js");
const {
  readAttackSurfaceStrict,
} = require("./attack-surface.js");
const {
  readSurfaceRoutesStrict,
} = require("./surface-router.js");
const {
  getCapabilityPack,
  getCapabilityPackContextBudget,
  normalizeContextBudget,
} = require("./capability-packs.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");

function getContextBudget(args) {
  const capabilityPack = assertNonEmptyString(args.capability_pack, "capability_pack");
  const pack = getCapabilityPack(capabilityPack);
  if (!pack) {
    throw new Error(`Unknown capability_pack: ${capabilityPack}`);
  }

  const targetDomain = normalizeOptionalText(args.target_domain, "target_domain");
  const surfaceId = normalizeOptionalText(args.surface_id, "surface_id");
  let briefProfile = normalizeOptionalText(args.brief_profile, "brief_profile") || pack.brief_profile;
  let capabilityPackVersion = pack.capability_pack_version;
  let contextBudget = getCapabilityPackContextBudget(capabilityPack);

  if (surfaceId && !targetDomain) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "target_domain is required when surface_id is provided",
    );
  }

  if (briefProfile !== pack.brief_profile) {
    throw new Error(`brief_profile ${briefProfile} does not match capability_pack ${capabilityPack}`);
  }

  if (targetDomain && surfaceId) {
    const attackSurface = readAttackSurfaceStrict(targetDomain);
    if (!attackSurface.surface_id_set.has(surfaceId)) {
      throw new Error(`Unknown surface_id: ${surfaceId}`);
    }

    try {
      const routesInfo = readSurfaceRoutesStrict(targetDomain);
      const route = routesInfo.document.routes.find((entry) => entry.surface_id === surfaceId) || null;
      if (route) {
        if (route.capability_pack !== capabilityPack) {
          throw new Error(`surface_id ${surfaceId} is routed to capability_pack ${route.capability_pack}`);
        }
        briefProfile = route.brief_profile;
        capabilityPackVersion = route.capability_pack_version;
        contextBudget = normalizeContextBudget(route.context_budget, pack);
      } else if (Array.isArray(routesInfo.malformed_routes)) {
        // readSurfaceRoutesStrict quarantines a malformed route (e.g. an unsupported context_budget
        // field, or a stale cross-version schema) so read-all consumers do not brick. But a TARGETED
        // budget lookup for that exact surface must SURFACE the problem — the agent cannot operate
        // under an undefined budget — rather than silently fall back to the pack default.
        const malformed = routesInfo.malformed_routes.find((entry) => entry.surface_id === surfaceId);
        if (malformed) {
          throw new Error(`surface_id ${surfaceId} has a malformed route: ${malformed.reason}`);
        }
      }
    } catch (error) {
      if (!/Missing surface routes JSON:/.test(error.message || String(error))) {
        throw error;
      }
    }
  }

  return JSON.stringify({
    version: 1,
    capability_pack: capabilityPack,
    capability_pack_version: capabilityPackVersion,
    brief_profile: briefProfile,
    context_budget: contextBudget,
  });
}

module.exports = {
  getContextBudget,
};
