"use strict";

const fs = require("fs");
const {
  assertNonEmptyString,
} = require("./validation.js");
const {
  attackSurfacePath,
} = require("./paths.js");

function readAttackSurfaceStrict(domain) {
  const filePath = attackSurfacePath(domain);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing attack surface JSON: ${filePath}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`Malformed attack surface JSON: ${filePath} (${error.message || String(error)})`);
  }

  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.surfaces)) {
    throw new Error(`Malformed attack surface JSON: ${filePath} (expected object with surfaces array)`);
  }

  const surfaceIds = [];
  const surfaceIdSet = new Set();
  for (const surface of parsed.surfaces) {
    let surfaceId;
    try {
      if (surface == null || typeof surface !== "object" || Array.isArray(surface)) {
        throw new Error("invalid surface entry");
      }
      surfaceId = assertNonEmptyString(surface.id, "surface.id");
    } catch (error) {
      throw new Error(`Malformed attack surface JSON: ${filePath} (${error.message || String(error)})`);
    }
    if (surfaceIdSet.has(surfaceId)) continue;
    surfaceIdSet.add(surfaceId);
    surfaceIds.push(surfaceId);
  }

  return {
    path: filePath,
    document: parsed,
    surface_ids: surfaceIds,
    surface_id_set: surfaceIdSet,
  };
}

module.exports = {
  readAttackSurfaceStrict,
};
