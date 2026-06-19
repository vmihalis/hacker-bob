"use strict";

const fs = require("fs");
const {
  assertSafeDomain,
  attackSurfacePath,
  sessionDir,
  symbolSurfaceIndexPath,
} = require("./paths.js");
const {
  readJsonFile,
} = require("./storage.js");
const { hashCanonicalJson } = require("./verification-contracts.js");

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function ensureSessionDir(domain) {
  const dir = sessionDir(domain);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function safeReadAttackSurfaceSurfaces(domain) {
  const filePath = attackSurfacePath(domain);
  if (!fs.existsSync(filePath)) return [];
  try {
    const parsed = readJsonFile(filePath, { label: "attack_surface.json" });
    if (!isPlainObject(parsed) || !Array.isArray(parsed.surfaces)) return [];
    return parsed.surfaces;
  } catch (_err) {
    return [];
  }
}

function normalizeRoutePath(path) {
  if (typeof path !== "string") return "";
  return path
    .replace(/:[A-Za-z_][\w]*/g, "{x}")
    .replace(/<[^>]*?>/g, "{x}")
    .replace(/\{[A-Za-z_][\w]*\}/g, "{x}")
    .replace(/\/+$/, "");
}

function pathSegments(path) {
  if (typeof path !== "string" || path.length === 0) return [];
  return path.split("/").filter((segment) => segment.length > 0);
}

function pathMatchesSurfaceHint(routePath, hintPath) {
  if (typeof routePath !== "string" || typeof hintPath !== "string") return false;
  if (routePath === hintPath) return true;
  const routeNorm = normalizeRoutePath(routePath);
  const hintNorm = normalizeRoutePath(hintPath);
  if (routeNorm === hintNorm) return true;
  if (routeNorm.length === 0 || hintNorm.length === 0) return false;
  if (routeNorm.startsWith(hintNorm + "/")) return true;
  if (hintNorm.startsWith(routeNorm + "/")) return true;
  return false;
}

function findMatchingSurfaceIds(routePath, surfaces) {
  if (!Array.isArray(surfaces) || surfaces.length === 0) return [];
  const matched = new Set();
  for (const surface of surfaces) {
    if (!isPlainObject(surface)) continue;
    const surfaceId = typeof surface.id === "string" ? surface.id : null;
    if (!surfaceId) continue;
    let isMatch = false;
    if (typeof surface.endpoint_pattern === "string"
      && pathMatchesSurfaceHint(routePath, surface.endpoint_pattern)) {
      isMatch = true;
    }
    if (!isMatch && Array.isArray(surface.endpoints)) {
      for (const endpoint of surface.endpoints) {
        if (typeof endpoint === "string" && pathMatchesSurfaceHint(routePath, endpoint)) {
          isMatch = true;
          break;
        }
      }
    }
    if (isMatch) matched.add(surfaceId);
  }
  return Array.from(matched).sort();
}

function buildSymbolSurfaceIndex({ target_domain, route_records, surfaces }) {
  const domain = assertSafeDomain(target_domain);
  if (!Array.isArray(route_records)) {
    throw new TypeError("route_records must be an array");
  }
  const surfaceList = Array.isArray(surfaces) ? surfaces : safeReadAttackSurfaceSurfaces(domain);
  const byKey = new Map();
  const byFile = new Map();
  const bySurface = new Map();
  for (const route of route_records) {
    if (!isPlainObject(route)) continue;
    if (typeof route.file !== "string" || typeof route.line !== "number") continue;
    if (typeof route.path !== "string") continue;
    const matchedSurfaces = findMatchingSurfaceIds(route.path, surfaceList);
    const entry = {
      file: route.file,
      line: route.line,
      framework: typeof route.framework === "string" ? route.framework : null,
      method: typeof route.method === "string" ? route.method : null,
      path: route.path,
      handler_hint: typeof route.handler_hint === "string" ? route.handler_hint : null,
      edge_kind: typeof route.edge_kind === "string" ? route.edge_kind : "route",
      surface_ids: matchedSurfaces,
    };
    const key = `${route.file}:${route.line}`;
    byKey.set(key, entry);
    if (!byFile.has(route.file)) byFile.set(route.file, []);
    byFile.get(route.file).push(entry);
    for (const surfaceId of matchedSurfaces) {
      if (!bySurface.has(surfaceId)) bySurface.set(surfaceId, []);
      bySurface.get(surfaceId).push(entry);
    }
  }
  const index = {
    schema_version: 1,
    target_domain: domain,
    built_at: new Date().toISOString(),
    entry_count: byKey.size,
    surfaces_referenced: bySurface.size,
    by_file_line: Object.fromEntries(Array.from(byKey.entries()).sort(([a], [b]) => a.localeCompare(b))),
    by_file: Object.fromEntries(Array.from(byFile.entries()).map(([file, entries]) => [
      file,
      entries.slice().sort((a, b) => a.line - b.line),
    ]).sort(([a], [b]) => a.localeCompare(b))),
    by_surface: Object.fromEntries(Array.from(bySurface.entries()).map(([id, entries]) => [
      id,
      entries.slice().sort((a, b) => `${a.file}:${a.line}`.localeCompare(`${b.file}:${b.line}`)),
    ]).sort(([a], [b]) => a.localeCompare(b))),
  };
  index.index_hash = hashCanonicalJson({ ...index, built_at: null });
  ensureSessionDir(domain);
  fs.writeFileSync(symbolSurfaceIndexPath(domain), `${JSON.stringify(index, null, 2)}\n`, "utf8");
  return {
    target_domain: domain,
    entry_count: index.entry_count,
    surfaces_referenced: index.surfaces_referenced,
    index_hash: index.index_hash,
  };
}

function readSymbolSurfaceIndex(domain) {
  const safeDomain = assertSafeDomain(domain);
  const filePath = symbolSurfaceIndexPath(safeDomain);
  if (!fs.existsSync(filePath)) return null;
  try {
    return readJsonFile(filePath, { label: "symbol-surface-index.json" });
  } catch (err) {
    throw new Error(`Malformed symbol-surface-index.json: ${err.message || String(err)}`);
  }
}

function lookupByFileLine({ target_domain, file, line }) {
  const index = readSymbolSurfaceIndex(target_domain);
  if (index == null) return null;
  const key = `${file}:${line}`;
  return index.by_file_line[key] || null;
}

function lookupByFile({ target_domain, file }) {
  const index = readSymbolSurfaceIndex(target_domain);
  if (index == null) return [];
  return index.by_file[file] || [];
}

function lookupBySurfaceId({ target_domain, surface_id }) {
  const index = readSymbolSurfaceIndex(target_domain);
  if (index == null) return [];
  return index.by_surface[surface_id] || [];
}

function lineInRanges(line, ranges) {
  if (!Array.isArray(ranges) || ranges.length === 0) return false;
  for (const range of ranges) {
    if (!isPlainObject(range)) continue;
    const start = typeof range.start === "number" ? range.start : null;
    const end = typeof range.end === "number" ? range.end : start;
    if (start == null) continue;
    if (line >= start && line <= (end == null ? start : end)) return true;
  }
  return false;
}

function summarizeImpactedSurfacesForDiff({ target_domain, diff_files }) {
  const index = readSymbolSurfaceIndex(target_domain);
  if (index == null) {
    return { impacted_entries: [], impacted_surface_ids: [], scanned_files: 0, path_used: "B" };
  }
  if (!Array.isArray(diff_files)) {
    throw new TypeError("diff_files must be an array of {file, line_ranges}");
  }
  const impactedEntries = [];
  const impactedSurfaceIds = new Set();
  let scannedFiles = 0;
  for (const diffFile of diff_files) {
    if (!isPlainObject(diffFile)) continue;
    if (typeof diffFile.file !== "string") continue;
    scannedFiles += 1;
    const fileEntries = index.by_file[diffFile.file];
    if (!Array.isArray(fileEntries)) continue;
    const ranges = Array.isArray(diffFile.line_ranges) ? diffFile.line_ranges : [{ start: 1, end: Infinity }];
    for (const entry of fileEntries) {
      if (!lineInRanges(entry.line, ranges)) continue;
      impactedEntries.push(entry);
      for (const surfaceId of entry.surface_ids) {
        impactedSurfaceIds.add(surfaceId);
      }
    }
  }
  return {
    impacted_entries: impactedEntries.sort((a, b) => `${a.file}:${a.line}`.localeCompare(`${b.file}:${b.line}`)),
    impacted_surface_ids: Array.from(impactedSurfaceIds).sort(),
    scanned_files: scannedFiles,
    path_used: "A",
  };
}

module.exports = {
  buildSymbolSurfaceIndex,
  readSymbolSurfaceIndex,
  lookupByFileLine,
  lookupByFile,
  lookupBySurfaceId,
  summarizeImpactedSurfacesForDiff,
};
