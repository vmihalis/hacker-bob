"use strict";

function safeUrlObject(value) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function stripUrlFragment(urlValue) {
  const parsed = safeUrlObject(urlValue);
  if (!parsed) return String(urlValue || "");
  parsed.hash = "";
  return parsed.toString();
}

function hostnameFromUrl(urlValue) {
  const parsed = safeUrlObject(urlValue);
  return parsed ? parsed.hostname.toLowerCase() : null;
}

function requestPathFromUrl(urlValue) {
  const parsed = safeUrlObject(urlValue);
  return parsed ? `${parsed.pathname}${parsed.search}` : "";
}

function isFirstPartyHost(hostname, targetDomain) {
  if (!hostname || !targetDomain) return false;
  const host = hostname.toLowerCase().replace(/\.+$/, "");
  const domain = targetDomain.toLowerCase().replace(/\.+$/, "");
  return host === domain || host.endsWith(`.${domain}`);
}

function stringArray(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item));
}

function hostnamesForSurface(surface) {
  const hostnames = [];
  const seen = new Set();
  for (const rawHost of stringArray(surface && surface.hosts)) {
    const parsedHost = hostnameFromUrl(rawHost) || rawHost.replace(/^https?:\/\//i, "").split(/[/?#]/, 1)[0];
    const host = parsedHost.toLowerCase().replace(/\.+$/, "");
    if (!host || seen.has(host)) continue;
    seen.add(host);
    hostnames.push(host);
  }
  return hostnames;
}

function pathLooksRelevantToSurface(pathValue, surface) {
  const requestPath = String(pathValue || "").split("#", 1)[0];
  const requestPathname = requestPath.split("?", 1)[0];
  if (!requestPath) return false;

  const candidates = [
    ...stringArray(surface && surface.endpoints),
    ...stringArray(surface && surface.discovered_endpoints),
    ...stringArray(surface && surface.js_endpoints),
  ];
  if (candidates.length === 0) return true;

  for (const candidate of candidates) {
    const parsed = safeUrlObject(candidate);
    const candidatePath = parsed
      ? `${parsed.pathname}${parsed.search}`
      : String(candidate || "");
    if (!candidatePath || !candidatePath.startsWith("/")) continue;
    const cleanCandidate = candidatePath.split("#", 1)[0];
    const candidatePathname = cleanCandidate.split("?", 1)[0];
    if (
      requestPath === cleanCandidate ||
      requestPath.startsWith(`${cleanCandidate.replace(/\/+$/, "")}/`) ||
      cleanCandidate.startsWith(`${requestPath.replace(/\/+$/, "")}/`) ||
      requestPathname === candidatePathname ||
      requestPathname.startsWith(`${candidatePathname.replace(/\/+$/, "")}/`) ||
      candidatePathname.startsWith(`${requestPathname.replace(/\/+$/, "")}/`)
    ) {
      return true;
    }
  }

  return false;
}

function recordMatchesSurface(record, surface) {
  if (!surface) return true;
  if (record.surface_id && surface.id && record.surface_id === surface.id) return true;

  const recordHost = (record.host || hostnameFromUrl(record.url) || "").toLowerCase();
  const surfaceHosts = hostnamesForSurface(surface);
  const hostMatches = surfaceHosts.length === 0 || surfaceHosts.some((host) => (
    recordHost === host || recordHost.endsWith(`.${host}`)
  ));
  if (!hostMatches) return false;

  return pathLooksRelevantToSurface(record.path || requestPathFromUrl(record.url), surface);
}

function validateScanUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Invalid URL");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`Unsupported protocol: ${parsed.protocol}`);
  }
  const host = parsed.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "[::1]" || host === "::1" ||
    host === "0.0.0.0" ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    host === "169.254.169.254" ||
    host.endsWith(".internal") ||
    host.endsWith(".local")
  ) {
    throw new Error(`Blocked internal/private host: ${host}`);
  }
}

module.exports = {
  hostnameFromUrl,
  hostnamesForSurface,
  isFirstPartyHost,
  pathLooksRelevantToSurface,
  recordMatchesSurface,
  requestPathFromUrl,
  safeUrlObject,
  stripUrlFragment,
  validateScanUrl,
};
