"use strict";

const net = require("net");

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

function ipv4ToNumber(address) {
  const parts = String(address).split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^[0-9]+$/.test(part)) return null;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    value = (value << 8) + octet;
  }
  return value >>> 0;
}

function isPrivateIpv4(address) {
  const value = ipv4ToNumber(address);
  if (value == null) return false;
  return (
    (value >>> 24) === 0 ||
    (value >>> 24) === 10 ||
    (value >>> 24) === 127 ||
    (value >= ipv4ToNumber("100.64.0.0") && value <= ipv4ToNumber("100.127.255.255")) ||
    (value >= ipv4ToNumber("169.254.0.0") && value <= ipv4ToNumber("169.254.255.255")) ||
    (value >= ipv4ToNumber("172.16.0.0") && value <= ipv4ToNumber("172.31.255.255")) ||
    (value >= ipv4ToNumber("192.168.0.0") && value <= ipv4ToNumber("192.168.255.255"))
  );
}

function expandIpv6(address) {
  const value = String(address || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!value) return null;
  const halves = value.split("::");
  if (halves.length > 2) return null;

  const parseSide = (side) => {
    if (!side) return [];
    return side.split(":").filter((part) => part.length > 0).map((part) => {
      if (!/^[0-9a-f]{1,4}$/i.test(part)) return null;
      return Number.parseInt(part, 16);
    });
  };

  const left = parseSide(halves[0]);
  const right = halves.length === 2 ? parseSide(halves[1]) : [];
  if (left.some((part) => part == null) || right.some((part) => part == null)) return null;
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 0) return null;
  return [...left, ...Array(Math.max(0, missing)).fill(0), ...right];
}

function isBlockedIpv6(address) {
  const parts = expandIpv6(address);
  if (!parts || parts.length !== 8) return false;

  const isUnspecified = parts.every((part) => part === 0);
  const isLoopback = parts.slice(0, 7).every((part) => part === 0) && parts[7] === 1;
  const isUniqueLocal = (parts[0] & 0xfe00) === 0xfc00;
  const isLinkLocal = (parts[0] & 0xffc0) === 0xfe80;
  const isIpv4Mapped = parts.slice(0, 5).every((part) => part === 0) && parts[5] === 0xffff;

  return isUnspecified || isLoopback || isUniqueLocal || isLinkLocal || isIpv4Mapped;
}

function normalizeValidationHost(hostname) {
  return String(hostname || "").toLowerCase().replace(/\.+$/, "");
}

function isBlockedInternalHost(hostname) {
  const host = normalizeValidationHost(hostname);
  const address = host.replace(/^\[|\]$/g, "");
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "metadata" ||
    host === "metadata.google.internal" ||
    host.endsWith(".internal") ||
    host.endsWith(".local") ||
    host.endsWith(".localdomain")
  ) {
    return true;
  }

  const ipVersion = net.isIP(address);
  if (ipVersion === 4) {
    return isPrivateIpv4(address);
  }
  if (ipVersion === 6) {
    return isBlockedIpv6(address);
  }

  return false;
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
  const host = normalizeValidationHost(parsed.hostname);
  if (isBlockedInternalHost(host)) {
    throw new Error(`Blocked internal/private host: ${host}`);
  }
}

module.exports = {
  hostnameFromUrl,
  hostnamesForSurface,
  isBlockedInternalHost,
  isFirstPartyHost,
  pathLooksRelevantToSurface,
  recordMatchesSurface,
  requestPathFromUrl,
  safeUrlObject,
  stripUrlFragment,
  validateScanUrl,
};
