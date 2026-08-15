"use strict";

const fs = require("fs");
const path = require("path");
const { sessionDir } = require("../../../core/io/paths.js");
const { writeFileAtomic } = require("../../../core/io/storage.js");
const { isAddress } = require("./evm-client.js");
const {
  isPublicHttpsUrl,
  redactRpcEndpoint,
  redactRpcEndpointText,
} = require("./sc-egress-policy.js");
const { requestPublicHttpsText } = require("./sc-http-client.js");

const SOURCIFY_BASE = "https://sourcify.dev/server/files/any";
const ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api";

const SOURCE_FETCH_TIMEOUT_MS = 15_000;
const SOURCE_MAX_RESPONSE_BYTES = 1024 * 1024; // 1 MiB
const SOURCE_MAX_RETURN_BYTES = 512 * 1024;    // 512 KiB returned to the agent
const SOURCE_MAX_FILE_BYTES = 256 * 1024;      // 256 KiB per file
const SOURCE_MAX_FILES = 80;

function contractsCacheDir(domain, chainId, address) {
  return path.join(sessionDir(domain), "contracts", String(chainId), address.toLowerCase());
}

function readCachedSource(domain, chainId, address) {
  const cacheDir = contractsCacheDir(domain, chainId, address);
  const manifestPath = path.join(cacheDir, "source-manifest.json");
  if (!fs.existsSync(manifestPath)) return null;
  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    if (manifest && manifest.address && manifest.address.toLowerCase() === address.toLowerCase()) {
      return manifest;
    }
    return null;
  } catch {
    return null;
  }
}

function sanitizeSourceName(rawName) {
  if (typeof rawName !== "string" || !rawName.trim()) return null;
  const noBackslash = rawName.replace(/\\/g, "/");
  // Strip any leading slashes/dots, then collapse "../" segments. After this
  // pass, path.resolve must still land inside the sources subdirectory.
  const stripped = noBackslash.replace(/^[/.]+/, "");
  const segments = stripped.split("/").filter((segment) => segment && segment !== "." && segment !== "..");
  if (segments.length === 0) return null;
  return segments
    .map((segment) => segment.replace(/[^A-Za-z0-9._-]/g, "_"))
    .join("/");
}

function assertWithinSources(rootDir, candidatePath) {
  const resolvedRoot = path.resolve(rootDir) + path.sep;
  const resolvedCandidate = path.resolve(candidatePath);
  if (resolvedCandidate !== path.resolve(rootDir) && !resolvedCandidate.startsWith(resolvedRoot)) {
    throw new Error(`source file path escapes the sources cache: ${candidatePath}`);
  }
  return resolvedCandidate;
}

function writeCachedSource(domain, chainId, address, manifest) {
  const cacheDir = contractsCacheDir(domain, chainId, address);
  const sourcesDir = path.join(cacheDir, "sources");
  fs.mkdirSync(sourcesDir, { recursive: true });
  writeFileAtomic(path.join(cacheDir, "source-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  for (const file of manifest.files || []) {
    if (!file || typeof file.content !== "string") continue;
    const sanitized = sanitizeSourceName(file.name);
    if (!sanitized) continue;
    const targetPath = path.join(sourcesDir, sanitized);
    let resolvedTarget;
    try {
      resolvedTarget = assertWithinSources(sourcesDir, targetPath);
    } catch {
      continue; // skip files that escape the cache
    }
    fs.mkdirSync(path.dirname(resolvedTarget), { recursive: true });
    writeFileAtomic(resolvedTarget, file.content);
  }
}

async function fetchTextWithTimeout(url, { timeoutMs = SOURCE_FETCH_TIMEOUT_MS, maxBytes = SOURCE_MAX_RESPONSE_BYTES, headers = {} } = {}) {
  if (!isPublicHttpsUrl(url)) {
    throw new Error(`source fetch URL is not a public https URL: ${redactRpcEndpoint(url)}`);
  }
  const resp = await requestPublicHttpsText(url, {
    method: "GET",
    headers: { Accept: "application/json,text/plain", ...headers },
    timeoutMs,
    maxBytes,
  });
  return { ok: resp.ok, status: resp.status, text: resp.text };
}

function trimFiles(files) {
  const trimmed = [];
  let totalBytes = 0;
  for (const file of files.slice(0, SOURCE_MAX_FILES)) {
    if (!file || typeof file.name !== "string" || typeof file.content !== "string") continue;
    const buffer = Buffer.from(file.content, "utf8");
    const fileBytes = Math.min(buffer.length, SOURCE_MAX_FILE_BYTES);
    if (totalBytes + fileBytes > SOURCE_MAX_RETURN_BYTES) {
      trimmed.push({ name: file.name, content: "", omitted: true, total_bytes: buffer.length });
      continue;
    }
    const content = fileBytes < buffer.length
      ? buffer.subarray(0, fileBytes).toString("utf8")
      : file.content;
    trimmed.push({ name: file.name, content, total_bytes: buffer.length, truncated: fileBytes < buffer.length });
    totalBytes += fileBytes;
  }
  return { files: trimmed, total_bytes: totalBytes };
}

function sourceFetchErrorText(value, maxChars = 200, knownSecrets = []) {
  let text = String(value || "");
  for (const secret of knownSecrets) {
    if (typeof secret === "string" && secret.length > 0) {
      text = text.split(secret).join("REDACTED");
    }
  }
  return redactRpcEndpointText(text).slice(0, maxChars);
}

async function fetchFromSourcify(chainId, address) {
  const url = `${SOURCIFY_BASE}/${chainId}/${address}`;
  const { ok, status, text } = await fetchTextWithTimeout(url);
  if (!ok) {
    return { source: "sourcify", ok: false, status, error: sourceFetchErrorText(text) };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return { source: "sourcify", ok: false, status, error: sourceFetchErrorText(`parse failed: ${error.message || String(error)}`) };
  }
  const files = Array.isArray(parsed.files) ? parsed.files : [];
  if (files.length === 0) {
    return { source: "sourcify", ok: false, status, error: "no files in sourcify response" };
  }
  const filesNormalized = files.map((file) => ({
    name: typeof file.name === "string" ? file.name.split("/").slice(-3).join("/") : "unknown.sol",
    content: typeof file.content === "string" ? file.content : "",
  }));
  return {
    source: "sourcify",
    ok: true,
    status: parsed.status || null,
    files: filesNormalized,
  };
}

async function fetchFromEtherscanV2(chainId, address, apiKey) {
  if (!apiKey) {
    return { source: "etherscan-v2", ok: false, error: "no BOB_ETHERSCAN_API_KEY" };
  }
  const url = `${ETHERSCAN_V2_BASE}?chainid=${encodeURIComponent(chainId)}&module=contract&action=getsourcecode&address=${encodeURIComponent(address)}&apikey=${encodeURIComponent(apiKey)}`;
  const { ok, status, text } = await fetchTextWithTimeout(url);
  if (!ok) {
    return { source: "etherscan-v2", ok: false, status, error: sourceFetchErrorText(text, 200, [apiKey]) };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return { source: "etherscan-v2", ok: false, status, error: sourceFetchErrorText(`parse failed: ${error.message || String(error)}`, 200, [apiKey]) };
  }
  if (parsed.status !== "1" || !Array.isArray(parsed.result) || parsed.result.length === 0) {
    return { source: "etherscan-v2", ok: false, status, error: sourceFetchErrorText(parsed.message || "no source returned", 200, [apiKey]) };
  }
  const entry = parsed.result[0];
  if (!entry || typeof entry !== "object") {
    return { source: "etherscan-v2", ok: false, status, error: "missing first result entry" };
  }
  // Etherscan V2 source can be (a) flat string, (b) JSON with sources map, (c) double-encoded JSON.
  const sourceCode = typeof entry.SourceCode === "string" ? entry.SourceCode : "";
  let files = [];
  if (sourceCode.startsWith("{{") && sourceCode.endsWith("}}")) {
    try {
      const stripped = sourceCode.slice(1, -1);
      const inner = JSON.parse(stripped);
      if (inner && typeof inner.sources === "object") {
        files = Object.entries(inner.sources).map(([name, info]) => ({
          name,
          content: typeof info?.content === "string" ? info.content : "",
        }));
      }
    } catch {}
  } else if (sourceCode.startsWith("{") && sourceCode.endsWith("}")) {
    try {
      const inner = JSON.parse(sourceCode);
      if (inner && typeof inner.sources === "object") {
        files = Object.entries(inner.sources).map(([name, info]) => ({
          name,
          content: typeof info?.content === "string" ? info.content : "",
        }));
      } else if (inner && typeof inner === "object") {
        files = Object.entries(inner).map(([name, info]) => ({
          name,
          content: typeof info?.content === "string" ? info.content : "",
        }));
      }
    } catch {}
  }
  if (files.length === 0 && sourceCode) {
    files = [{ name: `${entry.ContractName || "Contract"}.sol`, content: sourceCode }];
  }
  if (files.length === 0) {
    return { source: "etherscan-v2", ok: false, status, error: "could not parse source" };
  }
  return {
    source: "etherscan-v2",
    ok: true,
    status,
    contract_name: entry.ContractName || null,
    compiler_version: entry.CompilerVersion || null,
    optimization_used: entry.OptimizationUsed || null,
    runs: entry.Runs || null,
    proxy: entry.Proxy === "1",
    implementation: entry.Implementation || null,
    files,
  };
}

async function fetchVerifiedSource({ domain, chainId, address, force = false }) {
  if (!Number.isInteger(Number(chainId)) || Number(chainId) <= 0) {
    throw new Error(`chain_id must be a positive integer, received: ${chainId}`);
  }
  if (!isAddress(address)) {
    throw new Error(`address must be a 20-byte hex address, received: ${address}`);
  }
  const numericChainId = Number(chainId);
  const lower = address.toLowerCase();

  if (!force) {
    const cached = readCachedSource(domain, numericChainId, lower);
    if (cached) {
      return { ...cached, cached: true };
    }
  }

  const attempts = [];
  let manifest = null;
  const sourcify = await fetchFromSourcify(numericChainId, lower).catch((error) => ({ source: "sourcify", ok: false, error: redactRpcEndpointText(error.message || String(error)) }));
  attempts.push({ source: sourcify.source, ok: sourcify.ok, error: sourcify.error || null });
  if (sourcify.ok) {
    const trimmed = trimFiles(sourcify.files);
    manifest = {
      chain_id: numericChainId,
      address: lower,
      source: "sourcify",
      contract_name: null,
      proxy: null,
      implementation: null,
      files: trimmed.files,
      total_bytes: trimmed.total_bytes,
    };
  }

  if (!manifest) {
    const apiKey = process.env.BOB_ETHERSCAN_API_KEY || null;
    const etherscan = await fetchFromEtherscanV2(numericChainId, lower, apiKey).catch((error) => ({ source: "etherscan-v2", ok: false, error: redactRpcEndpointText(error.message || String(error)) }));
    attempts.push({ source: etherscan.source, ok: etherscan.ok, error: etherscan.error || null });
    if (etherscan.ok) {
      const trimmed = trimFiles(etherscan.files);
      manifest = {
        chain_id: numericChainId,
        address: lower,
        source: "etherscan-v2",
        contract_name: etherscan.contract_name,
        compiler_version: etherscan.compiler_version,
        proxy: etherscan.proxy,
        implementation: etherscan.implementation,
        files: trimmed.files,
        total_bytes: trimmed.total_bytes,
      };
    }
  }

  if (!manifest) {
    return {
      ok: false,
      chain_id: numericChainId,
      address: lower,
      attempts,
      reason: "verified source not found via Sourcify or Etherscan",
    };
  }
  manifest.attempts = attempts;
  manifest.cached = false;
  writeCachedSource(domain, numericChainId, lower, manifest);
  return manifest;
}

module.exports = {
  contractsCacheDir,
  fetchVerifiedSource,
  readCachedSource,
};
