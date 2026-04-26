"use strict";

const { redactUrlSensitiveValues } = require("../redaction.js");
const {
  assertNonEmptyString,
  assertRequiredText,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const { appendHttpAuditRecord } = require("./http-records.js");
const {
  safeUrlObject,
} = require("./url-surface.js");
const { resolveAuthProfile } = require("./auth.js");
const {
  resolveHttpScanTargetDomain,
} = require("./scope.js");
const {
  assertSafeRequestUrl,
  safeFetch,
} = require("./safe-fetch.js");

async function httpScan(args) {
  const method = assertRequiredText(args.method, "method").toUpperCase();
  const url = assertRequiredText(args.url, "url");
  const startedAt = Date.now();
  const explicitTargetDomain = args.target_domain
    ? assertNonEmptyString(args.target_domain, "target_domain")
    : null;
  const targetDomain = resolveHttpScanTargetDomain(url, explicitTargetDomain);
  if (!targetDomain) {
    return JSON.stringify({
      error: "target_domain is required for scoped HTTP scans",
      scope_decision: "blocked",
    });
  }
  const blockInternalHosts = args.block_internal_hosts === true;
  const parsedUrl = safeUrlObject(url);
  const auditUrl = redactUrlSensitiveValues(url);
  const auditParsedUrl = safeUrlObject(auditUrl) || parsedUrl;
  const auditBase = targetDomain ? {
    version: 1,
    ts: new Date().toISOString(),
    target_domain: targetDomain,
    method,
    url: auditUrl,
    host: parsedUrl ? parsedUrl.hostname.toLowerCase() : null,
    path: auditParsedUrl ? `${auditParsedUrl.pathname}${auditParsedUrl.search}` : null,
    wave: args.wave == null ? null : parseWaveId(args.wave),
    agent: args.agent == null ? null : parseAgentId(args.agent),
    surface_id: args.surface_id == null ? null : assertNonEmptyString(args.surface_id, "surface_id"),
    auth_profile: args.auth_profile || null,
  } : null;
  const audit = (fields) => {
    if (!auditBase) return;
    appendHttpAuditRecord({
      ...auditBase,
      ...fields,
      ts: new Date().toISOString(),
      duration_ms: Date.now() - startedAt,
    });
  };

  try {
    assertSafeRequestUrl(url, targetDomain, { blockInternalHosts });
  } catch (error) {
    audit({
      status: null,
      error: error.message || String(error),
      scope_decision: "blocked",
    });
    return JSON.stringify({
      error: error.message || String(error),
      scope_decision: "blocked",
    });
  }

  const headers = args.headers || {};
  const body = args.body || undefined;
  const followRedirects = args.follow_redirects ?? false;
  const timeoutMs = args.timeout_ms || 10000;
  const authProfile = args.auth_profile;

  if (authProfile) {
    const auth = resolveAuthProfile(authProfile, url, targetDomain);

    if (auth) {
      for (const [k, v] of Object.entries(auth)) {
        if (k !== "credentials" && !headers[k]) headers[k] = v;
      }
    } else {
      audit({
        status: null,
        error: `auth_profile "${authProfile}" requested but not found`,
        scope_decision: "auth_missing",
      });
      return JSON.stringify({
        error: `auth_profile "${authProfile}" requested but not found — request was NOT sent. Store auth first via bounty_auth_store.`,
      });
    }
  }

  try {
    const {
      status,
      statusText,
      headers: responseHeaders,
      url: finalUrl,
      redirected,
      redirectCount,
      bodyByteLength,
      bodyTruncated,
      text,
      arrayBuffer,
    } = await safeFetch(url, {
      method,
      headers,
      body,
      followRedirects,
      timeoutMs,
      targetDomain,
      blockInternalHosts,
    });

    const respHeaders = {};
    responseHeaders.forEach((v, k) => { respHeaders[k] = v; });

    const ct = responseHeaders.get("content-type") || "";
    let respBody;
    let analysisBody;
    if (ct.includes("text") || ct.includes("json") || ct.includes("xml") || ct.includes("javascript") || ct.includes("html")) {
      const bodyText = await text();
      analysisBody = bodyText;
      respBody = bodyText.slice(0, 12000);
      if (bodyText.length > 12000 || bodyTruncated) {
        respBody += `\n[TRUNCATED — ${bodyTruncated ? `${bodyByteLength} bytes exceeded transport cap` : `${bodyText.length} chars`}]`;
      }
    } else {
      const buf = await arrayBuffer();
      respBody = `[Binary: ${buf.byteLength} bytes${bodyTruncated ? ` (truncated from ${bodyByteLength})` : ""}, type: ${ct}]`;
      analysisBody = respBody;
    }

    const responseMode = args.response_mode || "full";
    const bodyLimit = args.body_limit || 2000;
    audit({
      status,
      error: null,
      scope_decision: "allowed",
      final_url: redactUrlSensitiveValues(finalUrl),
    });

    if (responseMode === "status_only") {
      return JSON.stringify({
        status,
        status_text: statusText,
        redirected,
        redirect_count: redirectCount,
        final_url: finalUrl,
      });
    }

    if (responseMode === "headers_only") {
      return JSON.stringify({
        status,
        status_text: statusText,
        headers: respHeaders,
        redirected,
        redirect_count: redirectCount,
        final_url: finalUrl,
      });
    }

    const analysis = analyzeResponse(url, status, respHeaders, analysisBody);

    if (responseMode === "body_truncate") {
      return JSON.stringify({
        status,
        status_text: statusText,
        headers: respHeaders,
        body: respBody.slice(0, bodyLimit) + (respBody.length > bodyLimit ? `\n[TRUNCATED at ${bodyLimit}/${respBody.length} chars]` : ""),
        redirected,
        redirect_count: redirectCount,
        final_url: finalUrl,
        analysis,
      }, null, 2);
    }

    return JSON.stringify({
      status,
      status_text: statusText,
      headers: respHeaders,
      body: respBody,
      redirected,
      redirect_count: redirectCount,
      final_url: finalUrl,
      analysis,
    }, null, 2);
  } catch (err) {
    const errorMessage = err && err.name === "AbortError"
      ? `timeout after ${timeoutMs}ms`
      : (err.message || String(err));
    const isBlocked = err && err.scope_decision === "blocked";
    audit({
      status: null,
      error: errorMessage,
      scope_decision: isBlocked ? "blocked" : "request_error",
    });
    return JSON.stringify(isBlocked
      ? { error: errorMessage, scope_decision: "blocked" }
      : { error: errorMessage });
  }
}

function analyzeResponse(url, status, headers, body) {
  const tech = [];
  const issues = [];
  const secrets = [];
  const endpoints = [];
  const authInfo = [];

  // Tech fingerprinting
  if (headers["x-powered-by"]) tech.push(`X-Powered-By: ${headers["x-powered-by"]}`);
  if (headers.server) tech.push(`Server: ${headers.server}`);
  if (body.includes("__NEXT_DATA__")) tech.push("Next.js");
  if (body.includes("__nuxt")) tech.push("Nuxt.js");
  if (body.includes("ng-version")) tech.push("Angular");
  if (body.includes("__vue__")) tech.push("Vue.js");
  if (body.includes("firebase")) tech.push("Firebase");
  if (body.includes("graphql")) tech.push("GraphQL");
  if (body.includes("wp-content")) tech.push("WordPress");
  if (body.includes("laravel") || body.includes("XSRF-TOKEN")) tech.push("Laravel");
  if (body.includes("django") || body.includes("csrfmiddlewaretoken")) tech.push("Django");
  if (headers["cf-ray"]) tech.push("Cloudflare");
  if (headers["x-vercel-id"]) tech.push("Vercel");
  if (headers["x-amzn-requestid"]) tech.push("AWS");

  // Security headers
  if (!headers["strict-transport-security"]) issues.push("Missing HSTS");
  if (!headers["x-content-type-options"]) issues.push("Missing X-Content-Type-Options");
  if (!headers["x-frame-options"] && !(headers["content-security-policy"] || "").includes("frame-ancestors"))
    issues.push("No clickjacking protection");
  if (headers["access-control-allow-origin"] === "*") issues.push("CORS: wildcard origin (*)");
  if (headers["access-control-allow-credentials"] === "true")
    issues.push(`CORS: credentials + origin ${headers["access-control-allow-origin"] || "?"} — test reflection`);

  // Cookie analysis
  const sc = headers["set-cookie"] || "";
  if (sc) {
    if (!sc.includes("HttpOnly")) authInfo.push("Cookie missing HttpOnly");
    if (!sc.includes("Secure")) authInfo.push("Cookie missing Secure flag");
    if (!sc.includes("SameSite")) authInfo.push("Cookie missing SameSite");
  }

  // Secret detection
  const patterns = [
    { re: /AKIA[A-Z0-9]{16}/, label: "AWS Access Key" },
    { re: /ghp_[a-zA-Z0-9]{36}/, label: "GitHub PAT" },
    { re: /gho_[a-zA-Z0-9]{36}/, label: "GitHub OAuth" },
    { re: /sk-[a-zA-Z0-9]{32,}/, label: "Secret key (sk-)" },
    { re: /sk_live_[a-zA-Z0-9]{24,}/, label: "Stripe Live" },
    { re: /pk_live_[a-zA-Z0-9]{24,}/, label: "Stripe Publishable" },
    { re: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+/, label: "JWT" },
    { re: /xox[bpas]-[a-zA-Z0-9-]+/, label: "Slack token" },
    { re: /AIza[a-zA-Z0-9_-]{35}/, label: "Google API key" },
    { re: /GOCSPX-[a-zA-Z0-9_-]+/, label: "Google OAuth secret" },
    { re: /-----BEGIN (?:RSA )?PRIVATE KEY-----/, label: "Private key" },
    { re: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})/i, label: "API key" },
    { re: /(?:secret|password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{8,})/i, label: "Secret/password" },
    { re: /mongodb(\+srv)?:\/\/[^\s"']+/, label: "MongoDB URI" },
    { re: /postgres(ql)?:\/\/[^\s"']+/, label: "PostgreSQL URI" },
    { re: /redis:\/\/[^\s"']+/, label: "Redis URI" },
    { re: /smtp:\/\/[^\s"']+/, label: "SMTP URI" },
  ];
  for (const { re, label } of patterns) {
    const m = body.match(re);
    if (m) secrets.push(`${label}: ${m[0].slice(0, 50)}...`);
  }

  // Endpoint extraction
  const urls = body.match(/(?:https?:\/\/[^\s"'<>{}]+|\/api\/[^\s"'<>{}]+|\/v[0-9]+\/[^\s"'<>{}]+)/g) || [];
  endpoints.push(...[...new Set(urls)].slice(0, 30));

  // Status hints
  if (status === 403) issues.push("403 — try different auth/methods");
  if (status === 405) issues.push("405 — try other HTTP methods");
  if (status === 500) issues.push("500 — possible injection vector");

  return { tech_stack: tech, security_issues: issues, leaked_secrets: secrets, discovered_endpoints: endpoints, auth_info: authInfo };
}

module.exports = {
  analyzeResponse,
  httpScan,
};
