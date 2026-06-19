"use strict";

const { redactUrlSensitiveValues } = require("../redaction.js");
const {
  assertNonEmptyString,
  assertRequiredText,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  appendHttpAuditRecord,
  recordJwtObservations,
  recordSchemaObservations,
} = require("./http-records.js");
const {
  createProxyAgent,
} = require("./egress-profiles.js");
const {
  blockInternalHostsPolicyFields,
} = require("./session-state-contracts.js");
const {
  blockInternalHostsRequestPolicy,
} = require("./session-state-store.js");
const {
  assertBlockInternalHostsCompatibleWithEgress,
  resolveAndAssertSessionEgressIdentity,
  readStateSummary,
} = require("./session-state.js");
const {
  isFirstPartyHost,
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

function scopeAuditFields(scopeDecision) {
  if (!scopeDecision || typeof scopeDecision !== "object") return {};
  const fields = {};
  for (const field of ["registrable_domain", "public_suffix", "public_suffix_source", "psl_overlay_file"]) {
    if (scopeDecision[field] != null) fields[field] = scopeDecision[field];
  }
  return fields;
}

function isNetworkUnreachableError(message) {
  return /timeout|abort|econnreset|socket hang up|etimedout|enotfound|eai_again|econnrefused|network unreachable|connection reset/i
    .test(String(message || ""));
}

function isMissingSessionStateError(error) {
  return /Missing session state:|requires an initialized session/.test(
    error && error.message ? error.message : String(error),
  );
}

function sessionStateExistsForEgressContext(targetDomain) {
  try {
    readStateSummary({ target_domain: targetDomain });
    return true;
  } catch (error) {
    if (isMissingSessionStateError(error)) return false;
    throw error;
  }
}

function scopeBlockedEgressContext(targetDomain, requestedEgressProfile, fallback) {
  if (!sessionStateExistsForEgressContext(targetDomain)) return fallback;
  try {
    return resolveAndAssertSessionEgressIdentity(targetDomain, requestedEgressProfile, {
      source: "bob_http_scan_scope_blocked",
    }).identity;
  } catch (error) {
    if (isMissingSessionStateError(error)) return fallback;
    throw error;
  }
}

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
  const internalHostPolicy = blockInternalHostsRequestPolicy(targetDomain, args, {
    allowMissingSession: true,
  });
  const blockInternalHosts = internalHostPolicy.block_internal_hosts === true;
  const internalHostContext = blockInternalHostsPolicyFields(internalHostPolicy);
  const parsedUrl = safeUrlObject(url);
  const requestedEgressProfile = args.egress_profile == null
    ? "default"
    : assertNonEmptyString(args.egress_profile, "egress_profile");
  let egressContext = {
    egress_profile: requestedEgressProfile,
    egress_region: null,
    proxy_configured: false,
    egress_profile_identity_hash: null,
    egress_profile_identity_version: null,
  };
  let egressAgent = null;
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
    egress_profile: requestedEgressProfile,
    egress_region: null,
    ...internalHostContext,
  } : null;
  const audit = (fields) => {
    if (!auditBase) return;
    appendHttpAuditRecord({
      ...auditBase,
      ...egressContext,
      ...fields,
      ts: new Date().toISOString(),
      duration_ms: Date.now() - startedAt,
    });
  };

  let initialScopeDecision = null;
  try {
    initialScopeDecision = assertSafeRequestUrl(url, targetDomain, { blockInternalHosts });
  } catch (error) {
    egressContext = scopeBlockedEgressContext(targetDomain, requestedEgressProfile, egressContext);
    audit({
      status: null,
      error: error.message || String(error),
      scope_decision: "blocked",
      ...scopeAuditFields(error.details),
    });
    return JSON.stringify({
      error: error.message || String(error),
      scope_decision: "blocked",
      ...egressContext,
      ...internalHostContext,
    });
  }

  try {
    const { profile, identity } = resolveAndAssertSessionEgressIdentity(targetDomain, requestedEgressProfile, {
      source: "bob_http_scan",
    });
    egressContext = identity;
    assertBlockInternalHostsCompatibleWithEgress(internalHostPolicy, profile);
    egressAgent = createProxyAgent(profile.proxy_url);
  } catch (error) {
    if (error && error.code === "STATE_CONFLICT") throw error;
    const message = error.message || String(error);
    const scopeDecision = error && (error.scope_decision === "blocked" || error.code === "SCOPE_BLOCKED")
      ? "blocked"
      : "egress_error";
    audit({
      status: null,
      error: message,
      scope_decision: scopeDecision,
      ...scopeAuditFields(initialScopeDecision),
    });
    return JSON.stringify({
      error: `${message} — request was NOT sent.`,
      scope_decision: scopeDecision,
      ...egressContext,
      ...internalHostContext,
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
        ...scopeAuditFields(initialScopeDecision),
      });
      return JSON.stringify({
        error: `auth_profile "${authProfile}" requested but not found — request was NOT sent. Store auth first via bob_auth_store.`,
        ...egressContext,
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
      agent: egressAgent,
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
    const auditTs = new Date().toISOString();
    audit({
      status,
      error: null,
      scope_decision: "allowed",
      final_url: redactUrlSensitiveValues(finalUrl),
      ...scopeAuditFields(initialScopeDecision),
    });
    // Plane T Cycle T.5 — JWT-as-observation-kind. Scan response headers + body
    // for JWT-shaped tokens; emit one observation.recorded per distinct token
    // for the parent surface. Dedup by (surface_id, token_fingerprint).
    // The full token never enters the event payload — only a sha256 fingerprint,
    // a truncated snippet, and a sanitized projection of standard claims.
    if (args.surface_id) {
      try {
        recordJwtObservations({
          target_domain: targetDomain,
          surface_id: args.surface_id,
          response_headers: respHeaders,
          response_body: analysisBody,
          source_ref: `${auditTs} ${method} ${auditUrl}`,
        });
      } catch {
        // Best-effort, mirrors the importHttpTraffic dual-write pattern.
      }
      // Plane T Cycle T.6 — GraphQL / OpenAPI schema observation. Inspect the
      // JSON body for an introspection result OR an OpenAPI / Swagger spec;
      // emit one observation.recorded per distinct schema per surface, keyed
      // by sha256(canonical_json(schema)). The full schema document never
      // enters the event payload — only the fingerprint + summary fields.
      try {
        recordSchemaObservations({
          target_domain: targetDomain,
          surface_id: args.surface_id,
          request_url: finalUrl || url,
          response_body: analysisBody,
          source_ref: `${auditTs} ${method} ${auditUrl}`,
        });
      } catch {
        // Best-effort, mirrors the JWT path.
      }
    }

    if (responseMode === "status_only") {
      return JSON.stringify({
        status,
        status_text: statusText,
        redirected,
        redirect_count: redirectCount,
        final_url: finalUrl,
        ...egressContext,
        ...internalHostContext,
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
        ...egressContext,
        ...internalHostContext,
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
        ...egressContext,
        ...internalHostContext,
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
      ...egressContext,
      ...internalHostContext,
    }, null, 2);
  } catch (err) {
    const errorMessage = err && err.name === "AbortError"
      ? `timeout after ${timeoutMs}ms`
      : (err.message || String(err));
    const isBlocked = err && err.scope_decision === "blocked";
    const targetOwned = parsedUrl ? isFirstPartyHost(parsedUrl.hostname, targetDomain) : false;
    const networkUnreachable = !isBlocked && targetOwned && isNetworkUnreachableError(errorMessage);
    audit({
      status: null,
      error: errorMessage,
      scope_decision: isBlocked ? "blocked" : networkUnreachable ? "network_unreachable_target" : "request_error",
      ...scopeAuditFields(initialScopeDecision),
      ...scopeAuditFields(err && err.details),
    });
    return JSON.stringify(isBlocked
      ? { error: errorMessage, scope_decision: "blocked", ...egressContext, ...internalHostContext }
      : {
        error: errorMessage,
        ...(networkUnreachable ? {
          error_class: "network_unreachable_target",
          geofence_warning: "Repeated first-party network failures may indicate a geofenced or unreachable target. Log coverage/dead-end context and ask the operator before switching egress profiles.",
        } : {}),
        ...egressContext,
        ...internalHostContext,
      });
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
