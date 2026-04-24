"use strict";

const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");
const { assertNonEmptyString } = require("./validation.js");
const { authStore } = require("./auth.js");
const {
  assertSafeRequestUrl,
  safeFetch,
} = require("./safe-fetch.js");

const SIGNUP_PATHS = [
  "/register", "/signup", "/sign-up", "/join", "/create-account",
  "/api/register", "/api/signup", "/api/auth/register", "/api/auth/signup",
  "/api/v1/register", "/api/v1/signup", "/api/v1/auth/register",
  "/auth/register", "/auth/signup", "/account/create",
  "/free-trial", "/try", "/get-started", "/start", "/onboarding",
  "/pricing", "/plans", "/account/signup", "/users/sign_up",
];

const CAPTCHA_INDICATORS = ["recaptcha", "hcaptcha", "turnstile", "captcha", "g-recaptcha", "cf-turnstile", "h-captcha"];

const FORM_FIELD_PATTERNS = [
  { name: "email", pattern: /name=["']?(?:email|e-mail|user_email|userEmail)["'\s>]/i },
  { name: "password", pattern: /name=["']?(?:password|passwd|pass|user_password)["'\s>]/i },
  { name: "username", pattern: /name=["']?(?:username|user_name|login|handle)["'\s>]/i },
  { name: "name", pattern: /name=["']?(?:name|full_name|fullName|first_name|firstName)["'\s>]/i },
  { name: "phone", pattern: /name=["']?(?:phone|telephone|mobile|tel)["'\s>]/i },
];

const AUTH_EVIDENCE_KEY_RE = /(sid|session|auth|token|jwt|access|refresh)/i;

function authEvidenceFromResult(result) {
  const headers = result && result.headers && typeof result.headers === "object" ? result.headers : {};
  const cookies = result && result.cookies && typeof result.cookies === "object" ? result.cookies : {};
  const localStorage = result && result.local_storage && typeof result.local_storage === "object" ? result.local_storage : {};
  const sessionStorage = result && result.session_storage && typeof result.session_storage === "object" ? result.session_storage : {};

  return {
    authorization_header: Object.keys(headers).some((name) => name.toLowerCase() === "authorization"),
    cookie_keys: Object.keys(cookies).filter((name) => AUTH_EVIDENCE_KEY_RE.test(name)),
    local_storage_keys: Object.keys(localStorage).filter((name) => AUTH_EVIDENCE_KEY_RE.test(name)),
    session_storage_keys: Object.keys(sessionStorage).filter((name) => AUTH_EVIDENCE_KEY_RE.test(name)),
  };
}

function hasAuthEvidence(evidence) {
  return !!(
    evidence.authorization_header ||
    evidence.cookie_keys.length ||
    evidence.local_storage_keys.length ||
    evidence.session_storage_keys.length
  );
}

function normalizeUrlForSignupSuccess(urlValue) {
  try {
    const parsed = new URL(urlValue);
    parsed.hash = "";
    parsed.pathname = parsed.pathname.replace(/\/+$/, "") || "/";
    return parsed.toString();
  } catch {
    return String(urlValue || "").replace(/#.*$/, "").replace(/\/+$/, "");
  }
}

function normalizeAutoSignupResult(result, signupUrl) {
  const normalized = result && typeof result === "object" ? result : {};
  const evidence = authEvidenceFromResult(normalized);
  const pageErrors = Array.isArray(normalized.page_errors) ? normalized.page_errors.filter(Boolean) : [];
  const submitted = normalized.submitted === true;
  const redirectUrl = normalized.redirect_url || null;
  const redirected = redirectUrl
    ? normalizeUrlForSignupSuccess(redirectUrl) !== normalizeUrlForSignupSuccess(signupUrl)
    : false;
  const evidencePresent = hasAuthEvidence(evidence);

  normalized.auth_evidence = evidence;
  normalized.page_errors = pageErrors;

  if (normalized.success === true && submitted && pageErrors.length === 0 && evidencePresent && redirected) {
    return normalized;
  }

  if (normalized.success === true || normalized.success == null) {
    normalized.success = false;
    normalized.fallback = "manual";
  }

  normalized.diagnostics = {
    submitted,
    page_errors: pageErrors,
    filled_fields: normalized.filled_fields || {},
    redirect_url: redirectUrl,
    auth_evidence: evidence,
  };
  return normalized;
}

async function signupDetect(args) {
  const targetDomain = assertNonEmptyString(args.target_domain, "target_domain");
  const targetUrl = assertNonEmptyString(args.target_url, "target_url").replace(/\/+$/, "");

  const endpointsFound = [];
  const blockedRequests = [];
  const formFieldsSet = new Set();
  let hasCaptcha = false;
  let captchaType = null;
  let oauthOnly = false;
  let emailRestrictions = false;

  for (const signupPath of SIGNUP_PATHS) {
    try {
      const url = `${targetUrl}${signupPath}`;
      const resp = await safeFetch(url, {
        method: "GET",
        headers: { "User-Agent": "Mozilla/5.0 (compatible; security-testing)", Accept: "text/html,application/json" },
        followRedirects: true,
        timeoutMs: 5000,
        targetDomain,
        maxResponseBytes: 20000,
      });

      if (resp.status >= 200 && resp.status < 400) {
        const ct = resp.headers.get("content-type") || "";
        let body = "";
        if (ct.includes("text") || ct.includes("json") || ct.includes("html")) {
          body = (await resp.text()).slice(0, 20000);
        }

        endpointsFound.push({ path: signupPath, method: "GET", status: resp.status, final_url: resp.url });

        // Detect form fields
        for (const { name, pattern } of FORM_FIELD_PATTERNS) {
          if (pattern.test(body)) formFieldsSet.add(name);
        }

        // Detect CAPTCHA
        const bodyLower = body.toLowerCase();
        for (const indicator of CAPTCHA_INDICATORS) {
          if (bodyLower.includes(indicator)) {
            hasCaptcha = true;
            captchaType = captchaType || indicator;
          }
        }

        // Detect email restrictions
        if (/disposable|temporary email|business email only|corporate email/i.test(body)) {
          emailRestrictions = true;
        }

        // Detect OAuth-only
        if (!formFieldsSet.has("email") && !formFieldsSet.has("password")) {
          const hasOAuth = /oauth|google.*sign|facebook.*sign|github.*sign|sign.*with.*google|sign.*with.*github/i.test(body);
          if (hasOAuth && endpointsFound.length === 1) oauthOnly = true;
        }
      }
    } catch (error) {
      if (error && error.scope_decision === "blocked") {
        blockedRequests.push({ path: signupPath, error: error.message || String(error) });
      }
      // Timeout or connection error — skip this path
    }
  }

  // Determine feasibility
  let feasibility = "manual";
  if (endpointsFound.length > 0) {
    if (oauthOnly) {
      feasibility = "manual";
    } else if (hasCaptcha) {
      feasibility = "assisted";
    } else {
      feasibility = "automated";
    }
  }

  // Override: if OAuth-only was a premature guess and we found email fields later, correct it
  if (formFieldsSet.has("email") && formFieldsSet.has("password")) {
    oauthOnly = false;
  }

  return JSON.stringify({
    endpoints_found: endpointsFound,
    form_fields: [...formFieldsSet],
    has_captcha: hasCaptcha,
    captcha_type: captchaType,
    oauth_only: oauthOnly,
    email_restrictions_detected: emailRestrictions,
    signup_feasibility: feasibility,
    blocked_requests: blockedRequests,
  });
}

async function autoSignup(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const signupUrl = assertNonEmptyString(args.signup_url, "signup_url");
  const email = assertNonEmptyString(args.email, "email");
  const password = assertNonEmptyString(args.password, "password");
  const profileName = args.profile_name || "attacker";
  const name = args.name || "Hunter Test";

  try {
    assertSafeRequestUrl(signupUrl, domain);
  } catch (error) {
    return JSON.stringify({
      success: false,
      error: error.message || String(error),
      scope_decision: "blocked",
      fallback: "manual",
    });
  }

  // Check if patchright is available before spawning the script
  let patchrightAvailable = false;
  try {
    require.resolve("patchright");
    patchrightAvailable = true;
  } catch {}

  if (!patchrightAvailable) {
    return JSON.stringify({
      success: false,
      error: "patchright not installed. Run: npm install && npx patchright install chromium",
      fallback: "manual",
    });
  }

  const scriptPath = path.join(__dirname, "..", "auto-signup.js");
  if (!fs.existsSync(scriptPath)) {
    return JSON.stringify({ success: false, error: "auto-signup.js not found", fallback: "manual" });
  }

  const config = {
    target_domain: domain,
    signup_url: signupUrl,
    email,
    password,
    name,
    capsolver_api_key: process.env.CAPSOLVER_API_KEY || null,
    proxy: args.proxy || process.env.BOUNTY_PROXY || null,
    timeout_ms: args.timeout_ms || 45000,
    headless: args.headless !== undefined ? args.headless : false,
  };

  return new Promise((resolve) => {
    const timeout = (config.timeout_ms || 45000) + 10000; // script timeout + buffer
    execFile(
      process.execPath,
      [scriptPath, JSON.stringify(config)],
      { timeout, maxBuffer: 5 * 1024 * 1024, env: { ...process.env } },
      async (err, stdout, stderr) => {
        if (err && !stdout) {
          resolve(JSON.stringify({
            success: false,
            error: err.message || String(err),
            stderr: (stderr || "").slice(0, 500),
            fallback: "manual",
          }));
          return;
        }

        let result;
        try {
          result = JSON.parse(stdout);
        } catch {
          resolve(JSON.stringify({
            success: false,
            error: "auto-signup returned invalid JSON",
            raw_output: (stdout || "").slice(0, 500),
            fallback: "manual",
          }));
          return;
        }

        result = normalizeAutoSignupResult(result, signupUrl);

        // If signup succeeded with auth-shaped evidence, auto-store auth.
        if (result.success === true && hasAuthEvidence(result.auth_evidence)) {
          try {
            await authStore({
              target_domain: domain,
              profile_name: profileName,
              cookies: result.cookies || {},
              headers: result.headers || {},
              local_storage: result.local_storage || {},
              credentials: { email, password },
            });
            result.auth_stored = true;
            result.auth_profile = profileName;
          } catch (storeErr) {
            result.auth_stored = false;
            result.auth_store_error = storeErr.message;
          }
        }

        resolve(JSON.stringify(result));
      }
    );
  });
}

module.exports = {
  authEvidenceFromResult,
  autoSignup,
  hasAuthEvidence,
  normalizeAutoSignupResult,
  signupDetect,
};
