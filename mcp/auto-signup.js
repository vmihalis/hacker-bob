#!/usr/bin/env node
// Auto-signup script — Patchright (stealth Playwright fork) + CapSolver CAPTCHA integration
// Called by bounty_auto_signup MCP tool via child_process.execFile
//
// Input:  JSON config as first CLI argument
// Output: JSON result on stdout
// Errors: JSON { error: "..." } on stdout, exit 0 (caller reads stdout)
//
// Anti-detection stack:
//   1. Patchright — fixes Runtime.Enable CDP leak (the #1 detection vector)
//   2. channel: 'chrome' — uses real system Chrome (TLS fingerprint, fonts, WebGL match)
//   3. Headed mode — avoids headless signals
//   4. ignoreDefaultArgs: ['--enable-automation'] — removes automation flag
//   5. Human-like timing — randomized delays between interactions
//   6. CapSolver API — solves reCAPTCHA, hCaptcha, Cloudflare Turnstile

"use strict";

const CAPTCHA_POLL_INTERVAL_MS = 3000;
const CAPTCHA_POLL_MAX_MS = 60000;
const AUTH_EVIDENCE_KEY_RE = /(sid|session|auth|token|jwt|access|refresh)/i;

// ── Helpers ──

function randomDelay(min = 100, max = 400) {
  return new Promise((r) => setTimeout(r, min + Math.random() * (max - min)));
}

function humanType(chars) {
  // Returns array of { char, delay } for human-like keystroke timing
  return chars.split("").map((c) => ({
    char: c,
    delay: 30 + Math.random() * 120 + (c === "@" || c === "." ? 200 * Math.random() : 0),
  }));
}

function output(obj) {
  process.stdout.write(JSON.stringify(obj));
  process.exit(0);
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

function authEvidenceFromAuthData(authData) {
  const headers = authData.headers || {};
  const cookies = authData.cookies || {};
  const localStorage = authData.local_storage || {};
  const sessionStorage = authData.session_storage || {};
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

// ── CAPTCHA Solving via CapSolver ──

async function solveCapsolverTask(apiKey, taskPayload) {
  const createResp = await fetch("https://api.capsolver.com/createTask", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ clientKey: apiKey, task: taskPayload }),
  });
  const createData = await createResp.json();
  if (createData.errorId && createData.errorId !== 0) {
    throw new Error(`CapSolver createTask: ${createData.errorDescription || createData.errorCode}`);
  }
  const taskId = createData.taskId;
  if (!taskId) throw new Error("CapSolver: no taskId returned");

  const deadline = Date.now() + CAPTCHA_POLL_MAX_MS;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, CAPTCHA_POLL_INTERVAL_MS));
    const pollResp = await fetch("https://api.capsolver.com/getTaskResult", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ clientKey: apiKey, taskId }),
    });
    const pollData = await pollResp.json();
    if (pollData.status === "ready") return pollData.solution;
    if (pollData.errorId && pollData.errorId !== 0) {
      throw new Error(`CapSolver poll: ${pollData.errorDescription || pollData.errorCode}`);
    }
  }
  throw new Error("CapSolver: timeout waiting for solution");
}

async function solveCaptcha(page, apiKey) {
  const pageUrl = page.url();

  // Detect CAPTCHA type by checking for known elements/scripts
  const captchaInfo = await page.evaluate(() => {
    const result = { type: null, siteKey: null };

    // Cloudflare Turnstile
    const turnstile = document.querySelector("[data-sitekey].cf-turnstile, .cf-turnstile[data-sitekey]");
    if (turnstile) {
      result.type = "turnstile";
      result.siteKey = turnstile.getAttribute("data-sitekey");
      return result;
    }
    const turnstileScript = document.querySelector('script[src*="challenges.cloudflare.com"]');
    if (turnstileScript) {
      const el = document.querySelector("[data-sitekey]");
      if (el) {
        result.type = "turnstile";
        result.siteKey = el.getAttribute("data-sitekey");
        return result;
      }
    }

    // reCAPTCHA v2
    const recaptchaV2 = document.querySelector(".g-recaptcha[data-sitekey]");
    if (recaptchaV2) {
      result.type = "recaptcha_v2";
      result.siteKey = recaptchaV2.getAttribute("data-sitekey");
      return result;
    }

    // reCAPTCHA v3 (script-based detection)
    const recaptchaScript = document.querySelector('script[src*="recaptcha/api.js"], script[src*="recaptcha/enterprise.js"]');
    if (recaptchaScript) {
      const src = recaptchaScript.getAttribute("src") || "";
      const renderMatch = src.match(/render=([^&]+)/);
      if (renderMatch && renderMatch[1] !== "explicit") {
        result.type = "recaptcha_v3";
        result.siteKey = renderMatch[1];
        return result;
      }
      // Fallback: look for sitekey in any recaptcha element
      const el = document.querySelector("[data-sitekey]");
      if (el) {
        result.type = "recaptcha_v2";
        result.siteKey = el.getAttribute("data-sitekey");
        return result;
      }
    }

    // hCaptcha
    const hcaptcha = document.querySelector(".h-captcha[data-sitekey], [data-hcaptcha-widget-id]");
    if (hcaptcha) {
      result.type = "hcaptcha";
      result.siteKey = hcaptcha.getAttribute("data-sitekey");
      return result;
    }
    const hcaptchaScript = document.querySelector('script[src*="hcaptcha.com"]');
    if (hcaptchaScript) {
      const el = document.querySelector("[data-sitekey]");
      if (el) {
        result.type = "hcaptcha";
        result.siteKey = el.getAttribute("data-sitekey");
        return result;
      }
    }

    return result;
  });

  if (!captchaInfo.type || !captchaInfo.siteKey) {
    return { solved: false, type: null, reason: "no_captcha_detected" };
  }

  if (!apiKey) {
    return { solved: false, type: captchaInfo.type, reason: "no_api_key" };
  }

  let task;
  switch (captchaInfo.type) {
    case "turnstile":
      task = { type: "AntiTurnstileTaskProxyLess", websiteURL: pageUrl, websiteKey: captchaInfo.siteKey };
      break;
    case "recaptcha_v2":
      task = { type: "ReCaptchaV2TaskProxyLess", websiteURL: pageUrl, websiteKey: captchaInfo.siteKey };
      break;
    case "recaptcha_v3":
      task = { type: "ReCaptchaV3TaskProxyLess", websiteURL: pageUrl, websiteKey: captchaInfo.siteKey, pageAction: "signup" };
      break;
    case "hcaptcha":
      task = { type: "HCaptchaTaskProxyLess", websiteURL: pageUrl, websiteKey: captchaInfo.siteKey };
      break;
    default:
      return { solved: false, type: captchaInfo.type, reason: "unsupported_type" };
  }

  const solution = await solveCapsolverTask(apiKey, task);

  // Inject the solution token into the page
  await page.evaluate(({ type, solution }) => {
    if (type === "turnstile") {
      const input = document.querySelector('[name="cf-turnstile-response"]');
      if (input) input.value = solution.token;
      // Trigger turnstile callback if available
      if (typeof window.turnstile !== "undefined") {
        try { window.turnstile.getResponse && window.turnstile.execute(); } catch {}
      }
    }

    if (type === "recaptcha_v2" || type === "recaptcha_v3") {
      const textarea = document.getElementById("g-recaptcha-response");
      if (textarea) {
        textarea.style.display = "block";
        textarea.value = solution.gRecaptchaResponse || solution.token;
      }
      // Fire callback if registered
      try {
        if (typeof ___grecaptcha_cfg !== "undefined") {
          Object.values(___grecaptcha_cfg.clients).forEach((client) => {
            Object.values(client).forEach((component) => {
              if (component && typeof component.callback === "function") {
                component.callback(solution.gRecaptchaResponse || solution.token);
              }
            });
          });
        }
      } catch {}
    }

    if (type === "hcaptcha") {
      const textarea = document.querySelector('[name="h-captcha-response"], textarea[name="g-recaptcha-response"]');
      if (textarea) textarea.value = solution.token || solution.gRecaptchaResponse;
      // Fire hCaptcha callback
      try {
        if (typeof hcaptcha !== "undefined") {
          const widgetId = document.querySelector("[data-hcaptcha-widget-id]")?.getAttribute("data-hcaptcha-widget-id");
          if (widgetId) hcaptcha.execute(widgetId);
        }
      } catch {}
    }
  }, { type: captchaInfo.type, solution });

  return { solved: true, type: captchaInfo.type, siteKey: captchaInfo.siteKey };
}

// ── Form Detection & Filling ──

// Common cookie/consent banner dismiss selectors — ordered most-specific first
const CONSENT_SELECTORS = [
  // CMP-specific buttons (exact IDs)
  '#onetrust-accept-btn-handler',
  '#CybotCookiebotDialogBodyLevelButtonLevelOptionalLevelAccept',
  '#CybotCookiebotDialogBodyButtonAccept',
  '.fc-cta-consent',                                    // Funding Choices
  '#didomi-notice-agree-button',                         // Didomi
  '.qc-cmp2-summary-buttons button:first-child',         // Quantcast
  '#usercentrics-root >>> button[data-testid="uc-accept-all-button"]', // Usercentrics (shadow DOM)
  '.cc-compliance .cc-btn.cc-allow',                     // CookieConsent
  '#cookie-consent-accept',
  '#accept-cookies',
  '#acceptCookies',
  // Google consent (GDPR interstitial)
  'button[aria-label="Accept all"]',
  'button[aria-label="Consent"]',
  'form[action*="consent"] button:first-of-type',
  // Generic text-based matches (broadest — last resort)
  'button:has-text("Accept all")',
  'button:has-text("Accept All")',
  'button:has-text("Accept cookies")',
  'button:has-text("Allow all")',
  'button:has-text("Allow All")',
  'button:has-text("Got it")',
  'button:has-text("I agree")',
  'button:has-text("Agree")',
  'button:has-text("OK")',
  'a:has-text("Accept all")',
  'a:has-text("Got it")',
  'a:has-text("I agree")',
];

async function dismissConsentBanners(page) {
  // SPA consent banners render after domcontentloaded. Wait for hydration.
  // Try up to 3 rounds with waits between them.
  for (let attempt = 0; attempt < 3; attempt++) {
    // Round 1: CSS selector-based (CMP-specific)
    for (const selector of CONSENT_SELECTORS) {
      try {
        const el = page.locator(selector).first();
        if (await el.isVisible({ timeout: 500 })) {
          await el.click({ force: true });
          await randomDelay(500, 1000);
          return true;
        }
      } catch {
        // Not found or not clickable — try next
      }
    }

    // Round 2: Playwright text-based locators (works on SPA-rendered content)
    // These use real mouse events, not synthetic JS clicks.
    const textPatterns = [
      "Got it, thanks",
      "Got it",
      "Accept all",
      "Accept All",
      "Accept cookies",
      "Allow all",
      "Allow All",
      "I agree",
      "Agree",
      "Yes, I agree",
      "OK",
    ];
    for (const text of textPatterns) {
      try {
        // getByRole matches buttons/links with accessible name
        const btn = page.getByRole("button", { name: text, exact: false }).first();
        if (await btn.isVisible({ timeout: 300 })) {
          await btn.click({ force: true });
          await randomDelay(500, 1000);
          return true;
        }
      } catch {}
      try {
        // Also try links styled as buttons
        const link = page.getByRole("link", { name: text, exact: false }).first();
        if (await link.isVisible({ timeout: 300 })) {
          await link.click({ force: true });
          await randomDelay(500, 1000);
          return true;
        }
      } catch {}
      try {
        // Last resort: any clickable element with this text
        const any = page.getByText(text, { exact: false }).first();
        if (await any.isVisible({ timeout: 300 })) {
          await any.click({ force: true });
          await randomDelay(500, 1000);
          return true;
        }
      } catch {}
    }

    if (attempt < 2) await randomDelay(2000, 3000); // Wait for SPA render
  }
  return false;
}

const FIELD_SELECTORS = {
  email: [
    'input[name="email"]', 'input[name="e-mail"]', 'input[name="user_email"]',
    'input[name="userEmail"]', 'input[name="username"][type="email"]',
    'input[type="email"]', 'input[placeholder*="email" i]',
    'input[autocomplete="email"]', 'input[id*="email" i]',
  ],
  password: [
    'input[name="password"]', 'input[name="passwd"]', 'input[name="pass"]',
    'input[name="user_password"]', 'input[type="password"]',
    'input[placeholder*="password" i]', 'input[autocomplete="new-password"]',
    'input[id*="password" i]',
  ],
  password_confirm: [
    'input[name="password_confirm"]', 'input[name="password_confirmation"]',
    'input[name="confirm_password"]', 'input[name="confirmPassword"]',
    'input[name="password2"]', 'input[name="repassword"]',
    'input[placeholder*="confirm" i][type="password"]',
    'input[autocomplete="new-password"]:nth-of-type(2)',
  ],
  name: [
    'input[name="name"]', 'input[name="full_name"]', 'input[name="fullName"]',
    'input[name="display_name"]', 'input[name="displayName"]',
    'input[placeholder*="full name" i]', 'input[autocomplete="name"]',
    'input[id*="name" i]:not([id*="user"]):not([type="email"])',
  ],
  first_name: [
    'input[name="first_name"]', 'input[name="firstName"]', 'input[name="fname"]',
    'input[placeholder*="first name" i]', 'input[autocomplete="given-name"]',
  ],
  last_name: [
    'input[name="last_name"]', 'input[name="lastName"]', 'input[name="lname"]',
    'input[placeholder*="last name" i]', 'input[autocomplete="family-name"]',
  ],
  company: [
    'input[name="company"]', 'input[name="organization"]', 'input[name="org"]',
    'input[placeholder*="company" i]', 'input[autocomplete="organization"]',
  ],
  phone: [
    'input[name="phone"]', 'input[name="telephone"]', 'input[name="mobile"]',
    'input[type="tel"]', 'input[placeholder*="phone" i]',
    'input[autocomplete="tel"]',
  ],
};

const SUBMIT_SELECTORS = [
  'button[type="submit"]',
  'input[type="submit"]',
  'button:has-text("Sign up")',
  'button:has-text("Register")',
  'button:has-text("Create account")',
  'button:has-text("Get started")',
  'button:has-text("Join")',
  'button:has-text("Start")',
  'button:has-text("Continue")',
  'button:has-text("Next")',
  'a:has-text("Sign up")',
  'a:has-text("Register")',
];

const TOS_SELECTORS = [
  'input[name*="terms" i][type="checkbox"]',
  'input[name*="tos" i][type="checkbox"]',
  'input[name*="agree" i][type="checkbox"]',
  'input[name*="accept" i][type="checkbox"]',
  'input[name*="consent" i][type="checkbox"]',
  'input[id*="terms" i][type="checkbox"]',
  'input[id*="agree" i][type="checkbox"]',
  'label:has-text("terms") input[type="checkbox"]',
  'label:has-text("agree") input[type="checkbox"]',
  'label:has-text("accept") input[type="checkbox"]',
];

async function findAndFill(page, fieldType, value) {
  const selectors = FIELD_SELECTORS[fieldType];
  if (!selectors) return false;

  for (const selector of selectors) {
    try {
      const el = page.locator(selector).first();
      if (await el.isVisible({ timeout: 500 })) {
        await el.click();
        await randomDelay(50, 150);
        // Type with human-like timing
        for (const { char, delay } of humanType(value)) {
          await el.pressSequentially(char, { delay: 0 });
          await new Promise((r) => setTimeout(r, delay));
        }
        await randomDelay(200, 500);
        return true;
      }
    } catch {
      // Selector not found or not visible — try next
    }
  }
  return false;
}

async function checkTosBoxes(page) {
  for (const selector of TOS_SELECTORS) {
    try {
      const el = page.locator(selector).first();
      if (await el.isVisible({ timeout: 300 })) {
        const checked = await el.isChecked();
        if (!checked) {
          await el.check();
          await randomDelay(100, 300);
        }
      }
    } catch {
      // Not found — skip
    }
  }
}

async function clickSubmit(page) {
  for (const selector of SUBMIT_SELECTORS) {
    try {
      const el = page.locator(selector).first();
      if (await el.isVisible({ timeout: 500 })) {
        await randomDelay(300, 800);
        await el.click();
        return true;
      }
    } catch {
      // Try next
    }
  }
  return false;
}

async function extractAuth(context) {
  const cookies = await context.cookies();
  const cookieObj = {};
  for (const c of cookies) {
    cookieObj[c.name] = c.value;
  }

  // Extract localStorage and sessionStorage from all pages
  const localStorage = {};
  const sessionStorage = {};
  for (const p of context.pages()) {
    try {
      const ls = await p.evaluate(() => {
        const items = {};
        for (let i = 0; i < window.localStorage.length; i++) {
          const key = window.localStorage.key(i);
          if (/token|auth|session|jwt|key|csrf|bearer|access|refresh/i.test(key)) {
            items[key] = window.localStorage.getItem(key);
          }
        }
        return items;
      });
      Object.assign(localStorage, ls);

      const ss = await p.evaluate(() => {
        const items = {};
        for (let i = 0; i < window.sessionStorage.length; i++) {
          const key = window.sessionStorage.key(i);
          if (/token|auth|session|jwt|key|csrf|bearer|access|refresh/i.test(key)) {
            items[key] = window.sessionStorage.getItem(key);
          }
        }
        return items;
      });
      Object.assign(sessionStorage, ss);
    } catch {
      // Page may have navigated — skip
    }
  }

  // Build Authorization header if we find a token
  const headers = {};
  const tokenValue = localStorage.access_token || localStorage.token || localStorage.jwt ||
    localStorage.auth_token || localStorage.accessToken || localStorage.id_token ||
    sessionStorage.access_token || sessionStorage.token;
  if (tokenValue) {
    headers["Authorization"] = `Bearer ${tokenValue}`;
  }

  return { cookies: cookieObj, local_storage: localStorage, session_storage: sessionStorage, headers };
}

// ── Main ──

async function main() {
  let config;
  try {
    config = JSON.parse(process.argv[2] || "{}");
  } catch (err) {
    output({ error: `Invalid JSON config: ${err.message}` });
  }

  const {
    signup_url,
    target_domain,
    email,
    password,
    name = "Hunter Test",
    capsolver_api_key,
    proxy,
    timeout_ms = 45000,
    headless = false,
  } = config;

  if (!signup_url) output({ error: "signup_url is required" });
  if (!target_domain) output({ error: "target_domain is required" });
  if (!email) output({ error: "email is required" });
  if (!password) output({ error: "password is required" });

  try {
    const { assertSafeRequestUrl } = require("./lib/safe-fetch.js");
    assertSafeRequestUrl(signup_url, target_domain);
  } catch (err) {
    output({
      success: false,
      fallback: "manual",
      scope_decision: "blocked",
      error: err.message || String(err),
    });
  }

  let patchright;
  try {
    patchright = require("patchright");
  } catch {
    output({ error: "patchright not installed. Run: npm install && npx patchright install chromium" });
  }

  const launchOptions = {
    headless,
    args: [
      "--disable-blink-features=AutomationControlled",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-infobars",
      "--window-size=1440,900",
    ],
    ignoreDefaultArgs: ["--enable-automation"],
  };

  // Try real Chrome first, fall back to bundled Chromium
  let browser;
  try {
    browser = await patchright.chromium.launch({ ...launchOptions, channel: "chrome" });
  } catch {
    try {
      browser = await patchright.chromium.launch(launchOptions);
    } catch (err) {
      output({ error: `Browser launch failed: ${err.message}` });
    }
  }

  const contextOptions = {
    viewport: { width: 1440, height: 900 },
    userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    locale: "en-US",
    timezoneId: Intl.DateTimeFormat().resolvedOptions().timeZone,
    colorScheme: "light",
    reducedMotion: "no-preference",
  };

  if (proxy) {
    const url = new URL(proxy);
    contextOptions.proxy = {
      server: `${url.protocol}//${url.host}`,
      username: url.username || undefined,
      password: url.password || undefined,
    };
  }

  const context = await browser.newContext(contextOptions);
  const page = await context.newPage();

  // Set a hard timeout for the entire operation
  const deadline = setTimeout(() => {
    output({ error: "Signup timed out", timeout_ms });
  }, timeout_ms);

  try {
    // Navigate to signup page and wait for full render (SPA hydration + consent banners)
    await page.goto(signup_url, { waitUntil: "domcontentloaded", timeout: 15000 });
    await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
    await randomDelay(2000, 3000);

    // Dismiss cookie/consent banners before interacting with the page
    await dismissConsentBanners(page);

    // Fill form fields
    const filled = {};
    filled.email = await findAndFill(page, "email", email);
    filled.password = await findAndFill(page, "password", password);
    filled.password_confirm = await findAndFill(page, "password_confirm", password);

    // Try name fields
    const filledFullName = await findAndFill(page, "name", name);
    if (!filledFullName) {
      const parts = name.split(" ");
      filled.first_name = await findAndFill(page, "first_name", parts[0] || "Hunter");
      filled.last_name = await findAndFill(page, "last_name", parts.slice(1).join(" ") || "Test");
    } else {
      filled.name = true;
    }

    // Optional fields
    filled.company = await findAndFill(page, "company", "Security Research LLC");

    // Check TOS boxes
    await checkTosBoxes(page);

    // Solve CAPTCHA if present
    let captchaResult = { solved: false, type: null, reason: "not_attempted" };
    try {
      captchaResult = await solveCaptcha(page, capsolver_api_key);
    } catch (err) {
      captchaResult = { solved: false, type: "unknown", reason: err.message };
    }

    // Submit the form
    const submitted = await clickSubmit(page);
    if (!submitted) {
      // Fallback: press Enter in the last focused field
      await page.keyboard.press("Enter");
    }

    // Wait for navigation or response
    try {
      await page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 10000 });
    } catch {
      // Some SPAs don't navigate — wait for network to settle
      await page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {});
    }
    await randomDelay(1000, 2000);

    // Check for error messages on the page
    const pageErrors = await page.evaluate(() => {
      const errorSelectors = [
        ".error", ".alert-danger", ".alert-error", '[role="alert"]',
        ".form-error", ".field-error", ".validation-error", ".error-message",
      ];
      const errors = [];
      for (const sel of errorSelectors) {
        document.querySelectorAll(sel).forEach((el) => {
          const text = el.textContent?.trim();
          if (text && text.length < 200) errors.push(text);
        });
      }
      return errors;
    });

    // Extract auth data
    const authData = await extractAuth(context);
    const finalUrl = page.url();
    const authEvidence = authEvidenceFromAuthData(authData);
    const success = submitted &&
      pageErrors.length === 0 &&
      hasAuthEvidence(authEvidence) &&
      normalizeUrlForSignupSuccess(finalUrl) !== normalizeUrlForSignupSuccess(signup_url);

    clearTimeout(deadline);
    await browser.close();

    output({
      success,
      fallback: success ? undefined : "manual",
      filled_fields: filled,
      captcha: captchaResult,
      submitted,
      redirect_url: finalUrl,
      page_errors: pageErrors,
      auth_evidence: authEvidence,
      diagnostics: success ? undefined : {
        submitted,
        page_errors: pageErrors,
        filled_fields: filled,
        redirect_url: finalUrl,
        auth_evidence: authEvidence,
      },
      ...authData,
    });
  } catch (err) {
    clearTimeout(deadline);
    try { await browser.close(); } catch {}
    output({ success: false, fallback: "manual", error: err.message, stack: err.stack?.split("\n").slice(0, 3).join(" | ") });
  }
}

main().catch((err) => output({ success: false, fallback: "manual", error: err.message }));
