"use strict";

// runner-wiring: projection POST client.
//
// Runs as a child CLI from bob_finalize_report (whose wrapped handler is
// synchronous) and doubles as the dispatch service's redrive path. Bounded
// retry with backoff; fails closed: a dispatched run that cannot project
// refuses to complete rather than silently losing sealed findings.

const DELAY_CAP_MS = 30000;

function delayFor(attempt, initialDelayMs) {
  return Math.min(initialDelayMs * 2 ** (attempt - 1), DELAY_CAP_MS);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// POST the projection payload. Returns { ok, status, result, attempts } on a
// 2xx, or { ok:false, status, error, attempts } on a definitive non-2xx
// (4xx — the payload or capability is wrong, retrying cannot fix it). Throws
// only when retries are exhausted on 5xx/network failures.
async function postProjection({
  url,
  secret,
  payload,
  fetchImpl = null,
  maxAttempts = 5,
  initialDelayMs = 1000,
} = {}) {
  if (!url || !secret) throw new Error("projection URL and runner secret are required");
  const fetchFn = fetchImpl || fetch;
  let lastError = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let response;
    try {
      response = await fetchFn(url, {
        method: "POST",
        redirect: "error",
        headers: {
          Authorization: `Bearer ${secret}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });
    } catch (error) {
      lastError = error;
      if (attempt < maxAttempts) {
        await sleep(delayFor(attempt, initialDelayMs));
        continue;
      }
      throw new Error(
        `projection POST failed after ${maxAttempts} attempts: ${error.message || String(error)}`,
      );
    }
    if (response.ok) {
      let result = null;
      try {
        result = await response.json();
      } catch {
        result = null;
      }
      return { ok: true, status: response.status, result, attempts: attempt };
    }
    const body = await response.text().catch(() => "");
    const failure = {
      ok: false,
      status: response.status,
      error: body.slice(0, 500),
      attempts: attempt,
    };
    if (response.status >= 400 && response.status < 500) {
      return failure; // definitive: the payload or capability is rejected
    }
    lastError = new Error(`projection POST returned ${response.status}`);
    if (attempt < maxAttempts) {
      await sleep(delayFor(attempt, initialDelayMs));
      continue;
    }
    throw new Error(`projection POST failed after ${maxAttempts} attempts: HTTP ${response.status}`);
  }
  throw lastError || new Error("projection POST failed");
}

module.exports = {
  postProjection,
};
