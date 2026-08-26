"use strict";

// runner-wiring: projection POST client.
//
// Runs as a child CLI from bob_finalize_report (whose wrapped handler is
// synchronous) and doubles as the dispatch service's redrive path. Bounded
// retry with backoff; fails closed: a dispatched run that cannot project
// refuses to complete rather than silently losing sealed findings.

const DELAY_CAP_MS = 30000;
const RESPONSE_BODY_MAX_BYTES = 64 * 1024;

async function readBoundedResponseText(response) {
  const contentLength = response.headers?.get?.("content-length");
  if (/^\d+$/u.test(contentLength || "") && Number(contentLength) > RESPONSE_BODY_MAX_BYTES) {
    throw new Error(`projection response exceeds ${RESPONSE_BODY_MAX_BYTES} bytes`);
  }
  if (response.body && typeof response.body.getReader === "function") {
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      total += chunk.length;
      if (total > RESPONSE_BODY_MAX_BYTES) {
        try { await reader.cancel(); } catch {}
        throw new Error(`projection response exceeds ${RESPONSE_BODY_MAX_BYTES} bytes`);
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks, total).toString("utf8");
  }
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > RESPONSE_BODY_MAX_BYTES) {
    throw new Error(`projection response exceeds ${RESPONSE_BODY_MAX_BYTES} bytes`);
  }
  return text;
}

function delayFor(attempt, initialDelayMs) {
  return Math.min(initialDelayMs * 2 ** (attempt - 1), DELAY_CAP_MS);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// POST the projection payload. Returns { ok, status, result, attempts } on a
// 2xx, or { ok:false, status, error, attempts } on a definitive rejection
// (non-transient 4xx or a malformed 2xx contract response). Throws only when
// retries are exhausted on transient HTTP/network failures.
function assertProjectionEndpoint(value) {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim()) {
    throw new Error("projection URL must be an exact HTTPS /api/findings endpoint");
  }
  try {
    const endpoint = new URL(value);
    if (
      endpoint.protocol !== "https:" ||
      endpoint.hostname.length === 0 ||
      endpoint.username !== "" ||
      endpoint.password !== "" ||
      endpoint.port !== "" ||
      endpoint.search !== "" ||
      endpoint.hash !== "" ||
      endpoint.pathname !== "/api/findings"
    ) {
      throw new Error("invalid endpoint");
    }
  } catch {
    throw new Error("projection URL must be an exact HTTPS /api/findings endpoint");
  }
}

async function postProjection({
  url,
  secret,
  payload,
  fetchImpl = null,
  maxAttempts = 5,
  initialDelayMs = 1000,
  requestTimeoutMs = 30000,
} = {}) {
  assertProjectionEndpoint(url);
  if (
    typeof secret !== "string" ||
    secret.length === 0 ||
    secret.length > 4096 ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(secret)
  ) {
    throw new Error("runner secret is required and must be safe bounded text");
  }
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10) {
    throw new Error("projection maxAttempts must be an integer from 1 to 10");
  }
  if (!Number.isSafeInteger(initialDelayMs) || initialDelayMs < 0 || initialDelayMs > DELAY_CAP_MS) {
    throw new Error(`projection initialDelayMs must be an integer from 0 to ${DELAY_CAP_MS}`);
  }
  if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 300000) {
    throw new Error("projection requestTimeoutMs must be an integer from 1 to 300000");
  }
  const serializedPayload = JSON.stringify(payload);
  if (typeof serializedPayload !== "string") throw new Error("projection payload must be JSON serializable");
  const fetchFn = fetchImpl || fetch;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
    let retryReason = null;
    let responseStatus = null;
    try {
      const response = await fetchFn(url, {
        method: "POST",
        redirect: "error",
        headers: {
          Authorization: `Bearer ${secret}`,
          "Content-Type": "application/json",
        },
        signal: controller.signal,
        body: serializedPayload,
      });
      responseStatus = response.status;
      const body = await readBoundedResponseText(response);
      if (response.ok) {
        let result;
        try {
          result = body ? JSON.parse(body) : null;
        } catch (error) {
          if (controller.signal.aborted) throw error;
        }
        if (
          result == null ||
          typeof result !== "object" ||
          Array.isArray(result) ||
          !["projected", "reopened", "closed"].every(
            (field) => Number.isInteger(result[field]) && result[field] >= 0,
          )
        ) {
          return {
            ok: false,
            status: response.status,
            error: "projection success response was not a committed result",
            attempts: attempt,
          };
        }
        return { ok: true, status: response.status, result, attempts: attempt };
      }
      const failure = {
        ok: false,
        status: response.status,
        error: body.slice(0, 500),
        attempts: attempt,
      };
      if (
        response.status >= 400 &&
        response.status < 500 &&
        ![408, 425, 429].includes(response.status)
      ) {
        return failure;
      }
      retryReason = `HTTP ${response.status}`;
    } catch (error) {
      retryReason = error && error.message ? error.message : String(error);
      if (responseStatus >= 200 && responseStatus < 300) {
        return {
          ok: false,
          status: responseStatus,
          error: `projection success response was invalid: ${retryReason}`,
          attempts: attempt,
        };
      }
    } finally {
      clearTimeout(timeout);
    }
    if (attempt < maxAttempts) {
      await sleep(delayFor(attempt, initialDelayMs));
      continue;
    }
    throw new Error(`projection POST failed after ${maxAttempts} attempts: ${retryReason || "unknown error"}`);
  }
  throw new Error("projection POST failed");
}

module.exports = {
  postProjection,
};
