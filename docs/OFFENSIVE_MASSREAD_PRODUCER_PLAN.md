# Offensive mass-read producer + WAF browser transport — design

Status: in progress (2026-06-22). Source of the requirement: a client pentest surfaced an
unauth/under-authorized bulk-PII read that the signed offensive rail had **no producer
for** — the broken-auth/mass-read class. This adds that producer, plus the WAF-capable
transport it needs (the finding was only provable through Cloudflare via the real-Chrome
channel). (Client/engagement specifics are deliberately omitted — this doc ships in the
published package.)

## Bug class

**Broken authorization → mass-read of a bulk sensitive collection.** An
under-authorized identity (unauth, a leaked/guessable credential, or a low-privilege
account) reads a bulk collection it should not — e.g. a listing/search endpoint that
returns many production records (emails / phones / financial identifiers) to a caller
that should only see its own.

## The oracle — `safe_oracle.kind: "differential_response"`, ceiling HIGH

Two requests, both **through the WAF via the real-Chrome browser transport**:

1. **attacker** identity (the under-authorized access) → response A
2. **control** baseline (denied: unauth, or a deliberately-invalid credential) → response C

**Derive a masked summary in-memory, then DISCARD the raw body:**
- `record_count` — number of items in the returned collection
- `sensitive_field_names` — which known-sensitive field *names* appear (`email`, `phone`,
  `iban`, `ssn`, `dob`, ...). Names only.
- `pii_shape_present` — booleans from shape-regex run over values; the values are thrown
  away, only the booleans are kept.

**Positive** requires:
- attacker: `2xx` AND `record_count ≥ MASSREAD_MIN_RECORDS` (bulk, not a single self-record)
  AND `≥1` sensitive field shape present
- control: `401/403` OR `2xx` with `0` records / no sensitive shapes (the control is
  DENIED the bulk data)

i.e. the attacker reads bulk PII the control cannot — a *differential* that proves an
authorization failure, not merely a public endpoint.

## The witness — dual output (operator decision, 2026-06-22)

Two separate outputs, by design:

1. **Signed proof row (`offensive-runs.jsonl`)** — ALWAYS masked. The capture hashed and
   signed contains only `record_count` + `sensitive_field_names` + `pii_shape_present`
   booleans + the differential statuses. It is screened by `sensitiveShapesPresent` and
   MUST contain no raw PII. This is the tamper-evident rail that lifts the severity
   ceiling; keeping raw PII here would break the safety screen for every future run
   (including third-party bug-bounty use where harvesting strangers' data is forbidden — the
   `no-PII-harvest` lesson). **Non-negotiable: signed rail stays masked.**
2. **Full evidence capture (`massread-evidence/<run_id>.json`)** — opt-in, operator-owned.
   When the operator confirms the client OWNS the data and authorizes full capture
   (`owner_authorized: true` — explicit, never default; the same tool runs against
   third-party bug-bounty targets where this must stay off), the producer ALSO writes the
   full raw response body to a clearly-marked, **gitignored**, sync-excluded file the
   operator deletes manually at the end of the engagement. Cautions: the folder must NOT
   be in any sync/backup path (life-context / openclaw mirrors); deletion is the
   operator's responsibility. This path is OUTSIDE the signed rail and never feeds the
   PII-screened capture.

## The WAF transport (Chrome + a trusted `authed_fetch`)

The in-process `safeFetch` is Cloudflare-blind (bare Node TLS fingerprint → 403). The
existing Patchright + system-Chrome stack (used by `bob_http_xss_confirm`) beats CF. So
(implemented in PR1, hardened across review rounds 2–3):

- **Auth injection over stdin, never the env** — cookies are sent to the driver AFTER ready
  via a server-side-only `set_auth_cookies` command (`mcp/lib/browser-sessions.js` →
  `mcp/browser-driver.js#setAuthCookies`), so auth secrets never touch the process
  environment (no child/renderer inheritance, no `/proc/<pid>/environ` snapshot). EACH
  cookie's target host is scope-validated against `target_domain` before it reaches the
  context — an out-of-scope cookie fails the whole session closed. Threaded from the
  producer, never an agent.
- **A trusted `authed_fetch` driver command** — server-side-only, NOT agent-reachable.
  Issues a scope-checked authenticated request from the **page world** (`page.evaluate` of a
  server-built `fetch`) — this is required to carry the real Chrome TLS/HTTP-2 fingerprint;
  a Node-side `context.request` is CF-403'd like `safeFetch`. The agent-facing `evaluate`
  sandbox (`FORBIDDEN_EVAL_PATTERN` — no `fetch(`/XHR/WS) stays FULLY CLOSED; only the
  trusted producer path uses the new command. Scaffolding mirrors `xss_confirm`:
  `assertSafeResolvedRequestUrl` (URL + origin) + `waitUntil:"commit"` (minimal authed-page
  execution) + final-URL origin-drift guard + `redirect:"manual"` (no off-scope auth leak) +
  a wall-clock timeout race + an in-page `AbortSignal.timeout` (no lingering renderer
  request) + a body cap measured in **bytes** (not UTF-16 code units), enforced while
  streaming.
- **DNS-rebinding pin (required, not opt-in)** — the target host is resolved ONCE in Node and
  Chrome is launched with `--host-resolver-rules=MAP <host> <validated-ip>`, so the browser
  connects to the IP we checked (closing the TOCTOU where the static scope check passes but
  Chrome would re-resolve to an internal/attacker IP). Because `authed_fetch` is ALWAYS
  credentialed, the pin is REQUIRED on every call (not just under `block_internal_hosts`): an
  unpinned host is refused fail-closed so a credentialed request can never ride a rebound
  hostname. The pin also records whether the resolved IP is internal; under
  `block_internal_hosts` a pinned-but-internal IP is refused too. **Producer contract:** start
  the browser session with `target_url` on the exact host you will read, so that host is the
  one pinned. Under an egress proxy the pin is N/A (DNS resolves at the proxy) and
  `block_internal_hosts` is refused rather than silently downgraded.
- **Refuse when `block_internal_hosts` is on** (same SSRF stance as `xss_confirm`, which
  cannot enforce the session SSRF policy through the browser) — the producer refuses; the
  driver's scope+pin checks are defense in depth for a direct call.
- **ACCEPTED RESIDUAL — page-controlled fetch.** The request runs in the page world, so a
  hostile target could in principle override `window.fetch`/`Response` to forge the result.
  This is inherent to the transport's purpose (real TLS fingerprint requires the page network
  stack), and a "native fetch capture" was tried and reverted — it is unreliable under the
  Patchright stealth driver and broke the transport. Compensating control: `waitUntil:
  "commit"` minimizes page-script execution before the fetch. On integrity, the
  authed-vs-control differential is NOT tamper-proof — the target CAN tell the authed arm (it
  carries the cookie) from the control arm and could serve forged data — but a target forging
  a vuln against ITSELF gains nothing (self-reporting), the per-tool ceiling bounds a forged
  result, and a single capture is evidence, not proof (the operator corroborates for
  integrity-sensitive use).

## Severity ceiling

`bob_http_massread_confirm: "high"` in `OFFENSIVE_TOOL_DEMONSTRATED_CEILING` (claims.js).
Honest HIGH: mass-read of PII is a HIGH (the motivating finding was graded HIGH). The producer proves the
IMPACT (bulk read); the underlying vuln (e.g. a hardcoded credential) is the finding.

## Delivery — two PRs

- **PR1 — browser transport** (this branch's first PR): auth injection + the trusted
  `authed_fetch` command in `mcp/browser-driver.js` (+ `browser-sessions.js` /
  `browser-tools-shared.js` plumbing) with its own driver-level tests (local test server).
  The security-critical, reusable piece, reviewed in isolation.
- **PR2 — the producer**: `mcp/lib/offensive-massread-producer.js` + the
  `bob_http_massread_confirm` tool wrapper + the differential oracle + dual-output witness
  + registration (ceiling, dual authority-class map, tools/index, evaluator prose) +
  generators + tests.

## Registration surface (PR2) — the load-bearing manual edits

Most of the registry is auto-derived from the tool module's `role_bundles: ["evaluator-web"]`.
The manual, fail-closed edits:
- `mcp/lib/claims.js` `OFFENSIVE_TOOL_DEMONSTRATED_CEILING` — add `bob_http_massread_confirm: "high"`.
- `mcp/lib/session-authority.js` + `scripts/authority-inventory.js` — add the **identical**
  `bob_http_massread_confirm: "scoped_http_network"` (the two maps must match or
  `validateExplicitAuthorityMap` throws).
- `mcp/lib/tools/index.js` — register the module in `TOOL_MODULES` (order-sensitive vs the
  test's `EXPECTED_TOOL_NAMES`).
- `prompts/roles/evaluator.md` + `prompts/roles/evaluator-spawn.md` — primitive→producer
  call-guidance prose (the #150 pattern).
- Test-fixture bumps (not auto-derived): `test/mcp-server.test.js` `EXPECTED_TOOL_NAMES`,
  `test/install-smoke.test.js` tool-count, `test/prompt-contracts.test.js` web budget
  (53→54), new `test/offensive-massread-producer.test.js` + register it in
  `test/mcp-test-manifest.json`.
- Generators after metadata: `generate-claude-roles.js` (or the individual agent/skill/
  settings generators), `generate-codex-skills.js`, `generate-kimi-roles.js`,
  `authority-inventory.js --write`.

## Safety invariants (must hold)

- Signed rail (`offensive-runs.jsonl`) carries NO raw PII — masked summary only, screened
  by `sensitiveShapesPresent`, fail-closed.
- Full raw capture only when `owner_authorized: true`, to a gitignored operator-managed
  file outside the signed rail.
- Agent-facing browser `evaluate` sandbox unchanged (no new agent network primitive).
- Auth material flows producer → driver over **stdin, never the env**; each cookie is
  scope-validated against `target_domain` before it reaches the browser context.
- The browser is DNS-pinned to the Node-validated IP (`--host-resolver-rules`); an unpinned
  host is refused on EVERY (always-credentialed) `authed_fetch`, and a pinned-but-internal IP
  is refused under `block_internal_hosts`.
- `authed_fetch` does not follow redirects (`redirect:"manual"`), self-aborts on timeout,
  and caps the body in bytes.
- Page-controlled fetch is an accepted residual (see transport section) — mitigated by
  `waitUntil:"commit"` + the differential design, not by an unreliable native-fetch capture.
- Every request audited via `auditConfirmRequest`; refuse under `block_internal_hosts`.
- `demonstrated_severity` stamped from the frozen registry, never agent-supplied; the
  per-tool ceiling bounds blast radius to a fabricated HIGH at worst (the #131 same-UID
  forge boundary remains the documented, deferred limit).
