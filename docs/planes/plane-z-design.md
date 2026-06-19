# Plane Z Design: Phishing-Kit Detection + Recon Wrappers

Status: design-only follow-up from PR #61 post-merge task #129.

Plane Z extends the Plane Y target-class and stigmergy work into a first-class
phishing-kit detection axis. The goal is not to add a second orchestrator. Plane
Z contributes technique packs, bounded MCP wrappers, and telemetry edges that
the existing wave scheduler and graph scheduler can consume.

## Current State

The repository already has the start of this axis:

- `mcp/lib/target-classes.js` includes `phishing_fraud`.
- `mcp/lib/target-class-pack-derivation.js` maps `phishing_fraud` to four
  auxiliary tools.
- `test/wave-brief-target-class.test.js` and
  `test/derive-pack-with-target-class.test.js` pin the target-class threading.
- `mcp/lib/queue-policy.js` carries `target_class_default` and
  `subdomain_enum_circuit_breaker_threshold`.

Plane Z builds on that substrate by adding richer phishing-kit pack semantics
and moving common recon steps onto the Bob ledger.

## Purpose

Bob is currently structurally better at web-app and smart-contract evaluation
than phishing-kit triage. Phishing-kit work has different signals:

- cloned brand surfaces and lookalike domains,
- kit-family fingerprints,
- credential-harvest endpoints,
- mobile user-agent cloaking,
- redirect and websocket exfiltration chains,
- hosting and takedown lifecycle signals.

Those signals should become typed observations and capability-pack inputs, not
ad hoc notes in evaluator prose.

## Hypergraph

Node families:

- `PhishingKit`: suspected kit instance or kit family.
- `KitSignature`: stable fingerprint such as DOM marker, path layout, asset
  hash, request shape, or exfil endpoint pattern.
- `BrandSurface`: protected brand, login surface, wallet surface, or customer
  portal being impersonated.
- `ReconSurface`: subdomain, URL, historical URL, certificate name, JS bundle,
  redirect chain, or observed host.
- `ExfilEndpoint`: credential postback, websocket collector, telemetry endpoint,
  or third-party paste/bin endpoint.
- `TakedownAction`: operator decision or external abuse-report record.

Hyperedges:

- `Z0 classify_target`: `Surface + queue_policy.target_class_default` ->
  `target_class: phishing_fraud`.
- `Z1 enumerate_recon`: seed domain + egress identity + circuit breaker ->
  `ReconSurface[]`.
- `Z2 fingerprint_kit`: `ReconSurface[] + HTTP bodies + JS assets` ->
  `KitSignature[]`.
- `Z3 group_kit_family`: `KitSignature[] + shared exfil endpoints` ->
  `PhishingKit`.
- `Z4 bind_brand_surface`: `PhishingKit + visual/login/form signals` ->
  `BrandSurface`.
- `Z5 develop_claim`: `PhishingKit + BrandSurface + ExfilEndpoint` ->
  `CandidateClaim`.
- `Z6 takedown_snapshot`: verified claim + operator decision ->
  `TakedownAction`.

All edges append existing `frontier-events.jsonl` kinds where possible. New
top-level event kinds are avoided unless a later realization proves the existing
observation/task/claim events cannot represent the data.

## MCP Tools

### `bob_subdomain_enumerate`

Purpose: wrap common passive/active subdomain enumeration into a bounded,
ledgered operation.

Inputs:

- `target_domain` (required)
- `providers` (optional closed list: `subfinder`, `amass`, `crtsh`,
  `securitytrails`)
- `max_results` (default 500, hard cap 5000)
- `timeout_ms` (default 60000)
- `egress_profile` (optional, authority checked)
- `include_active` (default false)

Behavior:

- Reads the session's egress and internal-host policy.
- Runs only installed local tools; missing optional binaries produce structured
  warnings, not shell fallback snippets.
- Deduplicates and normalizes hostnames.
- Applies `subdomain_enum_circuit_breaker_threshold` before appending events.
- Writes a session artifact such as `recon/subdomains.json`.
- Appends `surface.observed` and `observation.recorded` events with provider
  provenance.

### `bob_phishing_intel`

Purpose: collect phishing-kit intelligence from bounded OSINT providers and a
local kit-signature database.

Inputs:

- `target_domain` (required)
- `url` or `host` (required one-of)
- `providers` (optional closed list: `urlscan`, `phishtank`,
  `virustotal`, `local_kit_db`)
- `max_records` (default 100, hard cap 1000)
- `timeout_ms` (default 45000)
- `egress_profile` (optional, authority checked)

Behavior:

- Queries only configured providers. API keys must come from environment
  references or egress profiles; request secrets are never written to reports.
- Normalizes provider hits into `KitSignature`, `ReconSurface`, and
  `ExfilEndpoint` records.
- Writes `recon/phishing-intel.json`.
- Appends observations with `observation_kind` values such as
  `kit_signature_observed`, `brand_impersonation_suspected`, and
  `exfil_endpoint_observed`.

## Technique Packs

Initial pack family:

- `phishing_kit_cloaking`: mobile/desktop user-agent splits, geo/IP gates,
  redirector-only landing pages.
- `credential_harvest`: form postbacks, fake OAuth, fake wallet-connect flows,
  OTP capture.
- `websocket_exfil_collector`: websocket or long-poll collectors receiving form
  state or wallet prompts.
- `mobile_ua_cloaking`: mobile-only login clones, native-app deep-link traps,
  short-lived redirect chains.

These packs should live in the existing evaluator knowledge registry and be
selected through target-class and friction derivation. They should not add a
new role family unless the current evaluator/chain-builder roles cannot express
the work.

## Cycles

Z.1: Target-class pack enrichment

- Add the phishing-kit pack family to evaluator techniques.
- Extend tests that currently assert the four auxiliary tools to also assert
  pack selection and brief emphasis.

Z.2: `bob_subdomain_enumerate`

- Add registry-driven tool module, schema, authority inventory row, and tests.
- Add optional-binary behavior for `subfinder` and `amass` with clean skip
  diagnostics.

Z.3: `bob_phishing_intel`

- Add provider-normalization library and tool module.
- Add redaction tests for provider tokens, request bodies, screenshots, and
  evidence summaries.

Z.4: Frontier and graph materialization

- Project `KitSignature`, `ReconSurface`, and `ExfilEndpoint` into existing
  surface graph and frontier views.
- Add materializer tests that show kit-family grouping without adding new
  lifecycle states.

Z.5: Terminal smoke

- Add a synthetic phishing-kit fixture that exercises target-class derivation,
  subdomain enumeration stub output, phishing-intel stub output, claim
  development, and report snapshot binding.

## Invariants

- Preserve single-spawner topology: only wave scheduler and graph scheduler
  dispatch work.
- Preserve Y-P4 purity: target-class pack derivation stays deterministic and
  does not read disk or environment.
- Preserve Y-P13 audit-graded paths: reports, chains, evidence packs, grade,
  and handoffs remain MCP-owned.
- Preserve Y-P14 stigmergy: every new producer has a manifested consumer and a
  citable source location.
- Preserve authorization binding: recon wrappers must respect target binding,
  egress identity, internal-host policy, and first-party host checks.
- Preserve redaction: provider keys, cookies, request bodies, screenshots, and
  evidence excerpts must not leak into telemetry or report summaries.

## Acceptance Criteria

- New tools are registry-driven and appear in generated agent/tool surfaces.
- `npm run check:syntax`, `npm run test:mcp`, and relevant prompt/skill checks
  pass.
- Missing optional recon binaries produce structured skip/warning diagnostics.
- Provider tokens are accepted only via environment references or configured
  egress profiles.
- Terminal smoke proves a synthetic phishing-kit path from recon observation to
  CandidateClaim without real target scanning.

## Open Questions

- Where should the local kit-signature database live, and how is it updated?
- Should provider integrations be read-only by default, with active scanning
  behind a separate policy flag?
- What false-positive triage path should distinguish benign brand mentions from
  phishing-kit evidence?
- Should takedown artifacts remain operator-authored notes, or become a typed
  MCP-owned artifact once claims are verified?
