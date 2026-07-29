# Ephemeral-runner contract

The container entrypoint contract for hosted bob (Rail B). One EC2 ephemeral
container per engagement: **authorize → container → stream → seal → teardown**.
The container provisions, binds an egress identity, runs bob, streams curated
events the site witnesses live, POSTs a sealed report, and **destroys itself**.

This document specifies the *contract*. The `run.mjs` entrypoint glue and the
in-place edits to egress / scope / session-authority are a separate node (runner
glue); this spec is what that glue must satisfy.

## Stance

- **A publisher, not a new engine path.** The container runs the **existing mcp
  engine**. It selects an engine target family by `targetKind`, binds the
  **existing** scope gate (`mcp/lib/scope.js`) and **existing** egress profiles
  (`mcp/lib/egress-profiles.js`), and publishes the result on the **existing**
  ingest path (`POST /api/reports`, exactly as `bob-report publish`). The runner
  introduces no second grading path, no second seal, no second report surface.
  Where the contract says "the engine does X", it means the local rail's X,
  reused unchanged.
- **Ephemerality is the moat.** Provision → run → seal → **destroy** is
  mechanical forgetting extended to compute. Nothing persists in a vendor lake.
  The destroy is a real terminal event, not a cleanup afterthought.
- **Two rails, one soul.** This container is the local CLI bob, wrapped so a
  visitor who cannot operate it can **watch the adversary run**. Same engine,
  same gates, same seal — only the witness is new.

## Inputs

The entrypoint receives one **signed authorization payload**, shape pinned by
[`authorization.schema.json`](./authorization.schema.json) and shared with the
bob-site run-dispatch endpoint:

```
{ target, targetKind(repo|web|sc), runMode, autonomy,
  callbackUrl, ingestToken, accessPassword,
  engagementId, issuedAt, expiresAt, schemaVersion,
  scope?, egressProfile? }
```

Two secrets travel **out-of-band**, at the transport layer, never in this
payload and **never in model context**:

- the **runner write-secret** for Convex `run_events` / `runs` writes (mirrors
  `REPORTS_SECRET` discipline in `convex/reports.ts`);
- nothing else — `ingestToken` and `accessPassword` arrive *in* the payload but
  are immediately demoted to transport material (forwarded to `/api/reports`,
  never echoed into a streamed event or a model prompt).

## Lifecycle

The order is **discipline in the order of commitment**, not a clickflow. No step
name (`SETUP`/`OPEN_FRONTIER`/`CLAIM_FREEZE`/`VERIFY`/`GRADE`/`REPORT`) is ever
sent as on-screen text; the site **reads the state from what arrives, in what
rhythm, with what weight** — driving the existing unlabeled lifecycle gauge in
`Witness.svelte` from the streamed `phase`, never a progress bar or step counter.

### 1. Authorize (verify the grant — fail closed)

Before any side effect:

1. Verify the payload signature against the dispatch key. Bad signature → exit,
   no container work, no event.
2. Reject if `now > expiresAt` or `schemaVersion` is unrecognized.
3. **Bind the autonomy gradient — the one rule.** Cross-check `autonomy`
   against `targetKind`:
   - `autonomous` is permitted **only** for a zero-blast-radius repo run.
   - any live target (`web`, `sc`, or a private/staging/prod repo) **requires**
     `operator-approved` — a named human has authorized this exact engagement.
   - a mismatch (e.g. `autonomous` + `web`) **fails closed**: no container, no
     run, no event. The gate is a rule carried on the grant, not a wizard.
4. **Bind the scope gate.** Seed the engine's existing fail-closed scope from
   `target` (+ optional `scope.allowedHosts` / `scope.labAuthorization`) through
   `assertHttpScopeDomain` / `validateHttpScanScope`. Any entry that fails the
   gate fails the **whole grant**. The runner adds **no** scope bypass the local
   rail does not already have; lab/private escapes stay operator-attested and
   off by default.

A failure here is silence at the site, by design — nothing was authorized, so
nothing is witnessed. (The dispatch endpoint, not the container, narrates a
refusal to the operator.)

### 2. Container (provision + bind egress identity)

1. Provision the isolated container for `engagementId`. It self-names by
   `engagementId`; one engagement == one container.
2. **Bind the egress identity** from `egressProfile` (or the provisioned
   default) via `egress-profiles.js`, resolving the proxy/region.
3. Emit the **opening event** (`run.opened`, see Event contract) carrying
   `egress_profile_identity_hash` — **who the container is on the wire**. This is
   plain disclosure in bob's transparency voice, the inversion of a hidden
   background. Not a badge, not a lock, not gold.

> **The provision wait is the hardest moment.** Between dispatch and the first
> event there is a real machine wait. The contract **forbids the runner from
> emitting any "provisioning %" / "booting" / heartbeat / status event** to fill
> it. The site holds that gap as **wait-as-presence**: bob's voice over the Sea
> still breathing. The runner's only obligation is to emit `run.opened` **as
> soon as** egress is bound and not before — a true first breath, not a
> placeholder. No spinner exists anywhere in this contract.

### 3. Stream (curated events → Convex live queries)

The container runs the existing engine and **writes curated events** to Convex
(`run_events`, keyed by `engagementId`) using the runner write-secret. Convex
**live queries are the streaming layer** — the browser subscribes; there is no
WebSocket, SSE, or Durable Object.

**Curated, not a log dump.** The runner translates raw engine artifacts
(`frontier-events.jsonl`, `coverage.jsonl`, chain attempts, `claim-freeze.json`,
`grade.json`) into the **same vocabulary the Witness drum already renders**
(`wire`/`attempts`/`spill`/`pivot`/`matrix`/`code`/`grade`/`verdict`). The live
run is that vocabulary **arriving in time** rather than pre-composed. The runner
emits **only** what a face needs; raw stdout/stderr, secrets, and full ledgers
are never streamed.

#### The three-register law governs every event

Every event declares a `register` and the site honors it. There is no fourth
register — no `status`, no `metric`, no `log-line`, no `badge`.

- **Breath** — the accreting majority. `frontier.observed`, `coverage.tested`,
  `attempt.denied`, `phase.entered`. These **manifest by opacity, hold, and do
  not delete**. A closure (a hardened surface, a dead end) **recedes to
  breath-weight**, it is never removed. The stream is an **accreting ledger**,
  never a scrolling tail that pushes old lines away.
- **Strike** — reserved. The genuine `claim.developed` — *"that one's mine"*.
  **At most twice per run.** The runner must not mark every finding a Strike;
  over-striking turns the cut-in into decoration. Most findings begin life as
  Breath and only the developed claim cuts in.
- **Body** — the run's standing prose: the disposition as it crystallizes.

#### Severity rides weight, never color

A finding's severity is carried as `band` (`critical|high|medium|low`) + a CVSS
`vector`, exactly the Witness CVSS-cell data. The site renders severity as
**weight** (lit/dim) plus the single sanctioned `--signal-warn` ember for
HIGH/CRITICAL bands. The runner sends **no status color**, no red/yellow/green
stack, no green "up" dot. `--signal` (gold) appears only where the engine
genuinely found something or recognition has cost — never on liveness.

#### Phase drives the gauge, never a bar

Each event carries the current lifecycle `phase`. The site dedupes phases the
way the gauge already does and fills depth from the **live** phase — the
disciplined alternative to a progress bar. The runner never sends a percent, a
step number, or an ETA.

#### The disposition crystallizes (defender relens)

As verify/grade events arrive, the runner streams the **deterministic
disposition projection** — `final severity × reachability × score ×
reportable` → **`fix now` / `worth fixing` / `watch` / `held`**. bob's grade
math is **untouched**; the runner ships the same deterministic verdict the
engine computes and **projects** it. The customer-facing disposition is all that
streams: **drop `SUBMIT`/`HOLD`/`SKIP`, drop EV/USDC/triager prose** — those
stay LLM prose on operator surfaces, off the customer stream. `--signal` /
`--signal-warn` are permitted on the disposition **only** at the `fix now` /
severe terminus, never on the intermediate states.

#### Voice

Any prose a curated event carries is **bob's voice**: first person *I*, the
visitor is *you*, never *we*; one breath, two clauses, periods not semicolons,
present tense, no future-promise, no exclamation. Specific over general. bob does
not gloat over a finding and does not narrate the UI.

### 4. Seal (publish the report — unchanged path)

When the run grades out, the container **POSTs the sealed result to
`/api/reports`**, **byte-for-byte the way the CLI `bob-report publish` does**:

```
POST {callbackUrl-site}/api/reports
Authorization: Bearer {ingestToken}
Content-Type: application/json
{ domain, recipient?, method?, date?, model, business?, password: accessPassword }
```

bob-site hashes `accessPassword` (PBKDF2, `report-crypto.ts`), stores the sealed
record in Convex `reports`, and returns `{ slug, url }`. The runner emits one
final Body/Breath event carrying the `/r/<slug>` destination (the **slug only**,
never the password — the password reaches the operator out-of-band). **No new
seal, no new reader, no new crypto** — the sealed `/r` path is complete and is
reused as-is.

### 5. Teardown (destroy — witnessed)

After the seal POST returns `2xx`:

1. Emit the terminal `run.sealed` event, then the **`run.destroyed`** event —
   the **seal/destroy finality beat**. It declares `register: "strike"` used as
   a **closing, not a finding**: a single contained mark of finality the visitor
   **sees land**. It must read as **cleanliness and relief** — mechanical
   forgetting witnessed — **never** as `error`, `session ended`, `expired`, or
   `disconnected` chrome. The anti-KinoSec inversion: the forgetting is shown,
   not hidden.
2. **Destroy the container** — egress identity released, workspace gone, no
   standing credential survives. The destroy is mechanical; the
   `run.destroyed` event is its honest witness, written **before** the container
   can no longer write.
3. **On failure**, the container **still tears down** (fail-closed teardown). It
   emits a terminal event in bob's voice stating plainly that the run ended
   without a sealed result — one true line, not error chrome — and destroys
   itself anyway. A container is never left running, never left holding scope.

## Event contract (`run_events` row, summary)

The Convex schema is defined by the data node (`runs` + `run_events` tables);
the runner writes rows of this shape. Curated fields only:

| field | meaning |
| --- | --- |
| `engagementId` | partition key; one run |
| `seq` | monotonic per engagement; ordering, not a count shown to anyone |
| `kind` | `run.opened` \| `phase.entered` \| `frontier.observed` \| `coverage.tested` \| `attempt.denied` \| `claim.developed` \| `disposition.resolved` \| `run.sealed` \| `run.destroyed` |
| `register` | `body` \| `breath` \| `strike` — the rendering law, declared by the producer |
| `phase` | lifecycle phase for the gauge (never shown as text) |
| `face` | Witness panel kind this maps to (`wire`/`attempts`/`spill`/`pivot`/`matrix`/`code`/`grade`/`verdict`) when applicable |
| `payload` | the minimum a face needs — same engine vocabulary as the frozen Witness panels |
| `band` / `cvss` | severity as weight + CVSS vector (findings only) |
| `disposition` | `fix_now` \| `worth_fixing` \| `watch` \| `held` (verify/grade only) — the CANONICAL snake_case word the grade verdict stamped (`defender_disposition`), consumed verbatim so the live word IS the sealed word; the site renders it in its spoken form (`fix now` …) |
| `at` | epoch ms |

Disallowed in any row: raw stdout/stderr, full ledgers, secrets, the access
password, `ingestToken`, model-context text, EV/USDC/triager prose, percentages,
ETAs, status colors, step counts.

## Invariants

- **One grant, one container, one report, one destroy.** No reuse of
  `engagementId`.
- **Fail closed at every boundary** — signature, expiry, autonomy×target,
  scope. Reuses the engine's existing gates; adds none.
- **Secrets stay at transport.** `ingestToken` / `accessPassword` / write-secret
  never enter model context or a streamed event.
- **Reuse, do not rebuild.** mcp engine, `egress-profiles`
  (`egress_profile_identity_hash`), `scope.js` gates, `/api/reports`,
  `report-crypto`, `/r/<slug>`, Witness faces — all unchanged.
- **The witness obeys the three-register law.** Breath accretes and never
  deletes; Strike is the developed claim (≤2) and the destroy-finality; Body is
  the standing disposition. No fourth register.
- **No spinner, no bar, no status light, no dashboard** — anywhere in what the
  runner emits. The wait is presence; the state is felt; the destroy is relief.

## Out of scope for this node

The `run.mjs` entrypoint implementation and the in-place edits to
`egress-profiles.js` / `scope.js` / `session-authority.js` that bind a grant to
the engine are the **runner glue** node. This spec is the contract that glue —
and the bob-site run-dispatch endpoint — must satisfy.
