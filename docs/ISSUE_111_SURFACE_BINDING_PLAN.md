<!-- Generated 2026-06-15 by a 37-agent research+adversarial-design workflow (run wf_c977d5ba-b17).
     Research 4/6 lenses (surface_id-semantics + producer-it-gates rate-limited, compensated by red-team);
     3 candidate designs; 24 red-team attempts (19 vectors flagged); 2 critiques; final synthesis.
     Design robustness scores: A=2, B=1, C=2. Chosen spine: strict single-surface equality (refinement of A).
     Implemented by this PR (claims.js record gate + verification-round-store.js verify mirror + tests);
     this doc is the design rationale + producer-PR acceptance criteria. See GitHub issue #111. -->

I have verified every load-bearing claim against source (claims.js gate + stale comment 964-975, the MAC payload, the normalize/trim path, record-candidate-claim:508, the verify mirror's per-claim loop at 204 with refs at 215-230, paths.js audit-graded list, both test files, the confirmer's already-surface-matched flow, and `normalizeStringArray` trim/dedup). Here is the final build-ready plan.

---

# Implementation Plan — Issue #111: bind exploit rows to the claim surface (severity-ceiling cross-finding gate)

## 0. Overview

`assertExploitedClaimHasProof` (mcp/lib/claims.js:883) content-binds each cited `exploit_run` row to its ref (`offensiveRunRowSatisfiesEvidence`, 793-833), enforces `run_id` single-use (945-962), and clamps `claim.severity` to the max `demonstrated_severity` over the backed rows (976-1002) — but it **never checks that a cited row's surface matches the claim's finding/surface**. The gap is documented in-source at claims.js:964-975. Once a signed-row producer exists, a claim for surface A could cite a higher-severity row produced for surface B (same `run_id`, used once, content-bound, same domain) and the ceiling would pass: **cross-finding severity laundering**.

This PR closes that gap with an **additive, fail-closed surface-binding check** at record time, mirrored at verify time, before any signed-row producer ships. It is the gate the future "second-test-identity IDOR oracle" producer must build on.

### Threat boundary (stated up front, honestly)

This gate proves the **integrity** of the producer-stamped, MAC-covered `surface_id` and `demonstrated_severity` — it does **not** prove their **correctness**. Two correctness holes remain *by design* and are the producer PR's responsibility, not closeable in a string-binding gate:

- **Convergent mis-stamp** — a trusted producer that attacks endpoint B but stamps `surface_id = A` (and the agent files matching finding A) passes string equality. Closed by producer **AC-2** (surface == attacked endpoint).
- **Same-surface severity inflation** — a producer that stamps `demonstrated_severity = critical` on a low-impact read for surface A, paired with a critical claim for A, passes both the surface check and the ceiling. Closed by producer **AC-3** (server-derived severity).

Both are the same class as #108's "MAC proves integrity, not who ran the code." This is reasoned through in §6, §11, §12. The gate is the **necessary structural floor**; AC-2/AC-3 are the **sufficient producer obligations**, enforced where the producer holds the response bytes and the route.

### Why this design (vs the rejected alternatives)

- **"Bind to `claim.payload.finding.endpoint`" is out.** That field is agent-controlled free text never validated against the assignment-validated surface, and `canonicalizeExploitTarget` is method/query-blind — concrete laundering (cross-subdomain bare-path, method/query collision, `{id}`-template aggregation) reproduces against it, and it over-blocks legit cross-surface chains.
- **Strict single-surface equality (chosen)** is strictly stronger than per-ref membership on the surface axis: it blocks **surface-set padding** (`surface_ids=[A,B]` to satisfy membership for a B-row), is **fail-closed on a surfaceless row**, and ships the **verify-time mirror** in the same PR. Cost: it rejects a multi-surface exploited claim (none exist today) and a non-wave surfaceless exploited claim — documented and accepted in §1/§10/§12. The literal-issue deviation is elevated to an explicit, signed-off contract decision (§1).

---

## 1. Scope, sequencing, and the one contract decision that needs sign-off

**Ship #111 as a standalone pure-contract surface-binding PR FIRST, before the signed-row producer.** Tests seed hand-built signed rows (via `signOffensiveRunRow`), exactly as PR #108 landed the HMAC contract before any writer and PR #110 stayed negative-only.

Justification against the repo's "land the gate before the writer" discipline:
- The gap is **dormant today** — `bob_http_confirm` writes no `offensive-runs.jsonl` rows (offensive-confirmer.js is negative-only), so there is no row to launder. Nothing in production regresses.
- The memory note records the operator's explicit sequencing: the producer "MUST close #111" first; #111 "GATES the producer PR (dormant)."
- Landing the contract standalone means the producer PR inherits a gate it **cannot** disable.
- `assertExploitedClaimHasProof` is already exercised by `appendCandidateClaim`'s sole production caller; no producer code is required to test the gate.

### CONTRACT DECISION (requires operator sign-off in the PR description) — folds critique #1's blocking gap

Issue #111 req (2) literally says "require each backed exploit_run row's surface_id to be **IN** the claim's surfaces" (membership). This plan ships **strict equality + exactly-one surface**, which is stricter. **For every shape production produces today (`record-candidate-claim.js:508` always yields a single-element `surface_ids`), strict-single is identical to membership** — so the deviation is invisible to all current and near-term producers and *satisfies issue req (2) as a strict subset*. It only diverges for a hypothetical exploited_safely claim spanning two routed surfaces.

This is a **conscious contract choice, not an implementation detail.** The PR description must:
1. State the deviation explicitly and get operator confirmation that **no near-term producer** (the `bob_auto_signup` second-identity IDOR oracle, or any future chain producer) needs to record one finding spanning two routed surfaces.
2. If such a producer is ever planned, implement the documented **relax-path** instead: per-ref membership (every backed `row.surface_id ∈ claim.surface_ids`), dropping the exactly-1 rule. The two enforcement points (§3 record, §5 verify) must relax together.

Recommendation: **strict-single**, because the only thing membership buys is multi-surface exploited claims (which don't exist), while it reopens the surface-set-padding footgun. Get the sign-off; do not bury the choice.

---

## 2. Offensive-runs row schema change

**Add one field: `row.surface_id` (non-empty string), stamped by the producer.**

- **Auto-MAC-bound, no MAC code change.** `offensiveRowMacPayload` signs `{...row}` minus `row_mac` via `canonicalJson` (offensive-row-mac.js:22-26). Any field present on the row — a new `surface_id` and the existing `demonstrated_severity` — is therefore covered by the HMAC; `canonicalJson` is key-sorted so order is irrelevant; flipping/stripping `surface_id` invalidates the MAC and the row fails `verifyOffensiveRunRowMac` (58-75) → drops out of `backedRows` at claims.js:928-930 before the surface check runs. **No change to offensive-row-mac.js.**
- **`readOffensiveRunRecords` tolerates the field already.** It `JSON.parse`s each line with no field whitelist and fails closed on a malformed row (claims.js:726-746); the confirmer test already round-trips a row carrying `surface_id` (offensive-confirmer.test.js:237). **No paths.js change** — `offensive-runs.jsonl` stays audit-graded (paths.js:444) and agent-unwritable.
- **`demonstrated_severity` needs NO schema change.** It already exists on the row and is already MAC-bound. Its *correctness* is **not** a schema concern — it is producer AC-3 (§6), because the MAC proves integrity, not correctness.

The producer must set `row.surface_id` **before** calling `signOffensiveRunRow` (the signer rejects a pre-set `row_mac` and signs last — offensive-row-mac.js:42-55). Tests mint rows the same way.

---

## 3. The record-time gate — `mcp/lib/claims.js`

**File:** `mcp/lib/claims.js`

**Location:** inside `assertExploitedClaimHasProof(claim, { existingClaims = [] } = {})` (line 883), **after** the `run_id` single-use loop (ends 962) and **before** the `maxDemonstratedRank` reduce (976). This block **replaces the stale comment at 964-975.** `claim` and `backedRows` are in scope; `ToolError` + `ERROR_CODES` are already imported. **No signature change. No change to `offensiveRunRowSatisfiesEvidence`** (exported at claims.js, reused by verification-round-store.js:254; must keep its signature).

Folds critique #2 must-fixes: row `surface_id` is **trimmed** before comparison (so a `" surface-A "` / case divergence fail-closes rather than depending on a coincidence), and the gate comment states the **integrity-not-correctness** boundary and the **axis** caveat.

```js
// Surface binding (issue #111): cross-finding severity-laundering gate.
// Each backed row is already content-bound to its ref (offensiveRunRowSatisfiesEvidence)
// and run_id-single-use (above) makes each row back at most ONE claim. ADD: the
// row's producer-stamped, MAC-covered surface_id must equal the claim's own
// finding surface, so a higher-severity row produced for surface B can never raise
// a claim for surface A. claim.surface_ids is set by record-candidate-claim.js:508
// ([finding.surface_id]) and arrives here NORMALIZED (trimmed/deduped/order-preserved
// by normalizeOptionalTextArray, claims.js:486) because normalizeCandidateClaim runs
// before this assert (appendCandidateClaim:1006). Precedent: assertNotStaticOnly-
// NativeHighSeverity reads claim.surface_ids at claims.js:837.
//
// INTEGRITY, NOT CORRECTNESS (same boundary as #108): the MAC proves the producer
// STAMPED this surface_id and this demonstrated_severity; it does NOT prove the
// producer ATTACKED that surface or that the impact tier is right. A trusted producer
// that attacks endpoint B but stamps surface_id=A (convergent mis-stamp), or stamps
// demonstrated_severity=critical on a low read (same-surface inflation), passes here.
// Those are PRODUCER obligations (AC-2 endpoint==surface, AC-3 server-derived severity)
// enforced at the producer PR, not in this string-binding gate. AXIS: this compares
// only the opaque surface_id; it does not assert surface kind/axis. A single web-only
// producer is planned; add an axis guard if a non-web offensive-row producer lands in
// a session that also carries smart_contract/code_module surfaces.
const claimSurfaceIds = Array.isArray(claim.surface_ids) ? claim.surface_ids : [];

// (1) STRICT single-surface. Rejects surface-set padding (surface_ids=[A,B] to satisfy
//     membership for a B-row) AND fail-closes the non-wave null-surface path
//     (record-candidate-claim.js:543 may pass no surface -> normalizes to length 0).
if (claimSurfaceIds.length !== 1) {
  throw new ToolError(
    ERROR_CODES.INVALID_ARGUMENTS,
    "exploited_safely claims that cite exploit_run proof must carry exactly one surface_id so each cited offensive-run row binds to a single finding/surface.",
    { code: "exploit_proof_claim_surface_ambiguous", surface_id_count: claimSurfaceIds.length },
  );
}
const claimSurfaceId = claimSurfaceIds[0]; // already trimmed by normalizeOptionalTextArray

for (const row of backedRows) {
  // (2) FAIL-CLOSED on a surfaceless row. row.surface_id is MAC-covered, so a producer
  //     that forgets to stamp it is a loud reject, not silent laundering. Trim before
  //     compare so the gate matches the trimmed claim surface; the producer MUST stamp
  //     the identical, same-case routed surface id (AC-1).
  const rowSurfaceId = typeof row.surface_id === "string" ? row.surface_id.trim() : "";
  if (rowSurfaceId === "") {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "exploited_safely claims require every cited offensive-runs row to carry a non-empty surface_id (the surface the safe exploit ran against).",
      { code: "exploit_proof_row_surface_missing", run_id: row.run_id || null },
    );
  }
  // (3) STRICT EQUALITY — the cross-finding severity-laundering gate.
  if (rowSurfaceId !== claimSurfaceId) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "exploited_safely claim cites an offensive-runs row produced for a different surface; a cited row's surface_id must equal the claim's surface (cross-finding severity laundering is rejected).",
      {
        code: "exploit_proof_row_surface_mismatch",
        run_id: row.run_id || null,
        row_surface_id: rowSurfaceId,
        claim_surface_id: claimSurfaceId,
      },
    );
  }
}
// existing maxDemonstratedRank reduce (claims.js:976-1002) continues unchanged.
```

**Interaction with the ceiling:** the surface loop runs over the **same `backedRows`** the ceiling reduces over (assembled once at claims.js:926-943, never mutated between). Placed **before** the reduce, the first out-of-set row hard-rejects the whole claim, so a critical surface-B row can never reach the `Math.max`. Placement-before also gives the required negative test a **deterministic** `details.code` (`exploit_proof_row_surface_mismatch`) even when `claim.severity === row.demonstrated_severity` (the case that would otherwise satisfy the ceiling).

**Two-rank-function note (critique #1 nice-to-have):** the record gate uses `exploitSeverityRank` (claims.js:755); the verify mirror (§5) uses `verifySeverityRank` (verification-round-store.js:76). Both fail-closed at rank 0; test 665-672 already asserts `verifySeverityRank > 0` for every enum. A future severity-enum edit must update both. The surface gate itself is severity-agnostic, so this asymmetry does not affect it — recorded only so the reviewer is not surprised.

**Fail-closed posture** mirrors the existing rank-0 precedent (claims.js:982-991): absent/empty/whitespace-only `claim.surface_ids` (which `normalizeStringArray` drops, validation.js:63-64) → length 0 → reject; absent/empty/whitespace `row.surface_id` → reject. Non-exploited claims early-return at claims.js:902 so the block never fires on plain/static claims.

---

## 4. How `claim.surface_ids` flows to the gate (confirm — no wiring change)

**Already wired, verified, normalized — no change needed.**
- `record-candidate-claim.js:507-508`: `claim.surface_ids = [finding.surface_id]` — `finding.surface_id` is the assignment-validated `args.surface_id` in wave mode (`validateAssignedWaveAgentSurface`, :536), or the provided non-wave `surface_id` (:543, may be null).
- `appendCandidateClaim(claimInput)` → `normalizeCandidateClaim` reads `input.surface_ids` via `normalizeOptionalTextArray` → `normalizeStringArray` (validation.js:51-69: **trims, dedups, preserves order, drops empties**), attaches `base.surface_ids` only when non-empty (claims.js:486/569).
- `assertExploitedClaimHasProof(claim, …)` runs **after** `normalizeCandidateClaim` (claims.js:1006 normalize → 1014 assert), so the gate sees the **trimmed/deduped/order-preserved** array, not raw input (critique #1 nice-to-have, confirmed).

Issue requirement (1) ("wire the claim's surface through") is **structurally already satisfied**; the gate only had to start reading it.

---

## 5. Verify-time mirror — `mcp/lib/verification-round-store.js`

**File:** `mcp/lib/verification-round-store.js`

The verify-time severity-rise guard (`clampResultSeveritiesInPlace`) recomputes `maxDemonstratedRank` using the **same surface-blind** `offensiveRunRowSatisfiesEvidence` (line 254) to gate `provenRise` (275-277). Patching only record-time leaves a cross-surface rise validatable at verify against a forged/corrupt freeze. We mirror the record gate here, binding **per-ref to the owning claim's single surface**.

**Change A — capture each exploit_run ref's owning-claim surface (folds critique #1 must-fix: compute INSIDE the per-claim loop).** The `byFinding` accumulation loop is `for (const claim of freeze.claims)` at **line 204**; the `exploitRunRefs` filter is at **215-222**; refs are pushed at **230**. Compute `claimSurfaceId` **inside that per-claim loop, before line 215**, so each tuple carries its OWN owning-claim's surface (a finding can accumulate refs from multiple claims, e.g. the no-overcap test 577 where the medium baseline and the low exploit confirm are separate claims). Hoisting it out of the loop would bind every ref to the last claim's surface and is **wrong**.

```js
// inside `for (const claim of freeze.claims)` (line 204), BEFORE line 215:
// Owning claim's single surface, mirroring the record gate's exactly-1 rule;
// null when the (possibly forged) freeze claim does not carry exactly one surface.
const claimSurfaceIds = Array.isArray(claim.surface_ids) ? claim.surface_ids : [];
const claimSurfaceId = claimSurfaceIds.length === 1 ? claimSurfaceIds[0] : null;
const exploitRunRefs = findingIds.length === 1
  ? refs
      .filter((ref) => (
        ref
        && ref.kind === "exploit_run"
        && typeof ref.run_id === "string"
        && !duplicateExploitRunIds.has(ref.run_id)
      ))
      .map((ref) => ({ ref, surfaceId: claimSurfaceId }))
  : [];
// ...
for (const entry of exploitRunRefs) current.exploitRunRefs.push(entry);
```

**Change B — require row surface equality before counting toward the ceiling (lines 251-260).** Destructure the tuple and add the surface predicate:

```js
for (const { ref, surfaceId } of base.exploitRunRefs) {
  for (const row of runRows) {
    if (
      offensiveRunRowSatisfiesEvidence(row, ref, domain, signingKey)
      && rowAttemptFreshForState(row, sessionState)
      && surfaceId !== null
      && typeof row.surface_id === "string"
      && row.surface_id.trim() === surfaceId
    ) {
      maxDemonstratedRank = Math.max(maxDemonstratedRank, verifySeverityRank(row.demonstrated_severity));
    }
  }
}
```

**Purely subtractive** — it only removes a row's eligibility, never adds a clamp on an unrelated baseline, so the no-overcap invariant (verification-round-store.js:288-297 and the "low row does not cap a separate higher baseline" test) holds. `surfaceId === null` (claim not exactly-1, e.g. a forged freeze with padded/absent surfaces) → row never counted → `provenRise` stays false → severity clamps to the frozen baseline. No new claims.js export needed; `claim.surface_ids` is read from the freeze's own claims. (`row.surface_id` is trimmed here too for symmetry with §3.)

---

## 6. Producer-compatibility contract (blocking acceptance criteria for the producer PR)

These are **blocking acceptance criteria** for the future signed-row producer (the `bob_auto_signup` second-identity IDOR oracle). The record gate fails *closed* on every divergence (safe direction), but the producer must satisfy these for the positive path to work and to close the convergent-mis-stamp and severity-inflation residuals (critique #2's two blocking gaps), which a string-binding gate cannot close.

**AC-1 (surface_id stamping, equal-comparability).** The producer MUST stamp `row.surface_id` with the **canonical routed surface id** — the same namespace/value as `finding.surface_id` (the `surface-routes.json` key resolved via `findRoutedSurface`, offensive-confirmer.js:278-282), post-trim, **same case**. The gate's equality is exact and case-sensitive (consistent with the route lookup and `validateAssignedWaveAgentSurface`). The wave-routed producer derives both strings from the same route key, but the gate must not depend on that coincidence — hence AC-1 is a HARD, tested requirement, and §3 trims defensively.

**AC-2 (surface == attacked endpoint; closes the convergent mis-stamp).** At row-write time the producer MUST re-resolve `row.surface_id → surface-routes.json` route and **assert `row.target`'s host+path belongs to that surface's recorded endpoints** (reuse `pathTemplateMatchesEndpoint`, offensive-confirmer.js:243, query-stripped via `.split("?")[0]` as the confirmer already does at :347/:374). It MUST refuse to sign a row whose `target` is outside the route. This makes `row.surface_id` structurally inseparable from what was actually attacked, so a producer that attacks endpoint B but stamps surface A is rejected **at production**. The gate's string equality alone cannot catch a *convergent* mis-stamp. **The producer PR MUST add a passing test** proving a row whose target is outside its surface_id's route cannot be signed.

**AC-3 (demonstrated_severity provenance; closes same-surface inflation).** The producer MUST reject any agent-supplied `severity` / `demonstrated_severity` / sensitivity hint (the existing denylist `assertNoForbiddenInputs` already rejects `severity`, `demonstrated_severity`, `finding_id`, `resource_id`, `id` at offensive-confirmer.js:120) and **derive `demonstrated_severity` server-side from the proven oracle outcome**, with a hard per-oracle-kind ceiling (a read-only `differential_response` cross-tenant READ demonstrates at most MEDIUM unless the producer itself classifies exposed-data sensitivity from the actual response bytes whose `stdout_hash` is MAC-covered — never an agent label). **The producer PR MUST add a passing test** that an agent-supplied severity/sensitivity hint cannot raise the signed row's `demonstrated_severity`.

**AC-4 (wave/surface-routed only — reconciled with the gate's actual permissiveness, critique #2 must-fix).** The producer MUST run against an assignment-validated, routed `surface_id` so the recorded claim always carries exactly one surface. **State plainly:** the *gate itself* accepts ANY exploited_safely claim that carries exactly one `surface_id`, including a **non-wave** claim whose `surface_id` is agent-controlled and route-unvalidated (the confirmer test's `recordExploitedClaim` uses exactly this non-wave-with-`surface_id` path, offensive-confirmer.test.js:185-204). Security still holds because the row's `surface_id` must *equal* the claim's and the row is route-anchored by the producer (AC-2) — but **only once AC-2 is enforced.** Until then, a non-wave claim surface is attacker-chosen on both sides modulo the MAC. AC-4 is therefore a producer obligation, not a gate guarantee.

**Enforcement bridge (so AC-2/AC-3 are not just prose) — partial rebuttal of critique #2's "in-gate endpoint check" fix:** I do **not** add endpoint-route resolution to the `claims.js` gate as the primary mechanism, for three reasons: (a) it would close only the surface-label hole while leaving the strictly-more-dangerous severity-label hole (AC-3) open — the gate provably cannot re-derive impact from response bytes, so shipping endpoint-binding alone advertises a completeness the gate does not have; (b) it couples `claims.js` to the routing layer and introduces a fail-open "skip when the surface is unrouted" branch whose safety rests on the *same* "producer only signs rows for routed surfaces" property it is trying not to trust; (c) the issue's required items are the string binding, and the repo discipline is "the producer MUST close #111," i.e. AC-2/AC-3 belong to the producer PR's own review gate. **Instead**, #111 lands committed, CI-visible `test.todo` placeholders in the producer's test file naming AC-2 and AC-3 (the producer PR converts them to passing tests), and the gate comment + §12 state the residual explicitly. **Operator option (§11):** if you prefer the convergent vector closed at record-time-now over architectural cleanliness, adopt the optional in-gate endpoint check described in §11 — with the honest caveat that it still does not close AC-3.

---

## 7. Test plan — rooted in `test/severity-rise-guard.test.js`

### 7a. Required new tests (add to `test/severity-rise-guard.test.js`)

All use already-imported symbols (`withTempHome`, `initWebSession`, `exploitRef`, `seedSignedOffensiveRow`, `appendFrozenFindingClaim`, `appendRawClaim`, `findingRef`, `assert`, `fs`, `claimsJsonlPath`). This file has **no** `assertInvalidArgumentsCode` helper (that one lives in `offensive-proof-contract.test.js:129`), so negative tests use the file's native `assert.throws(fn, predicate)` style (precedent at 737-745), asserting `err.code === "INVALID_ARGUMENTS" && err.details.code === "<code>"`, plus `assert.equal(fs.existsSync(claimsJsonlPath(domain)), false)` to prove `claims.jsonl` is untouched on reject. (Optionally add one small local predicate helper.)

1. **B-backs-A negative (the issue's required test).** `seedSignedOffensiveRow(domain, ref, { demonstrated_severity: "critical", surface_id: "surface-B" })`; `assert.throws(() => appendFrozenFindingClaim(domain, { severity: "critical", surfaceIds: ["surface-A"], evidenceRefs: [findingRef("F-1"), ref], exploitOutcome: { outcome: "exploited_safely", safe_oracle: { kind: "reflected_canary" } } }), <predicate exploit_proof_row_surface_mismatch>)`; assert `claims.jsonl` not created. (Equal severity on both sides isolates the surface check from the ceiling.)
2. **Positive control (single surface matches).** Same critical surface-B row; claim `surfaceIds: ["surface-B"]`, `severity: "critical"` → records; assert `claim.surface_ids` deep-equals `["surface-B"]`. Proves no over-blocking and the ceiling still applies.
3. **Multi-surface ambiguous reject.** `surfaceIds: ["surface-A", "surface-B"]` citing a backed row → `exploit_proof_claim_surface_ambiguous`.
4. **Missing row surface (fail-closed).** Seed row with `surface_id: ""` (MAC valid over the empty value); claim `surfaceIds: ["surface-A"]` → `exploit_proof_row_surface_missing`.
5. **Missing claim surface (fail-closed, non-wave null path).** Valid surface-stamped row; record with `surfaceIds: []` (normalizes away) → `exploit_proof_claim_surface_ambiguous`.
6. **Multi-row mixed-surface (red-team vector).** Seed a `low` row for `surface-A` (run-1) AND a `critical` row for `surface-B` (run-2); claim `surfaceIds: ["surface-A"]`, `severity: "critical"`, citing both → `exploit_proof_row_surface_mismatch`; `claims.jsonl` untouched. Sibling positive: both cited rows in-set (`surface-A`) records — proves the loop does not over-block legit multi-row claims.
7. **Surface matches but severity exceeds (critique #1 nice-to-have — pins surface/ceiling independence).** Seed a `low` row `surface_id: "surface-A"`; claim `surfaceIds: ["surface-A"]`, `severity: "critical"`, citing it → throws `exploit_proof_severity_exceeds_demonstrated` (surface passes, ceiling rejects). Guards against a future reorder of the two checks.
8. **Verify-time cross-surface rise denied (folds critique #1 must-fix: baseline pinned).** `appendRawClaim` (bypasses the record gate) a single-finding frozen exploited claim with `severity: "low"` (the **explicit frozen baseline**), `surface_ids: ["surface-A"]`, `exploit_outcome: exploited_safely`, citing a `critical` row stamped `surface_id: "surface-B"`; freeze; `enterVerifyV2` + `writeV2Round` brutalist asserting `severity: "critical"` + `confidence_reasons: ["exploit_replay_confirmed"]`; assert `persistedSeverity(domain) === "low"` (clamps to the pinned `low` baseline, because `surface-B !== "surface-A"` drops the row → `maxDemonstratedRank 0` → `provenRise false`). Contrast: with `surface-A` on the row, the critical rise is allowed — covered by edited test 288.
9. **Verify-time same-surface rise still allowed (critique #1 nice-to-have, explicit).** Add an explicit assertion (or a dedicated test) that with row `surface_id` matching the claim's single surface + `exploit_replay_confirmed` + `demonstrated_severity >= asserted`, the rise is permitted — documenting that Change B does not over-block legitimate rises (edited test 288/314 cover this via the helper default; make it explicit).

### 7b. Existing tests that MUST be edited in the same commit

**`test/severity-rise-guard.test.js`:**
- Add `const DEFAULT_SURFACE_ID = "surface-rise-default";` near the helpers.
- `offensiveRunRow` (114-133): add `surface_id: DEFAULT_SURFACE_ID,` **before** `...overrides` so seeded signed rows carry a MAC-covered surface (and remain overridable).
- `appendFrozenFindingClaim` (161-183): default `surfaceIds` **only for exploited_safely claims**, so plain/non-exploit claims stay byte-identical. Replace the `if (surfaceIds) claim.surface_ids = surfaceIds;` at line 181 with:
  ```js
  const effectiveSurfaceIds = surfaceIds
    || (exploitOutcome && exploitOutcome.outcome === "exploited_safely" ? [DEFAULT_SURFACE_ID] : null);
  if (effectiveSurfaceIds) claim.surface_ids = effectiveSurfaceIds;
  ```
  This makes every existing exploit-backed setup (288, 314, 343, 416, 442, 482, 528, 548, 577, 720…) carry `surface_ids` matching the row's default surface, so record passes and the verify-mirror counts the row. **Traced:** test 288/314 → same-surface rise still allowed (positive); 343 → F-1 kept low, F-2 clamped; 482 (multi-finding) → `findingIds.length===2` so refs dropped, F-2 clamped, unchanged; 528/548/720 → row dropped/ceiling holds, clamp unchanged; 464/474 (uniform) pass their own `surfaceIds` with **no** `exploitOutcome` → plain claim, byte-identical; 385 (duplicate-run-drop) uses `appendRawClaim` (no surface_ids) → verify mirror `claimSurfaceId === null` drops its rows → still clamps to `info`, unchanged.

**`test/offensive-proof-contract.test.js`:**
- Add `const DEFAULT_SURFACE_ID = "surface-proof-default";`.
- `buildOffensiveRunRow` (82-104): add `surface_id: DEFAULT_SURFACE_ID,` before `...overrides`.
- `exploitedClaim` (67-80): add `surface_ids: [DEFAULT_SURFACE_ID],` before `...overrides`.
- **Traced:** positive record tests (216, 264, 322, 334/341, 364, 408, 481…) pass (matching defaults); the round-trip test (216) asserts only `readBack.claim_hash === claim.claim_hash` (no hardcoded hash), so the new `surface_ids` field is fine. Content-binding negatives (234, 416, 427, 452, 495-565) throw `exploit_proof_unbacked_exploit_run_evidence`/`STATE_CONFLICT` **before** the surface loop; the run_id-consumed test (329) throws at the single-use loop (before the surface block); the missing-ref tests (225, 309) throw `exploit_proof_missing_exploit_run_evidence` (before surface); the ref-without-outcome tests (567/582) throw at the outcome gate (before surface); the severity-ceiling test (355) passes the surface check (both DEFAULT) then throws `exploit_proof_severity_exceeds_demonstrated` as before. Grep first to confirm no pre-existing `surface` references conflict.

**`test/offensive-confirmer.test.js`: NO edit required (verified).** The end-to-end test "a hand-written signed low row supports claim→freeze→verify (info→low)" (line 339) seeds the routed surface (345), seeds the signed row with `surface_id: surfaceId` (347 → 237), and records via `recordExploitedClaim(domain, surfaceId, ref)` (355 → tool sets `claim.surface_ids = [surfaceId]`) — **the same `surfaceId` on both sides** (`"surface:accounts"`), so the strict gate passes and the record→freeze→verify chain stays green. Optionally add an assertion documenting the surface match.

---

## 8. Verification commands

Run from the repo root:

```bash
node --check mcp/lib/claims.js
node --check mcp/lib/verification-round-store.js
node --check test/severity-rise-guard.test.js
node --check test/offensive-proof-contract.test.js

npm run check:syntax
node --test test/severity-rise-guard.test.js
node --test test/offensive-proof-contract.test.js
node --test test/offensive-confirmer.test.js
npm run test:mcp
npm test
```

Expected: all green. New negatives assert exact `details.code` values; positive controls assert successful records and the verify-time clamp/rise.

---

## 9. CI / drift gates & generators

- **`npm run test:mcp`** — covers the three edited/added test files green.
- **`npm run check:syntax`** — `node --check` on edited files.
- **`npm test`** — full aggregate passes.
- **`npm run test:prompts`** — stays green **with no regeneration.** #111 adds **no MCP tool, no tool-schema field, no role-bundle / authority change** (the new `row.surface_id` is read-only proof material, not a tool input; the `exploit_run` evidence-ref schema is unchanged). Therefore:
  - **`node scripts/generate-agent-tools.js`** — NOT needed.
  - **`node scripts/generate-hacker-bob-skill.js`** (+ kimi/codex generators) — NOT needed.
  - **`check:authority-inventory`** (`scripts/authority-inventory.js`, TOOL_REGISTRY-driven) — stays green untouched.
- **Drift tripwire:** if any generator or `check:authority-inventory` reports drift, a tool-input field has been added by accident — stop; #111 must remain a pure internal-validator change.
- **Stale-comment removal:** replace claims.js:964-975 with the enforcement comment (§3) when the check lands, so the codebase no longer advertises an unenforced binding pointing at #111 (critique #2 must-fix).

---

## 10. Risks

- **Test-fixture churn (medium-low).** ~4 helper edits across two files; the confirmer suite needs none. The explicit new negative/positive tests pin each error code so a future one-sided override (row or claim surface) cannot silently change which gate fires.
- **Two enforcement points must stay consistent (medium).** Record gate (§3) and verify mirror (§5) both encode exactly-1 + strict-equality. The §1 relax-path (membership) must update both together.
- **Over-block of legit cross-surface chains (low, accepted).** Strict single-surface forbids recording a multi-step chain spanning surfaces as one exploited_safely claim; record it on its impact surface. Relax-path documented (§1).
- **Non-wave/surfaceless exploited claims rejected (low, accepted).** Safe today (negative-only confirmer; wave/surface-routed producer). If a legit non-wave exploited path is introduced, revisit exactly-1.

---

## 11. Explicitly deferred (NOT in this PR)

- **The signed-row producer itself** (the `bob_auto_signup` IDOR oracle). #111 is the gate; the producer is the next PR and must satisfy §6 AC-1..AC-4 (with passing AC-2/AC-3 tests).
- **OPTIONAL in-gate endpoint↔surface re-resolution (critique #2 fix (a), electable).** If the operator wants the convergent mis-stamp closed at record-time-now: in §3, after `claimSurfaceId` is fixed, resolve `claimSurfaceId → surface-routes.json` via a **fail-closed** helper (the same store the confirmer reads via `findRoutedSurface`; reuse `pathTemplateMatchesEndpoint` query-stripped) and assert each backed `row.target`'s path matches a recorded endpoint of `route(claimSurfaceId)`. **Skip only when no route exists** for the surface (test fixtures with `DEFAULT_SURFACE_ID`, non-wave paths) — and note honestly that this fail-open skip rests on "the producer only signs rows for routed surfaces," and that it does **not** close AC-3 (severity correctness). Kept out of the recommended diff to avoid coupling `claims.js` to routing and the fail-open edge; the gate fails closed on a *divergent* surface label regardless, and AC-2 closes the *convergent* mis-stamp at the producer.
- **`demonstrated_severity` provenance / oracle-kind ceiling** (AC-3). Producer-side; the gate trusts the MAC-covered value's integrity, not its correctness.
- **`assertSnapshotMatchesFreeze` freeze-hash recompute** (verification-snapshot-contracts.js): it compares the recorded `freeze_hash` field rather than recomputing `hashDocumentExcluding` over `freeze.claims`. Recomputing would make the §5 verify mirror genuinely independent of the record gate rather than co-trusting the freeze (a content-tampered freeze with a preserved hash field would feed the mirror forged surfaces/refs). Same in-process-exec / audit-graded-write boundary as #108 — honestly deferrable; file as a follow-up.
- **Write-guard hardening for `claims.jsonl` + `claim-freeze.json`.** Verified: `claims.jsonl` is NOT in `AUDIT_GRADED_BASENAMES` (only `offensive-runs.jsonl` at paths.js:444 and `claim-freeze.json` at :434 are); `claims.jsonl` is MCP-owned but protected only by the default-deny branch, not by name in `session-write-guard.sh` `MCP_OWNED_EXACT`. Adding `claims.jsonl` (and `claim-freeze.json`) explicitly to `MCP_OWNED_EXACT` (and mirroring in `adapters/kimi/hooks/session-write-guard.sh`) is cheap defense-in-depth that makes "`appendCandidateClaim` is the sole minting path" enforced by name. **Split out of this PR into issue #113** (write-guard hook coverage: claim-ledger protection + bash-redirect-grammar gaps like no-space `>file` / `>&file` + Kimi-hook resync) to keep #111 scoped to the server-side gate — the write-guard is defense-in-depth that the offensive-sandbox PR ultimately owns and is NOT required for #111's contract.
- **Axis-compatibility guard.** The gate compares only the opaque `surface_id` string, not surface kind/axis. Out of scope for the single web-only planned producer; if a non-web offensive-row producer lands in a session that also carries `smart_contract`/`code_module` surfaces, add an axis guard (reject `exploit_run`/`exploited_safely` on those surfaces) at that time. Noted in the §3 gate comment.

---

## 12. Residual risk after this PR (honest)

- **In-process code-execution boundary (inherited from #108, NOT closed here).** A same-UID actor with arbitrary in-process code execution (`node -e`) can read the 0600 per-session signing key and mint a fully-valid signed row with any `surface_id`, defeating the equality check; the same capability lets it append directly to the (non-write-guarded) `claims.jsonl`. Absolute un-fakeability is deferred to the offensive-sandbox PR (privilege/container separation). This gate defends an agent confined to the MCP + guarded-Bash surface — the same boundary #108 stated.
- **Convergent producer mis-stamp (closed only by AC-2, in the producer PR).** Until AC-2 ships, a producer that attacks endpoint B but stamps `surface_id = A` (with the agent filing matching finding A) passes the gate's string equality. The gate is necessary-but-not-sufficient; AC-2 (or the §11 optional in-gate check) must ship with the producer.
- **Same-surface `demonstrated_severity` inflation (closed only by AC-3, in the producer PR).** A row stamped `critical` for a low-impact read on surface A passes both the surface check and the ceiling. AC-3 (server-derived severity + per-oracle-kind ceiling; the `assertNoForbiddenInputs` denylist already blocks agent-supplied severity) is required before the producer ships.
- **Cross-axis confusion (partial).** The strict gate does not assert axis/kind; out of scope for the single web-only producer. Add an axis guard when a second (non-web) producer lands (§11).

Net: this PR closes the **cross-finding severity-laundering** gap (issue #111) at record time within the documented threat boundary, mirrors it at verify, fails closed on every missing/mismatched-surface case, trims defensively, and is the un-bypassable structural floor the signed-row producer must build on — with the convergent-mis-stamp and severity-provenance residuals explicitly handed to the producer PR as blocking, *tested* acceptance criteria (AC-2/AC-3) rather than prose.

---

## Bottom line

**Build-ready? Yes — pure-validator scope, every claim source-verified, every critique disposition explicit.** All four files and both test suites were read; the gate placement (after run_id single-use 962, before the ceiling 976, replacing the stale 964-975 comment), the whole-row MAC auto-binding, the trimmed/normalized `claim.surface_ids` flow, the per-claim verify-mirror loop at line 204, the audit-graded list (`offensive-runs.jsonl` + `claim-freeze.json` yes, `claims.jsonl` no), and the confirmer's already-surface-matched E2E test were all confirmed against source. Critique must-fixes are folded (per-claim `claimSurfaceId` placement, pinned verify baseline, row `surface_id` trim, AC-4 reconciliation, stale-comment removal, surface-vs-ceiling independence test); critique #1's blocking gap is resolved by elevating strict-single to a **sign-off contract decision** with a documented membership relax-path; critique #2's two blocking gaps are resolved by reasoned partial-rebuttal — the gate stays a pure validator (integrity-not-correctness, the same boundary as #108) and the convergent-mis-stamp + severity-inflation holes are pushed to the producer PR as **tested** AC-2/AC-3, with an electable in-gate endpoint-check documented in §11 for operators who want the convergent vector closed at record-time-now.

**What to verify first, in order:** (1) the §3 block lands between line 962 and line 976 and the §5 `claimSurfaceId` is computed **inside** the `for (const claim of freeze.claims)` loop (a hoist is a silent correctness bug); (2) run `node --test test/offensive-proof-contract.test.js` and `test/offensive-confirmer.test.js` immediately after the two helper-default edits to confirm no positive record-path test regressed and no negative test changed which error code it throws; (3) get the operator's explicit sign-off on the strict-single-vs-membership contract decision (§1) before merge, since it is the one place this PR knowingly diverges from the issue's literal wording.

---

## 13. Reconciliation addendum (post-fill, 2026-06-15)

The two research lenses that were rate-limited in the main run (`surface_id-semantics`, `producer-it-gates`) were re-run and reconciled against this plan (run `wf_541cc7ea-c97`). **Verdict: the §3 record gate, §5 verify mirror, §1 contract decision, §2 schema, §4 wiring, and §7 gate tests stand unchanged — the #111 PR itself is build-ready as written.** The `surface_id-semantics` lens *corroborated* the red-team's inferences (opaque agent-authored label; trim + case-sensitive + exact-equality at every layer with no canonicalization; `claim.surface_ids` is always `[finding.surface_id]` so strict-single ≡ membership for all current producers; `surface_id → exactly-one-surface` uniqueness is genuinely enforced; MAC auto-binds the new field). The additions below are all confined to the **producer-contract (§6)** and **residuals (§11/§12)** — i.e. obligations on the *next* (producer) PR, not on #111.

### New blocking, *tested* producer ACs (fold into §6 before the producer PR opens)

- **AC-5 — attacker-provisioned identities (safety/policy, highest priority).** Both test identities **and** the differential target object id MUST be attacker-provisioned via `bob_auto_signup` + `bob_temp_email` — never an id/PII harvested from real traffic. Otherwise a "successful IDOR" row's `stdout_hash` MAC-binds **real victim bytes**, violating the operator hard rule (the `sec/CLAUDE.md` project rules) and the `feedback_no_pii_harvest_confirmation` memory. This is a *policy* obligation, not just a soundness one — the difference between a safe producer and a PII-harvesting one.
- **AC-6 — oracle soundness (three-way differential).** A row may be minted ONLY when: `B-as-A` content `==` `A-as-A` content, `!=` `B-as-B` content, **and** `anon-as-A` is challenged (401/403). A bare resource-shaped 200 is exactly the `synthetic_id_resource_shape_not_provable` false positive the negative-only confirmer (`offensive-confirmer.js:541-574`) was built to reject; without AC-6 the producer reintroduces the unsound positive PR #110 deliberately removed.

### Tightening of an existing AC

- **AC-3 → HARD MEDIUM ceiling.** As written, AC-3's "*unless* the producer classifies exposed-data sensitivity from the response bytes" is unsound for *this* oracle: the bytes are **attacker-owned synthetic objects**, so their field shape does not reflect a real victim. A read-only cross-tenant READ must cap at **MEDIUM**; PII-typed field shape is a structural note only, never a severity lift. (This is the one place a lens *changed* a producer-AC rather than confirming it.) AC-3's agent-supplied-severity half is **already enforced** by `assertNoForbiddenInputs` (`offensive-confirmer.js:119-125`), so AC-3 reduces to "add a server-side classifier with a hard ceiling," not "build new input filtering."

### New documentation residuals (fold into §12)

- **GAP A — intra-surface endpoint/host divergence (new).** One `surface_id` can aggregate many `surface.endpoints[]` across many `surface.hosts[]` (`offensive-confirmer.js:292-329`). AC-2 binds `row.target` to *some* endpoint/host of the surface, not to the claim's specific `finding.endpoint`, so on a coarse multi-endpoint surface the proof's target and the named finding endpoint can diverge and still pass. **Severity laundering — #111's actual target — stays CLOSED** (AC-3 derives severity from the attacked endpoint's bytes); the uncovered axis is **report endpoint/host integrity**, orthogonal to severity. Mitigation options: pin `row.target` to the claim's `finding.endpoint` within the surface, scope the first producer to single-endpoint surfaces, or accept + document.
- **GAP B — AC-2 anchor is agent-authored even in wave mode.** `surface.endpoints[]`/`hosts[]` are written via `bob_append_frontier_event`; only the `surface_id` *label* is assignment-validated, not the endpoint-list content. AC-2 proves label + endpoint-membership integrity, **not** "what really exists" — same in-process / agent-authored trust boundary as the §12 code-exec residual. Don't over-credit AC-2.
- **GAP E — `{id}`-must-be-final-segment coverage limit.** AC-2 inherits `normalizePathTemplate`'s rule (`offensive-confirmer.js:186-208`): the first producer can confirm only **direct** resource reads (`GET /accounts/{id}`), not sub-resource IDOR (`GET /accounts/{id}/txns`).
- **GAP F — exact-enum `demonstrated_severity` stamp (fail-closed footgun).** A ROW with an unrecognized `demonstrated_severity` does **not** throw (only the CLAIM severity throws at `claims.js:982`); it silently contributes rank 0 and floor-rejects any non-info claim. Producer must stamp an exact `SEVERITY_VALUES` member (`constants.js:7`); add a tested assertion.

**Bottom line of the reconciliation:** land #111 unchanged except the §12/§6 documentation residuals (GAP A/B); fold AC-5/AC-6 + the AC-3 tightening + GAP E/F into §6 **before** opening the producer PR. They are exactly the difference between a producer that is merely "un-laundered on the surface axis" and one that is also sound (AC-6), severity-honest (AC-3), and policy-safe (AC-5).
