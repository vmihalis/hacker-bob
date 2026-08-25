# Core cycle residual

## Result

The N4 analysis started from a 62-module giant strongly connected component: 51
core modules and the 11-module physical arc recorded by the analyzer. A single
behavior-preserving ownership inversion reduced the giant SCC to 37 modules.

`ledger-integrity/index.js` had 18 incoming edges and one outgoing edge: it
re-exported the verdict-level sandbox gate. That gate is a policy consumer of
claims, verification, differential summaries, and invariant summaries; it is not
ledger custody or row-MAC machinery. The gate now lives at
`mcp/core/verdict-sandbox-gate.js`, and its three production consumers import it
directly. The ledger facade consequently has no edge back into claim-lifecycle
policy and is a pure sink. The implementation moved intact apart from relative
specifier adjustment. Dedicated sandbox-gate tests cover the same exported
functions and same mutable module-export seam used by the test signer helper.

The live analyzer after that inversion reports:

- giant SCC: **37** (down from 62)
- next SCC: **2**
- physical modules in the giant SCC: **0**
- ledger-integrity modules in the giant SCC: **0**

No file below `mcp/domains/physical/` was changed. Physical remains a separate
frozen-contract arc; its restored core-to-physical seams are inventoried in
`physical-severance-seam.md` and are not candidates for this node.

## Residual members

The 37-module residual, grouped by responsibility, is:

- claims (4): `candidate-claim-recorder.js`, `claim-freeze.js`,
  `claim-projections.js`, `claims.js`
- verification (5): `verification.js`, `verification-round-store.js`,
  `verification-finding-id-adapter.js`, `verification-replay-safety.js`,
  `verification-snapshot-contracts.js`
- evidence/grading/report core (6): `evidence.js`, `grade-verdict-store.js`,
  `invariant-runner.js`, `proof-bundle.js`, `report-finalize.js`,
  `verdict-sandbox-gate.js`
- capability (4): `capability-pack-derivation.js` and the evidence, grade, and
  proof adapters
- session (4): `agent-run-completion.js`, `assignment-brief.js`,
  `lifecycle-gates.js`, `session-state.js`
- differential (4): `index.js`, `composition-live-verifier.js`,
  `cross-stack-differential-verifier.js`, `finding-differential-verifier.js`
- frontier (2): `coverage-closure.js`, `reachability-ceiling.js`
- waves (3): `scheduler-preconditions.js`, `wave-brief-derivation.js`,
  `wave-handoff-store.js`
- telemetry (2): `pipeline-analytics.js`, `pipeline-session-artifacts.js`
- belief (3): `cell-scheduler-priority.js`, `model.js`,
  `scheduler-priority.js`

## Why the residual is mutual

These are bidirectional call relationships, not directory-shape accidents:

| Relationship | Forward call | Return call | Why the return is load-bearing |
|---|---|---|---|
| claims and freeze | `claim-freeze.js:29` reads normalized claims | `claims.js:1148` reads the current freeze | A freeze is built from claims, while later claim adjudication must use the exact frozen baseline. |
| verification and evidence | `verification.js:77` resolves evidence | `evidence.js:411` resolves verification | Verification adjudicates evidence packs; evidence completeness is checked against the authoritative verification result. |
| verification round and claims | `verification-round-store.js:54,59` reads freeze and claims | `claims.js:1298,1306,1482` reads differential/invariant verification summaries | Severity is reclamped to the frozen claim while claim reportability is derived from executed verification outcomes. |
| claims and differential | `claims.js:1298,1482` reads differential summaries | `cross-stack-differential-verifier.js:115,621` and `finding-differential-verifier.js:47` resolve claim-bound executed rows | A claim is graded from a verified flip, and the flip is valid only when rebound to that claim and its signed evidence. |
| claims and invariant verification | `claims.js:1306` reads invariant verdicts | `invariant-runner.js` reads claims/freeze when binding a run to a finding | Neither side can authoritatively classify reportability without the other's executed identity. |
| core grade/evidence and capability | `grade-verdict-store.js:262,504` and `evidence.js:603,884` apply capability projections | capability grade/evidence adapters read claim freeze and reachability | Capability-specific grading is an adapter over the same claim, evidence, and severity authorities, not an independent leaf calculation. |
| capability and frontier | `coverage-closure.js:50` uses capability fanout derivation | capability evidence/grade adapters import `reachability-ceiling.js` | Coverage uses the authoritative pack fanout, while pack grading uses the authoritative reachability ceiling. Splitting either duplicates a gate definition. |
| session and frontier | `lifecycle-gates.js:28,115` consumes reachability; session state consumes frontier projections | `coverage-closure.js:49,84` consumes session-owned cell-floor derivation | Lifecycle transitions gate on frontier truth, while frontier closure is calculated from the session's dispatched obligations. |
| session and waves | `agent-run-completion.js:13` consumes handoffs; `lifecycle-gates.js:458+` consumes scheduler preconditions | `wave-handoff-store.js:193` completes agent runs; scheduler preconditions consume assignment/session state | A handoff closes an agent run and run completion settles its handoff. Changing this to optional callbacks changes failure and persistence ordering. |
| claims and waves | `claims.js:1857` reads handoff assignments | `wave-handoff-store.js:26` records candidate claims | Handoff completeness is part of claim depth, while the handoff is the producer boundary for the candidate claim. |
| telemetry and lifecycle | scheduler preconditions call `pipeline-session-artifacts.js:168`; telemetry's import edges point into evidence, claim recording, and verification at `:55,69,74` | Lifecycle producers persist canonical session state, which `readSessionArtifactSummary()` reads back; this is a data read, not a return import edge. | The shared artifact reader supplies a server-derived lifecycle projection used by both analytics and a scheduler gate. Relocating it would fork `readSessionArtifactSummary()` or change gating behavior. |
| belief and capability/waves | `capability-pack-derivation.js:770` derives the score map inside the pure fanout planner; `assignment-brief.js` is the impure producer that assembles and passes its belief inputs | All rank producers are members of the 37-module residual, so there is no external producer toward which to invert the dependency. | Priority is deterministic dispatch input. Moving the ranker would either duplicate the score-map derivation or pull I/O into the pure planner, risking changed ordering and derived pack bytes. |

## Inversions deliberately not taken

The post-ledger topology no longer has the original simple leafward cuts. The
remaining candidate edges were reviewed in the required order and left intact:

1. **Differential.** Its return edges are strict MAC-verified re-resolution of
   claim, freeze, offensive-run, and invariant-run authorities. Supplying these
   through an optional port would change direct-call defaults; copying them into
   differential would fork security-sensitive verification logic.
2. **Frontier.** Coverage closure calls the exact session cell-floor derivation
   and capability hard cap, while reachability is consumed by capability and
   grading. Moving either calculation to an importer creates two definitions of
   an authoritative gate.
3. **Waves.** Handoff storage and agent-run completion call one another across a
   persistence boundary, and scheduler preconditions consume the session's
   assignment derivation. Callback injection would alter module initialization,
   exception timing, or write ordering.
4. **Telemetry.** The two residual modules build authoritative pipeline session
   artifacts used by scheduler preconditions. They read evidence, verification,
   and claim-recording state. The apparent return is persisted-state data flow,
   not an import edge; relocating the shared reader would fork
   `readSessionArtifactSummary()`, while treating those reads as optional
   telemetry would be a behavior change.
5. **Belief.** Every producer of the dispatch rank is already inside the residual:
   `assignment-brief.js` assembles the caller-owned inputs, and
   `capability-pack-derivation.js:770` derives the score map inside the pure fanout
   planner. Moving that calculation across the boundary would duplicate the rank
   definition or introduce I/O into the pure planner, either of which can change
   ordering and derived pack bytes.

Those cuts are therefore classified as essential under N4's rule: if an
inversion is not provably behavior-preserving, skip it rather than force a lower
SCC count. The residual is the mutual claim lifecycle—claims, verification,
evidence, capability, session, and the server-derived projections that enforce
their transitions. It is recorded as architecture, not hidden as an unargued
allowance.
