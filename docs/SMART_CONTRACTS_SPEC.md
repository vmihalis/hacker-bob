# Smart Contract Surface Spec

This document defines `bob-spec.yaml`, the normalized program spec Bob uses to
evaluate smart-contract bounties. It maps each major bounty platform's rules into a
single shape so the anti-stop rule, evaluator brief, verifier, and report-writer
can reason about findings the same way regardless of platform.

The spec is read at session init and consumed by:
- Surface-discovery SC ingestion (writes `bob-spec.yaml` from a platform page + extends).
- Evaluator brief (`mcp/lib/assignment-brief.js`) — surfaces trust assumptions and
  bypass conditions so evaluators know which "admin-only" claims are still
  reportable.
- Anti-stop rule (`prompts/roles/evaluator-evm.md` etc., `.claude/rules/evaluating.md`)
  — references `program.severity_system.admin_rule.exceptions` to decide
  whether a role-gated finding still needs an impact hypothesis.
- Verifier and report-writer — uses `severity_system.tiers` and platform-shaped
  payout/severity mapping.

## Top-level structure

```yaml
program: { ... }            # platform metadata + severity system
assets: [ ... ]             # in-scope contracts, multi-chain
trust_assumptions: { ... }  # roles + externals + bypass conditions
known_issues: [ ... ]       # ingested from program text (excluded by program)
out_of_scope_classes: [...] # platform-defined excluded bug classes
invariants: [ ... ]         # mostly Bob-extracted, drive PoC design
audit_index: [ ... ]        # Bob-built audit-fix map
```

## `program`

```yaml
program:
  platform: immunefi | sherlock | code4rena | cantina | custom
  source_url: https://immunefi.com/bug-bounty/sky/
  severity_system:
    id: immunefi-v2.3 | sherlock | code4rena | cantina | custom
    tiers: [critical, high, medium, low]   # platform default
    impact_axis: only | impact_x_likelihood
    admin_rule:
      treatment: out_of_scope | low_severity_max | trusted_unless_restricted
                | privilege_escalation_valid | resilience_dependent
      exceptions: [ <enum> ]               # see "Admin rule encoding" below
    poc_required: true | { hm_only: true, with_rep_under: 80 }
  payouts:
    critical: { min: 150000, max: 10000000, formula: "10% of funds" }
    high: { max: 100000 }
    medium: { flat: 5000 }
    low: { flat: 1000 }
```

`platform` is informative; `severity_system.id` is the load-bearing field for
verifier and reporter. `admin_rule` drives the anti-stop logic.

## `assets`

```yaml
assets:
  - chain: ethereum
    chain_id: 1
    address: "0x..."
    name: ALMController
    role_in_protocol: controller | bridge | oracle | module | vault | hook
                    | router | psm | adapter | governor
    contract_type: proxy | implementation | library | router
    deployed_block: 12345
    audit_links: [ "https://github.com/.../audit.pdf" ]
```

`role_in_protocol` is a free taxonomy used for ranking; surface-discovery should populate
it from program text and audit context. `contract_type` is structural.

Multi-chain protocols list one entry per (chain, address). Cross-chain
relationships (e.g. a foreign controller and its mainnet counterpart) are
captured in `trust_assumptions.trusted_externals`.

## `trust_assumptions`

This is the section the anti-stop rule reads most heavily.

```yaml
trust_assumptions:
  trusted_roles:
    - role: ward                          # role name as it appears on-chain
      contracts: [ all ] | [ "0x..." ]    # which contracts this role applies to
      stated_by: program | inferred       # program text or Bob-derived
      bypass_conditions:                  # Bob-extended; drives anti-stop
        - admin_eoa_compromise
        - governance_proposal_bypass
        - signature_forgery
        - delegated_role_drift
        - role_renouncement_bug
        - upgrade_path_takeover
        - multisig_threshold_break
  trusted_externals:
    - protocol: chainlink
      role: price_oracle
      address: "0x..."                    # if pinned
      bypass_conditions:
        - staleness
        - manipulation
        - sequencer_outage
        - reorg_replay
    - protocol: layerzero
      role: bridge_messenger
      bypass_conditions:
        - dvn_compromise
        - executor_collusion
        - replay
        - chain_id_confusion
```

`bypass_conditions` is the heart of the anti-stop rule. When a evaluator wants to
declare a surface complete because "function is admin-only", the rule requires
them to enumerate at least one bypass condition from this list and either
attempt a PoC or set `surface_status: partial` with a documented missing
harness.

The condition vocabulary is open; surface-discovery and evaluators can extend it. A short
list of commonly applicable conditions for EVM surfaces:

- `admin_eoa_compromise` — single private key holds the role
- `governance_proposal_bypass` — propose a malicious upgrade through governance
- `signature_forgery` — replay or forge a permit/EIP-712 signed authorization
- `delegated_role_drift` — role was granted then forgotten
- `role_renouncement_bug` — role logic allows unintended renounce/grant flows
- `upgrade_path_takeover` — UUPS/transparent proxy upgrade race
- `multisig_threshold_break` — threshold lower than declared
- `staleness` — oracle/price/state cache returns outdated value
- `manipulation` — TWAP / pool-price manipulation
- `sequencer_outage` — L2 sequencer down, forced inclusion path bug
- `reorg_replay` — reorg replays a state transition
- `dvn_compromise` — LayerZero DVN compromised or one DVN sufficient
- `executor_collusion` — executor + DVN collude
- `replay` — cross-chain message replayed on a different chain
- `chain_id_confusion` — chain ID not bound into a signed payload

## `known_issues`

```yaml
known_issues:
  - id: ki-01
    text: "MCD_ETH balance discrepancies"
    source: program-page
    affects: [ "0x..." ]                  # optional asset filter
```

Known issues are program-declared exclusions. Evaluators MUST NOT submit findings
that match these. Surface-discovery ingests them verbatim from the program page.

## `out_of_scope_classes`

```yaml
out_of_scope_classes:
  - gas_optimization
  - zero_address_check
  - reckless_admin
  - ai_generated
  - approval_race
  - dust_loss
  - non_standard_erc20            # platform-conditional (Sherlock)
  - sequencer_downtime_assumption # Sherlock-specific
  - chainlink_staleness_only      # Sherlock-specific
```

The platform-default exclusion list. Evaluators shortcut findings that match
these without recording them.

## `invariants`

```yaml
invariants:
  - id: inv-01
    statement: "PSM.totalAssets() monotonic except via withdraw"
    source: docs | audit-comment | code-comment | bob-derived
    surface_ids: [ mainnet-alm-controller-proxy, foreign-controller-cctp-psm3 ]
    expected_break_classes: [ donation_round, precision_loss, accounting_drift ]
    poc_hint: "donate raw token, observe totalAssets() drop"
```

Invariants are evaluator prompts as data. The evaluator brief surfaces them and the
evaluator is expected to write at least one Foundry test that asserts each
invariant before declaring a surface complete.

## `audit_index`

```yaml
audit_index:
  - audit:
      firm: ChainSecurity
      date: 2024-Q3
      scope: ALM Controller
      url: "https://github.com/.../audit.pdf"
      commit_at_audit: "abc123"
    issues:
      - id: L-04
        title: "Stale module allowlist"
        severity_at_audit: low
        fix_commit: "def456"
        status: confirmed_fixed | partially_fixed | unverified
        bob_check: "verify allowlist update path is monotonic post-fix"
        related_invariants: [ inv-03 ]
```

The `bob_check` field is what flips an audit from "trust this is fixed" to
"verify the fix in code, then attempt a bypass that the audit didn't cover".
The anti-stop rule references `audit_index[].issues[].bob_check`.

`status` tracking lets the verifier round flag findings that re-introduce a
previously-fixed issue.

## Platform mapping

| Field | Immunefi v2.3 | Sherlock | Code4rena | Cantina |
|---|---|---|---|---|
| `severity_system.tiers` | C/H/M/L | H/M | H/M/QA | H/M/L/Info |
| `severity_system.impact_axis` | only | only (loss thresholds) | only | impact × likelihood |
| `severity_system.poc_required` | true | true | true | `{hm_only: true, with_rep_under: 80}` |
| `severity_system.admin_rule.treatment` | `out_of_scope` | `trusted_unless_restricted` | `privilege_escalation_valid` | `resilience_dependent` |
| `severity_system.admin_rule.exceptions` | `additional_modifications_required` | `program_states_restriction_and_bypass`, `admin_unknowing_harm`, `role_open_to_anyone` | `privilege_escalation_path` | `protocol_designed_for_resilience` |

### Admin rule encoding (drives anti-stop)

Each platform's admin rule maps to an `exceptions` list. The anti-stop rule
reads this list and asks the evaluator to attempt at least one applicable
exception before allowing `surface_status: complete`.

**Immunefi v2.3** — admin-required attacks are out of scope unless the
impact proof also requires "additional modifications". The evaluator must articulate
what the additional modification is (e.g. signature forgery, governance bypass,
upgrade-path takeover) before declaring the surface complete.

**Sherlock** — admins are trusted unless: (a) the program README explicitly
states a restriction the bug bypasses, (b) the admin causes harm unknowingly,
or (c) the role is accessible without permission. Evaluator must check program
text for stated restrictions and enumerate unknowing-harm scenarios.

**Code4rena** — privilege escalation is valid up to Medium. Reckless admin
mistakes are QA-only. Evaluator focuses on escalation paths to a privileged role
rather than admin-acts-badly scenarios.

**Cantina** — admin-gated bugs are at most Low, **unless the protocol was
designed to be resilient against such actions**. This is the most permissive:
the evaluator must read program docs/architecture for resilience claims and treat
any breach of those claims as in-scope.

## Bob extensions (what the platforms don't capture)

These fields exist in `bob-spec.yaml` but are not provided by any platform's
spec format. Surface-discovery and evaluators fill them.

- `trust_assumptions.trusted_roles[].bypass_conditions` — platforms list
  trusted roles, never the bypass model.
- `trust_assumptions.trusted_externals[].bypass_conditions` — same.
- `invariants` — no platform requires a program to declare these.
- `audit_index` — programs link to audits but never map issues → fix commits
  → current status. Bob builds this index from audit PDFs and repo history.
- `assets[].role_in_protocol` and `assets[].contract_type` — programs list
  addresses without structural roles.

## Ingestion contract

Surface-discovery SC writes `bob-spec.yaml` in three passes:

1. **Platform scrape** — pull `program.platform`, `source_url`,
   `severity_system.id`, `assets[]`, `known_issues[]`, `audit_links` from the
   bounty page (Immunefi/Sherlock/C4/Cantina-specific scrape).
2. **Source enrichment** — pull verified source from
   Etherscan/Sourcify/Blockscout for each asset, extract `contract_type`,
   `role_in_protocol`, on-chain role tables, and dependency edges into
   `trust_assumptions.trusted_externals`.
3. **Bob extension** — read each linked audit PDF and source comments to
   populate `invariants`, `audit_index`, and `trust_assumptions[*].bypass_conditions`.

Pass 1 is mechanical. Pass 2 needs the EVM read tools from Phase 1
(`bob_evm_fetch_source`, `bob_evm_role_table`, `bob_evm_dependency_graph`).
Pass 3 needs `bob_audit_fetch` and `bob_invariant_extract` (Phase 1).

For Phase 0, surface-discovery writes a partial `bob-spec.yaml` (Pass 1 only). Passes 2-3
fill in dynamically as evaluators request context, or as a surface-discovery Pass 2/3 expansion
when Phase 1 tools land.

## Severity tier mapping

For cross-platform reporting and verifier severity calibration, Bob normalizes
findings to a four-tier internal scale and translates to the program's
platform on report:

| Bob tier | Immunefi v2.3 | Sherlock | Code4rena | Cantina |
|---|---|---|---|---|
| critical | Critical | High | High | High |
| high | High | High | High | High or Medium |
| medium | Medium | Medium | Medium | Medium |
| low | Low | (invalid) | QA | Low or Informational |

Sherlock's loss thresholds (>1% AND >$10 for High; >0.01% AND >$10 for Medium)
gate whether a Bob-internal `high` finding is reportable on Sherlock at all.
The verifier records Bob-internal severity and the platform-specific tier
side-by-side.

## Pipeline integration: phase gates, chain attempts, evidence packs, egress

Beyond `bob-spec.yaml` and the per-family evaluator / verifier / chain / reporter
prompts, SC findings flow through four shared mechanisms introduced in main:

### 1. Lifecycle gates (`mcp/lib/lifecycle-gates.js`)

The orchestrator's `bob_advance_session(to_state)` enforces gates between
lifecycle states. The transitions that matter for SC claims:

- **OPEN_FRONTIER → CLAIM_FREEZE.** Blocks if `pending_wave` is set or any
  HIGH/CRITICAL surface is unexplored. SC surfaces with `surface_status:
  partial` and at least one `bypass_attempts[]` entry are marked explored by
  `apply-wave-merge`, satisfying the gate. Operators with persistently blocked
  harness runs may set an operator override, but the standard path is to fix
  the toolchain and re-run. Chain attempts (one terminal
  `bob_write_chain_attempt` record per pivot — `confirmed`, `denied`,
  `blocked`, or `not_applicable`) are validated as part of the freeze
  prerequisites; see `prompts/roles/chain.md` for the SC pivot conventions.
- **CLAIM_FREEZE → VERIFY.** Requires a `ClaimFreeze` artifact with at least
  one `CandidateClaim` in scope. VerificationResult records are written
  against the frozen payload, not the live claim ledger.
- **VERIFY → GRADE.** Blocks if any final-reportable claim (medium severity
  or higher) lacks a valid evidence pack. The evidence-agent owns this; SC
  claims produce evidence packs via the family runners (see below).

### 2. Chain attempts × SC pivots

The chain-builder (`prompts/roles/chain.md`) writes one terminal chain attempt
per tested pivot via `bob_write_chain_attempt`. For SC pivots specifically,
the `proof_reference` field cites the verifier's `match_test` (per
`sc_evidence.match_test`) or a family fetch read (e.g., `bob_evm_role_table`
showing the granted role, `bob_sui_fetch_object` showing the transferred
owner) — never a free-text claim.

Cross-family chains (e.g., `subdomain_takeover -> frontend_wallet_drain`)
record one chain attempt per pivot edge. The web-side proof anchors on a
`bob_http_scan` request ID from `bob_read_http_audit`; the SC-side
proof anchors on `sc_evidence`.

### 3. Evidence packs × SC findings

The evidence-agent (`prompts/roles/evidence.md` source, `.claude/agents/
evidence-agent.md` artifact) runs after final verification when reportables
exist. It dispatches by `claim.surface_type`:

- **`web` (or null legacy):** replays via `bob_http_scan` with
  `egress_profile`, samples request/response shape (≤10 representative
  samples), redacts secrets/PII.
- **`smart_contract`:** re-runs the family runner against a FRESH chain
  reference (no `fork_block` pin), captures the test stdout excerpt, and
  builds the pack with a family-specific `sample_type`:

| chain_family | runner | sample_type | trust-map reads |
|---|---|---|---|
| evm | bob_foundry_run | evm_foundry_run | bob_evm_role_table / bob_evm_storage_read / bob_evm_call |
| svm | bob_anchor_run | svm_anchor_run | bob_svm_fetch_program / bob_svm_fetch_account |
| aptos | bob_aptos_run | aptos_move_test | bob_aptos_fetch_resource / bob_aptos_fetch_module |
| sui | bob_sui_run | sui_move_test | bob_sui_fetch_object / bob_sui_fetch_package |
| substrate | bob_substrate_run | substrate_ink_test | bob_substrate_fetch_storage / bob_substrate_fetch_runtime |
| cosmwasm | bob_cosmwasm_run | cosmwasm_cw_multi_test | bob_cosmwasm_fetch_contract / bob_cosmwasm_smart_query |

`representative_samples[]` for SC findings carry `runner`, `harness_path`,
`match_test`, `fork_block_used`, `test_stdout_excerpt` (≤1000 chars, the
failing assertion plus 2-3 lines of context), and `state_delta_summary`. The
`replay_summary` anchors the verifier's "verified at block N on chain X"
reasoning so the grader and reporter can quote it.

If the runner returns a tooling-blocker reason (`*_not_in_path`,
`*_dependency_missing`, `move_compile_failed`, `cargo_compile_failed`,
`rpc_unreachable`), the evidence pack still gets written but with the
verifier's earlier reasoning text in `representative_samples[]` — the gate
checks pack EXISTENCE, not pack quality. The verifier owns reportability.

### 4. Direct SC egress policy

`bob_http_scan` honors the operator's `egress_profile` for HTTP traffic
to the target. SC RPC clients and fork runners use a separate direct-only
policy because chain RPC/REST endpoints are operator-curated infrastructure,
not first-party target web traffic.

Default SC egress policy:

- accepted transport: direct HTTPS only
- accepted endpoint sources: shipped public ladders, explicit `endpoints` /
  `fork_urls`, and `BOB_<FAMILY>_RPCS_<NETWORK>` env overrides
- blocked by default: `http:`, localhost, private/link-local/internal host
  literals, and public hostnames whose DNS answers resolve to private or
  link-local addresses
- unsupported by default: private/localnet RPC; no per-family elevation policy
  exists yet
- unsupported by default: corporate proxy routing through `egress_profile`
- recorded evidence: runners return redacted `fork_attempts[]` and
  `rpc_policy_rejections[]`; read tools return redacted `endpoint_used`
  values and redact query credentials in errors
- timeout evidence: DNS preflight is bounded at 3s per candidate endpoint
  before the family-specific read or runner timeout budget applies
- DNS limitation: the preflight rejects private/link-local answers observed
  before the read or runner starts; it is not DNS pinning and does not make
  external CLIs immune to DNS rebinding or resolver divergence

Per-family matrix:

| family | direct endpoint kind | default timeout budget | default localnet/private behavior |
|---|---|---:|---|
| EVM | JSON-RPC HTTPS | DNS 3s per candidate; reads 10s per endpoint; Foundry 60s, max 300s | no localnet chain_id; private/fork URLs blocked |
| SVM | JSON-RPC HTTPS | DNS 3s per candidate; reads 10s per endpoint; Anchor 90s, max 600s | private/fork URLs blocked |
| Aptos | REST HTTPS with `/v1` base | DNS 3s per candidate; reads 10s per endpoint; Move runner 90s, max 600s | private/fork URLs blocked |
| Sui | JSON-RPC HTTPS | DNS 3s per candidate; reads 10s per endpoint; Move runner 90s, max 600s | `localnet` RPC returns no endpoints; local-only tests may run without fork RPC |
| Substrate | JSON-RPC HTTPS | DNS 3s per candidate; reads 10s per endpoint; cargo runner 90s, max 600s | `localnet` RPC returns no endpoints; local-only tests may run without fork RPC |
| CosmWasm | REST/LCD HTTPS | DNS 3s per candidate; reads 10s per endpoint; cargo runner 90s, max 600s | `localnet` RPC returns no endpoints; local-only tests may run without fork RPC |

When SC findings have an off-chain web side (e.g., a leaked API key that
controls oracle pricing on-chain), the off-chain HTTP step still flows
through `bob_http_scan` and honors the egress profile. The SC-side
RPC/REST reads stay under the direct HTTPS policy above.
