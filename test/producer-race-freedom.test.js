"use strict";

// Recon-producer race freedom. The producer-floor planner proposes a derived
// producer only once its input clause holds, so a consumer never co-runs with a
// writer that produces its inputs. The default JOIN clause is all-of: a
// multi-input synthesizer (web_assembly's eight kinds) is ready ONLY when every
// consumed kind exists, so it never fires a partial, permanent synthesis on its
// first input. A producer may opt into an any-of clause (sc_address_expander,
// bootstrapped by the chain_address_set seed alone). With only the root seed
// present, just the root host-family producer is ready; every derived producer
// waits in the gap set — carrying the full list of artifact kinds it still needs
// — until its clause is satisfied. The plan never drops a not-ready producer; it
// ranks it into gaps[] with its missing inputs. The bare sc_address_expander is
// suppressed entirely once address-keyed instances exist (WAW-free).

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  planProducerFloor,
  isProducerFloorAtFixpoint,
} = require("../mcp/lib/tools/materialize-producer-floor.js");
const { PRODUCER_PACKS, isProducerReady } = require("../mcp/lib/producer-packs.js");

function readyIds(plan) {
  return plan.ready.map((pack) => pack.producer_id).sort();
}

function gapFor(plan, producerId) {
  return plan.gaps.find((gap) => gap.producer_id === producerId);
}

test("with only the root seed, only the root producer is ready and every derived producer waits for its writer", () => {
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["target"],
  });

  assert.deepEqual(readyIds(plan), ["web_host_family"],
    "the only ready producer under the root seed alone is the root host-family producer");

  for (const derived of ["web_urls", "web_nuclei", "web_js_jwt", "web_assembly"]) {
    assert.equal(readyIds(plan).includes(derived), false,
      `${derived} must not be ready before any input it consumes exists`);
    assert.ok(gapFor(plan, derived),
      `${derived} must be reported in the gap set, never dropped`);
  }
});

test("the url and nuclei producers wait for the live-host artifacts, then both become ready together", () => {
  const rootPlan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["target"],
  });
  for (const derived of ["web_urls", "web_nuclei"]) {
    assert.equal(readyIds(rootPlan).includes(derived), false,
      `${derived} is not ready under the root seed alone`);
    assert.deepEqual(gapFor(rootPlan, derived).missing_input_types, ["live_hosts", "family_live"],
      `${derived} reports both live-host inputs as missing`);
  }

  const withLiveHosts = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(["web_host_family"]),
    availableArtifactKinds: ["target", "live_hosts", "family_live", "subdomains"],
  });
  assert.equal(readyIds(withLiveHosts).includes("web_urls"), true,
    "the url producer is ready once the live-host artifacts exist");
  assert.equal(readyIds(withLiveHosts).includes("web_nuclei"), true,
    "the nuclei producer is ready once the live-host artifacts exist — the safe parallel pair");
});

test("the js-and-jwt producer waits for the aggregated url artifact, then flips to ready once it exists", () => {
  const rootPlan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["target"],
  });
  assert.equal(readyIds(rootPlan).includes("web_js_jwt"), false,
    "the js-and-jwt producer is not ready under the root seed alone");
  assert.deepEqual(gapFor(rootPlan, "web_js_jwt").missing_input_types, ["all_urls"],
    "it is gated specifically on the aggregated url artifact");

  const withUrls = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(["web_host_family"]),
    availableArtifactKinds: ["target", "live_hosts", "family_live", "all_urls"],
  });
  assert.equal(readyIds(withUrls).includes("web_js_jwt"), true,
    "it flips to ready once the aggregated url artifact exists");
  assert.equal(gapFor(withUrls, "web_js_jwt"), undefined,
    "and no longer appears in the gap set once it is ready");
});

test("the assembly JOIN producer is NOT ready until ALL eight upstream artifact kinds exist (no partial synthesis)", () => {
  const eight = [
    "live_hosts", "family_live", "subdomains", "all_urls",
    "nuclei_results", "js_endpoints", "js_secrets", "jwt_candidates",
  ];
  // The four upstream producers are terminal so only the assembly producer's
  // readiness is in question; its inputs are supplied directly via available kinds.
  const upstreamTerminal = new Set(["web_host_family", "web_urls", "web_nuclei", "web_js_jwt"]);

  // Every strict subset (exactly one of the eight missing) keeps the assembly
  // producer OUT of the ready set and REPORTS the missing input — never a partial,
  // permanent synthesis on its first input.
  for (let i = 0; i < eight.length; i += 1) {
    const missingKind = eight[i];
    const partial = ["target", ...eight.filter((_, j) => j !== i)];
    const plan = planProducerFloor({
      packs: PRODUCER_PACKS,
      producerRunSet: upstreamTerminal,
      availableArtifactKinds: partial,
    });
    assert.equal(readyIds(plan).includes("web_assembly"), false,
      `web_assembly must not run with only seven of eight inputs (missing ${missingKind})`);
    const gap = gapFor(plan, "web_assembly");
    assert.ok(gap && gap.missing_input_types.includes(missingKind),
      `the one missing input (${missingKind}) is reported, never dropped`);
  }

  // With all eight present the JOIN clause finally holds and the assembly producer
  // flips to ready exactly once — and leaves the gap set.
  const full = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: upstreamTerminal,
    availableArtifactKinds: ["target", ...eight],
  });
  assert.equal(readyIds(full).includes("web_assembly"), true,
    "web_assembly is ready exactly when all eight inputs exist");
  assert.equal(gapFor(full, "web_assembly"), undefined,
    "and no longer appears in the gap set once every input is present");
});

test("no bare sc_address_expander is emitted when address-keyed instances exist (WAW-free suppression)", () => {
  const scSurfaces = [{
    chain_family: "evm",
    chain_id: "1",
    address: "0xABCdef0000000000000000000000000000000001",
    depth: 1,
    provenance: "seed",
  }];
  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(["sc_chain_root"]),
    // BOTH consumed kinds present, so under the any-of predicate the bare expander
    // WOULD be ready — only the instance-suppression keeps it out.
    availableArtifactKinds: ["chain_address_set", "sc_surface"],
    scSurfaces,
    caps: {},
  });
  assert.equal(readyIds(plan).includes("sc_address_expander"), false,
    "the bare sc_address_expander (no chain identity) is suppressed when instances exist");
  assert.equal(gapFor(plan, "sc_address_expander"), undefined,
    "and it is not reported as a gap — the per-instance recursion covers it");
  assert.equal(plan.sc_expander_instances.length, 1,
    "exactly the address-keyed instance is proposed");
  assert.equal(
    plan.sc_expander_instances[0].producer_key,
    "sc_address_expander:evm:1:0xabcdef0000000000000000000000000000000001",
    "the per-instance key embeds the lowercased on-chain identity",
  );
});

test("caps are CLAMPED, not merely defaulted: negative/zero/huge overrides never widen or freeze the sc-expander fan-out", () => {
  // Four seed contracts on the same chain: enough to prove the per-pass fan-out
  // cap actually binds. Each is a depth-1 seed (bound + provenanced) so provenance
  // never suppresses them — only the caps decide how many instances mint.
  const scSurfaces = [1, 2, 3, 4].map((n) => ({
    chain_family: "evm",
    chain_id: "1",
    address: `0x${String(n).repeat(40)}`,
    depth: 1,
    provenance: "seed",
  }));
  const base = {
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(["sc_chain_root"]),
    availableArtifactKinds: ["chain_address_set", "sc_surface"],
    scSurfaces,
  };

  // A negative per-pass cap must NOT pass through as a negative bound (which would
  // defer everything and freeze the floor). Clamped up to the floor of 1 ⇒ exactly
  // one instance mints and the other three are reported as a linked-address gap.
  const negative = planProducerFloor({ ...base, caps: { seed_producer_per_pass_cap: -5 } });
  assert.equal(negative.sc_expander_instances.length, 1,
    "a negative per-pass cap clamps to the floor of 1, never a negative (freeze) bound");
  assert.ok(
    negative.sc_recursion_gaps.some((gap) => gap.kind === "sc_linked_address_capped"),
    "the three deferred contracts are reported by name, never silently dropped",
  );

  // A zero depth cap disables recursion entirely (proposedDepth >= 2 > 0), and is
  // an intentional operator setting — every source is depth-capped, none freezes.
  const zeroDepth = planProducerFloor({ ...base, caps: { linked_contract_depth: 0 } });
  assert.equal(zeroDepth.sc_expander_instances.length, 0,
    "a zero depth cap is honored (recursion disabled), not treated as garbage");
  assert.equal(
    zeroDepth.sc_recursion_gaps.filter((gap) => gap.kind === "linked_contract_depth_capped").length,
    4,
    "all four depth-capped contracts are reported by name",
  );

  // An absurdly-large per-pass cap must be clamped to the CLAMP_CEILING, not
  // trusted verbatim; with only four sources the clamp is not the binding limit,
  // so all four mint — proving the huge value did not corrupt the bound.
  const huge = planProducerFloor({ ...base, caps: { seed_producer_per_pass_cap: 10 ** 12 } });
  assert.equal(huge.sc_expander_instances.length, 4,
    "an absurdly-large per-pass cap is clamped but still admits every in-range source");
});

test("a self-produced kind is NOT a readiness trigger: the minted sc_surface alone never makes the sc-expander ready (structural, no ready-forever)", () => {
  const pack = PRODUCER_PACKS.sc_address_expander;
  const consumes = pack.trigger.consumes; // ["chain_address_set", "sc_surface"]
  const produces = pack.produces; // ["sc_surface"] — the self-edge output
  const mode = pack.trigger.input_mode; // "any"

  // The finding: once a single sc_surface has EVER been minted it is permanently
  // available, so under a naive any-of the expander would be READY FOREVER. The
  // self-produced sc_surface must NOT satisfy readiness on its own.
  assert.equal(isProducerReady(consumes, ["sc_surface"], mode, produces), false,
    "the self-produced sc_surface alone must NOT make the expander ready (no ready-forever fixpoint)");

  // The EXTERNAL chain_address_set seed is the real bootstrap trigger.
  assert.equal(isProducerReady(consumes, ["chain_address_set"], mode, produces), true,
    "the external chain_address_set seed bootstraps the expander");

  // Both present is still ready (the bootstrap seed carries it) — but sc_surface is
  // never the reason, so removing it can never leave the expander perpetually ready.
  assert.equal(isProducerReady(consumes, ["chain_address_set", "sc_surface"], mode, produces), true,
    "the external seed still bootstraps the expander when both kinds are present");

  // A producer whose ONLY declared input is its own output has no external trigger.
  assert.equal(isProducerReady(["sc_surface"], ["sc_surface"], "any", ["sc_surface"]), false,
    "a pure self-edge (no external input) is never ready — it cannot bootstrap itself");
});

test("once every sc source is expanded (its per-instance key terminal) the floor proposes ZERO instances and the bare expander is not ready — a structural fixpoint", () => {
  // One seed contract whose per-instance expander has ALREADY run: its
  // identity-keyed producer_key is terminal in the run ledger, so the recursion
  // has no un-expanded source left.
  const scSurfaces = [{
    chain_family: "evm",
    chain_id: "1",
    address: "0xABCdef0000000000000000000000000000000001",
    depth: 1,
    provenance: "seed",
  }];
  const expandedKey = "sc_address_expander:evm:1:0xabcdef0000000000000000000000000000000001";
  // The chain root is terminal (bootstrap done) and every source is expanded.
  const runSet = new Set(["sc_chain_root", expandedKey]);

  const plan = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: runSet,
    // BOTH consumed kinds are present — pre-fix the any-of predicate would keep the
    // bare expander perpetually ready off the self-produced sc_surface.
    availableArtifactKinds: ["chain_address_set", "sc_surface"],
    scSurfaces,
    caps: {},
  });

  assert.equal(plan.sc_expander_instances.length, 0,
    "every source is expanded ⇒ the per-instance recursion proposes zero instances (structural dedup)");
  assert.equal(readyIds(plan).includes("sc_address_expander"), false,
    "the bare expander is not proposed once the recursion is exhausted — readiness is not perpetually-true-but-empty");
  assert.equal(isProducerFloorAtFixpoint(plan), true,
    "no ready producer and no pending instance ⇒ the producer floor is at a true structural fixpoint");
});

test("with no live SC surfaces the bare expander follows the any-of predicate, never suppressed", () => {
  // The chain_address_set seed alone bootstraps the depth-1 root expansion: the
  // any-of input mode makes the bare expander ready without waiting for the
  // sc_surface it is itself responsible for producing.
  const root = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["chain_address_set"],
    scSurfaces: [],
  });
  assert.equal(readyIds(root).includes("sc_address_expander"), true,
    "the chain_address_set seed alone makes the bare root expander ready (any-of bootstrap)");
  // With NEITHER consumed kind present it is not ready and is reported as a gap.
  const none = planProducerFloor({
    packs: PRODUCER_PACKS,
    producerRunSet: new Set(),
    availableArtifactKinds: ["target"],
    scSurfaces: [],
  });
  assert.equal(readyIds(none).includes("sc_address_expander"), false,
    "with no consumed kind available the any-of expander is not ready");
  assert.ok(gapFor(none, "sc_address_expander"),
    "and the not-ready expander is reported, never dropped");
});
