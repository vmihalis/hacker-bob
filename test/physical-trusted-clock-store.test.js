"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  compareAndSetPhysicalMonotonicOwnerState,
  openProductionPhysicalMonotonicOwner,
  readPhysicalMonotonicOwnerState,
} = require("../mcp/lib/physical-monotonic-owner.js");
const {
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
} = require("../mcp/lib/physical-trusted-clock.js");
const {
  FIXED_SOURCE_BLOCKER,
  PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN,
  PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE,
  PHYSICAL_TRUSTED_CLOCK_TRUST_DOMAIN,
  assertProductionPhysicalTrustedClockPort,
  assertRestartDurablePhysicalTrustedClockPort,
  assertRestartDurablePhysicalTrustedClockSample,
  assertRestartDurablePhysicalTrustedClockValidityWindow,
  describeProductionPhysicalTrustedClockPort,
  normalizePhysicalTrustedClockAuthorityBundle,
  openProductionPhysicalTrustedClockPort,
  physicalClockTrustSigningMessage,
  sampleRestartDurablePhysicalTrustedClock,
} = require("../mcp/lib/physical-trusted-clock-store.js");
const { sessionNucleusFromState } = require("../mcp/lib/governance-contracts.js");
const { sessionDir } = require("../mcp/lib/paths.js");
const { normalizePhysicalScopeNucleusAxis } = require("../mcp/lib/physical-scope-axis.js");
const { buildInitialSessionState } = require("../mcp/lib/session-state-contracts.js");
const { writeSessionStateDocument } = require("../mcp/lib/session-state-store.js");
const {
  SANDBOX_AGENT_UID_ENV,
  SANDBOX_ISOLATION_ACK_ENV,
  SANDBOX_ISOLATION_ACK_TOKEN,
  SANDBOX_SIGNER_UID_ENV,
} = require("../mcp/lib/sandbox-isolation-attest.js");
const { hashCanonicalJson } = require("../mcp/lib/verification-contracts.js");

const CLOCK_CONTEXT = "hacker-bob/physical-trusted-clock-high-water/v1";

function digest(label) {
  return hashCanonicalJson({ label });
}

function iso(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function monotonicMs() {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

function installPhysicalSession(domain) {
  const physicalScope = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "physical_trusted_clock_store_fixture",
    policy_digest: digest(`policy:${domain}`),
    projection_version: 1,
    projection_digest: digest(`projection:${domain}`),
    provenance_digest: digest(`provenance:${domain}`),
    compatibility_digest: digest(`compatibility:${domain}`),
    transition_receipt_registry_digest: digest(`transition:${domain}`),
    authority_epoch: 1,
    revocation_generation: 0,
  });
  const directory = sessionDir(domain);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const state = buildInitialSessionState(domain, `https://${domain}`, {
    physicalScope,
    egressProfile: {
      name: "default",
      region: null,
      proxy_configured: false,
      egress_profile_identity_hash: null,
      egress_profile_identity_version: null,
      egress_profile_identity_source: {
        proxy_url_source: "none",
        proxy_env_var: null,
        proxy_url_redacted: null,
        resolved_proxy: null,
      },
    },
  });
  writeSessionStateDocument(domain, {}, state);
  const nucleus = sessionNucleusFromState(state);
  fs.writeFileSync(
    path.join(directory, "session-nucleus.json"),
    `${JSON.stringify(nucleus, null, 2)}\n`,
    { mode: 0o600 },
  );
  return nucleus;
}

function harness(t, suffix) {
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid == null || uid === 0) throw new Error("trusted-clock fixture requires a non-root uid");
  const prior = Object.fromEntries([
    ["HOME", process.env.HOME],
    [SANDBOX_ISOLATION_ACK_ENV, process.env[SANDBOX_ISOLATION_ACK_ENV]],
    [SANDBOX_SIGNER_UID_ENV, process.env[SANDBOX_SIGNER_UID_ENV]],
    [SANDBOX_AGENT_UID_ENV, process.env[SANDBOX_AGENT_UID_ENV]],
  ]);
  const home = fs.mkdtempSync(path.join(os.tmpdir(), `bob-clock-home-${suffix}-`));
  const ownerRoot = fs.mkdtempSync(path.join(os.tmpdir(), `bob-clock-owner-${suffix}-`));
  const authorityRoot = fs.mkdtempSync(path.join(os.tmpdir(), `bob-clock-authority-${suffix}-`));
  for (const directory of [home, ownerRoot, authorityRoot]) fs.chmodSync(directory, 0o700);
  process.env.HOME = home;
  process.env[SANDBOX_ISOLATION_ACK_ENV] = SANDBOX_ISOLATION_ACK_TOKEN;
  process.env[SANDBOX_SIGNER_UID_ENV] = String(uid);
  process.env[SANDBOX_AGENT_UID_ENV] = String(uid + 1);
  t.after(() => {
    for (const [name, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    for (const directory of [home, ownerRoot, authorityRoot]) {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
  return { authorityRoot, home, ownerRoot };
}

function signMapping(signer, payload) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    signer.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  return { ...basis, signed_mapping_digest: hashCanonicalJson(basis) };
}

function signTrust(root, payload) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockTrustSigningMessage(payloadDigest),
    root.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: PHYSICAL_TRUSTED_CLOCK_TRUST_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
    trust_root_public_key_spki_base64url: root.publicKey.export({
      type: "spki",
      format: "der",
    }).toString("base64url"),
  };
  return { ...basis, trust_statement_digest: hashCanonicalJson(basis) };
}

function authorityFixture(domain, nucleusHash) {
  const signer = crypto.generateKeyPairSync("ed25519");
  const root = crypto.generateKeyPairSync("ed25519");
  const clockId = "physical-clock:durable-store-fixture";
  const base = {
    domain,
    nucleusHash,
    signer,
    root,
    clockId,
    monotonicEpochId: digest("trusted-clock-boot-epoch-a"),
    referenceMonotonicMs: monotonicMs(),
    referenceUtcMs: Date.now(),
  };
  return base;
}

function buildBundle(fixture, overrides = {}) {
  const signer = overrides.signer || fixture.signer;
  const monotonicEpochId = overrides.monotonic_epoch_id || fixture.monotonicEpochId;
  const mappingGeneration = overrides.mapping_generation || 1;
  const trustRootEpoch = overrides.trust_root_epoch || 4;
  const authorityEpoch = overrides.authority_epoch || 7;
  const revocationGeneration = overrides.revocation_generation == null
    ? 2
    : overrides.revocation_generation;
  const referenceMonotonicMs = overrides.reference_monotonic_ms == null
    ? fixture.referenceMonotonicMs
    : overrides.reference_monotonic_ms;
  const referenceUtcMs = overrides.reference_utc_ms == null
    ? fixture.referenceUtcMs
    : overrides.reference_utc_ms;
  const validityStart = overrides.validity_start_ms == null
    ? referenceUtcMs - 60_000
    : overrides.validity_start_ms;
  const validityEnd = overrides.validity_end_ms == null
    ? referenceUtcMs + 10 * 60_000
    : overrides.validity_end_ms;
  const signerSpki = signer.publicKey.export({ type: "spki", format: "der" })
    .toString("base64url");
  const mapping = signMapping(signer, {
    version: 1,
    clock_id: fixture.clockId,
    monotonic_epoch_id: monotonicEpochId,
    mapping_generation: mappingGeneration,
    reference_monotonic_ms: referenceMonotonicMs,
    reference_utc: iso(referenceUtcMs),
    max_uncertainty_ms: overrides.max_uncertainty_ms == null
      ? 5
      : overrides.max_uncertainty_ms,
    not_before: iso(validityStart),
    expires_at: iso(validityEnd),
    trust_root_epoch: trustRootEpoch,
    authority_epoch: authorityEpoch,
    revocation_generation: revocationGeneration,
    signer_key_id: overrides.signer_key_id || "clock-key:durable-store-fixture",
    signer_public_key_digest: publicKeyDigest(signer.publicKey),
    ...(overrides.mapping_payload || {}),
  });
  const trust = signTrust(fixture.root, {
    version: 1,
    target_domain: fixture.domain,
    session_nucleus_hash: fixture.nucleusHash,
    trusted: overrides.trusted == null ? true : overrides.trusted,
    revoked: overrides.revoked == null ? false : overrides.revoked,
    clock_id: fixture.clockId,
    monotonic_epoch_id: mapping.payload.monotonic_epoch_id,
    current_mapping_generation: mapping.payload.mapping_generation,
    current_signed_mapping_digest: mapping.signed_mapping_digest,
    trust_root_epoch: mapping.payload.trust_root_epoch,
    authority_epoch: mapping.payload.authority_epoch,
    revocation_generation: mapping.payload.revocation_generation,
    signer_key_id: mapping.payload.signer_key_id,
    signer_public_key_digest: mapping.payload.signer_public_key_digest,
    signer_public_key_spki_base64url: signerSpki,
    trust_root_key_id: "clock-trust-root:durable-store-fixture",
    trust_root_public_key_digest: publicKeyDigest(fixture.root.publicKey),
    not_before: iso(validityStart),
    expires_at: iso(validityEnd),
    ...(overrides.trust_payload || {}),
  });
  const basis = {
    version: 1,
    domain: PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN,
    signed_mapping: mapping,
    signed_trust: trust,
  };
  return { ...basis, bundle_digest: hashCanonicalJson(basis) };
}

function writeBundle(root, bundle) {
  const filePath = path.join(root, PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE);
  fs.writeFileSync(filePath, `${JSON.stringify(bundle)}\n`, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

function openOwner(h, fixture) {
  return openProductionPhysicalMonotonicOwner({
    version: 1,
    target_domain: fixture.domain,
    session_nucleus_hash: fixture.nucleusHash,
    external_owner_root: h.ownerRoot,
    context_domain: CLOCK_CONTEXT,
  });
}

function openClock(h, fixture, owner) {
  return openProductionPhysicalTrustedClockPort({
    version: 1,
    target_domain: fixture.domain,
    session_nucleus_hash: fixture.nucleusHash,
    port_id: "durable_clock_fixture",
    clock_id: fixture.clockId,
    uncertainty_ceiling_ms: 50,
    authority_root: h.authorityRoot,
    monotonic_head_owner: owner,
  });
}

function setup(t, suffix) {
  const h = harness(t, suffix);
  const domain = `physical-trusted-clock-${suffix}.example.com`;
  const nucleus = installPhysicalSession(domain);
  const fixture = authorityFixture(domain, nucleus.nucleus_hash);
  const bundle = buildBundle(fixture);
  writeBundle(h.authorityRoot, bundle);
  const owner = openOwner(h, fixture);
  const clock = openClock(h, fixture, owner);
  return { bundle, clock, fixture, h, owner };
}

test("fixed trusted-clock adapter durably samples, cold-reopens in a new process, and stays non-authorizing",
  { concurrency: false }, (t) => {
    const setupResult = setup(t, "cold-restart");
    const { clock, fixture, h, owner } = setupResult;
    assert.equal(assertRestartDurablePhysicalTrustedClockPort(clock), clock);
    assert.equal(clock.production_ready, false);
    assert.equal(clock.production_blocker, FIXED_SOURCE_BLOCKER);
    assert.equal(clock.exact_signed_time_ready, true);
    assert.throws(
      () => assertProductionPhysicalTrustedClockPort(clock),
      /native_restart_stable_monotonic_epoch/u,
    );
    assert.throws(() => JSON.stringify(clock), /process-local capabilities/u);
    assert.deepEqual(
      Object.keys(clock).filter((key) => /read_|resolve_|callback/u.test(key)),
      [],
    );

    const first = sampleRestartDurablePhysicalTrustedClock(clock);
    assert.equal(assertRestartDurablePhysicalTrustedClockSample(first), first);
    assert.equal(first.durable_observation_sequence, 1);
    assert.equal(first.production_ready, false);
    assert.equal(first.exact_signed_time, true);
    assertRestartDurablePhysicalTrustedClockValidityWindow(first, {
      not_before: first.trusted_utc_earliest,
      expires_at: iso(Date.parse(first.trusted_utc_latest) + 1),
    });
    assert.throws(
      () => readPhysicalMonotonicOwnerState(owner),
      /exclusively claimed/u,
    );
    assert.throws(
      () => compareAndSetPhysicalMonotonicOwnerState(owner, null, {
        monotonic_revision: 1,
        monotonic_position: 0,
        monotonic_value_digest: digest("forged-clock-state"),
      }),
      /exclusively claimed/u,
    );

    const reopenedOwner = openOwner(h, fixture);
    const reopenedClock = openClock(h, fixture, reopenedOwner);
    const second = sampleRestartDurablePhysicalTrustedClock(reopenedClock);
    assert.equal(second.durable_observation_sequence, 2);
    assert.ok(second.monotonic_ms >= first.monotonic_ms);
    assert.ok(Date.parse(second.trusted_utc_earliest) >= Date.parse(first.trusted_utc_earliest));

    const ownerModule = require.resolve("../mcp/lib/physical-monotonic-owner.js");
    const storeModule = require.resolve("../mcp/lib/physical-trusted-clock-store.js");
    const childScript = `
      const { openProductionPhysicalMonotonicOwner } = require(${JSON.stringify(ownerModule)});
      const { openProductionPhysicalTrustedClockPort, sampleRestartDurablePhysicalTrustedClock } = require(${JSON.stringify(storeModule)});
      const config = JSON.parse(process.argv[1]);
      const ownerPort = openProductionPhysicalMonotonicOwner(config.owner);
      const clockPort = openProductionPhysicalTrustedClockPort({ ...config.clock, monotonic_head_owner: ownerPort });
      process.stdout.write(JSON.stringify(sampleRestartDurablePhysicalTrustedClock(clockPort)));
    `;
    const childConfig = {
      owner: {
        version: 1,
        target_domain: fixture.domain,
        session_nucleus_hash: fixture.nucleusHash,
        external_owner_root: h.ownerRoot,
        context_domain: CLOCK_CONTEXT,
      },
      clock: {
        version: 1,
        target_domain: fixture.domain,
        session_nucleus_hash: fixture.nucleusHash,
        port_id: "durable_clock_fixture",
        clock_id: fixture.clockId,
        uncertainty_ceiling_ms: 50,
        authority_root: h.authorityRoot,
      },
    };
    const childSample = JSON.parse(childProcess.execFileSync(
      process.execPath,
      ["-e", childScript, JSON.stringify(childConfig)],
      { encoding: "utf8", env: { ...process.env } },
    ));
    assert.equal(childSample.durable_observation_sequence, 3);
    assert.equal(childSample.restart_durable, true);
    assert.equal(childSample.production_ready, false);

    const afterChild = sampleRestartDurablePhysicalTrustedClock(clock);
    assert.equal(afterChild.durable_observation_sequence, 4);
    const description = describeProductionPhysicalTrustedClockPort(clock);
    assert.equal(description.durable_observation_count, 4);
    assert.equal(description.production_ready, false);
    assert.equal(description.production_blocker, FIXED_SOURCE_BLOCKER);
  });

test("durable trusted-clock high water rejects mapping rollback, same-generation forks, and epoch reuse",
  { concurrency: false }, async (t) => {
    const setupResult = setup(t, "adversarial-history");
    const { clock, fixture, h } = setupResult;
    const first = sampleRestartDurablePhysicalTrustedClock(clock);

    await t.test("same-generation mapping fork", () => {
      const fork = buildBundle(fixture, {
        reference_utc_ms: fixture.referenceUtcMs + 1,
      });
      writeBundle(h.authorityRoot, fork);
      assert.throws(
        () => sampleRestartDurablePhysicalTrustedClock(clock),
        /physical_trusted_clock_mapping_fork/u,
      );
      writeBundle(h.authorityRoot, setupResult.bundle);
    });

    const epochB = digest("trusted-clock-boot-epoch-b");
    const transitionMono = monotonicMs();
    const transitionUtc = Math.max(Date.now(), Date.parse(first.trusted_utc_latest) + 10);
    const epochTransition = buildBundle(fixture, {
      monotonic_epoch_id: epochB,
      mapping_generation: 2,
      authority_epoch: 8,
      reference_monotonic_ms: transitionMono,
      reference_utc_ms: transitionUtc,
    });
    writeBundle(h.authorityRoot, epochTransition);
    const second = sampleRestartDurablePhysicalTrustedClock(clock);
    assert.equal(second.monotonic_epoch_id, epochB);
    assert.equal(second.mapping_generation, 2);

    await t.test("mapping generation rollback after an epoch transition", () => {
      const rollback = buildBundle(fixture, {
        monotonic_epoch_id: epochB,
        mapping_generation: 1,
        authority_epoch: 8,
        reference_monotonic_ms: transitionMono,
        reference_utc_ms: transitionUtc,
      });
      writeBundle(h.authorityRoot, rollback);
      assert.throws(
        () => sampleRestartDurablePhysicalTrustedClock(clock),
        /mapping_generation moved backwards/u,
      );
      writeBundle(h.authorityRoot, epochTransition);
    });

    await t.test("retired monotonic epoch cannot be reused", () => {
      const reused = buildBundle(fixture, {
        monotonic_epoch_id: fixture.monotonicEpochId,
        mapping_generation: 3,
        authority_epoch: 9,
        reference_monotonic_ms: monotonicMs(),
        reference_utc_ms: Math.max(Date.now(), Date.parse(second.trusted_utc_latest) + 10),
      });
      writeBundle(h.authorityRoot, reused);
      assert.throws(
        () => sampleRestartDurablePhysicalTrustedClock(clock),
        /reuses a monotonic epoch|reused a retired monotonic epoch/u,
      );
      writeBundle(h.authorityRoot, epochTransition);
    });

    await t.test("epoch change requires an authority epoch advance", () => {
      const epochC = buildBundle(fixture, {
        monotonic_epoch_id: digest("trusted-clock-boot-epoch-c"),
        mapping_generation: 3,
        authority_epoch: 8,
        reference_monotonic_ms: monotonicMs(),
        reference_utc_ms: Math.max(Date.now(), Date.parse(second.trusted_utc_latest) + 10),
      });
      writeBundle(h.authorityRoot, epochC);
      assert.throws(
        () => sampleRestartDurablePhysicalTrustedClock(clock),
        /epoch transition lacks a fresh signed authority generation/u,
      );
      writeBundle(h.authorityRoot, epochTransition);
    });
  });

test("authority signatures, exact current trust, revocation, roots, and input schemas fail closed",
  { concurrency: false }, async (t) => {
    const setupResult = setup(t, "authority-closure");
    const { clock, fixture, h, owner } = setupResult;

    await t.test("revoked exact-current trust cannot be sampled", () => {
      writeBundle(h.authorityRoot, buildBundle(fixture, { revoked: true }));
      assert.throws(
        () => sampleRestartDurablePhysicalTrustedClock(clock),
        /no longer trusted or current/u,
      );
      writeBundle(h.authorityRoot, setupResult.bundle);
    });

    await t.test("trust-root signature tamper is rejected before high-water mutation", () => {
      const tampered = structuredClone(setupResult.bundle);
      tampered.signed_trust.signature = `$${tampered.signed_trust.signature.slice(1)}`;
      tampered.signed_trust.trust_statement_digest = hashCanonicalJson({
        version: tampered.signed_trust.version,
        domain: tampered.signed_trust.domain,
        payload: tampered.signed_trust.payload,
        payload_digest: tampered.signed_trust.payload_digest,
        scheme: tampered.signed_trust.scheme,
        signature: tampered.signed_trust.signature,
        trust_root_public_key_spki_base64url:
          tampered.signed_trust.trust_root_public_key_spki_base64url,
      });
      tampered.bundle_digest = hashCanonicalJson({
        version: tampered.version,
        domain: tampered.domain,
        signed_mapping: tampered.signed_mapping,
        signed_trust: tampered.signed_trust,
      });
      writeBundle(h.authorityRoot, tampered);
      assert.throws(
        () => sampleRestartDurablePhysicalTrustedClock(clock),
        /canonical Ed25519 base64url/u,
      );
      writeBundle(h.authorityRoot, setupResult.bundle);
      assert.equal(sampleRestartDurablePhysicalTrustedClock(clock).durable_observation_sequence, 1);
    });

    await t.test("mapping and trust must name one exact current document", () => {
      const drift = structuredClone(setupResult.bundle);
      drift.signed_trust.payload.current_signed_mapping_digest = digest("other-mapping");
      const resigned = signTrust(fixture.root, drift.signed_trust.payload);
      const basis = {
        version: 1,
        domain: PHYSICAL_TRUSTED_CLOCK_AUTHORITY_BUNDLE_DOMAIN,
        signed_mapping: drift.signed_mapping,
        signed_trust: resigned,
      };
      const mismatched = { ...basis, bundle_digest: hashCanonicalJson(basis) };
      assert.throws(
        () => normalizePhysicalTrustedClockAuthorityBundle(mismatched),
        /does not name the exact current mapping/u,
      );
    });

    await t.test("public APIs reject callback and readiness injection", () => {
      assert.throws(
        () => openProductionPhysicalTrustedClockPort({
          version: 1,
          target_domain: fixture.domain,
          session_nucleus_hash: fixture.nucleusHash,
          port_id: "durable_clock_fixture",
          clock_id: fixture.clockId,
          uncertainty_ceiling_ms: 50,
          authority_root: h.authorityRoot,
          monotonic_head_owner: owner,
          read_monotonic_ms() { return 0; },
        }),
        /fields are not exact/u,
      );
      assert.throws(
        () => openProductionPhysicalTrustedClockPort({
          version: 1,
          target_domain: fixture.domain,
          session_nucleus_hash: fixture.nucleusHash,
          port_id: "durable_clock_fixture",
          clock_id: fixture.clockId,
          uncertainty_ceiling_ms: 50,
          authority_root: h.authorityRoot,
          monotonic_head_owner: owner,
          production_ready: true,
        }),
        /fields are not exact/u,
      );
      assert.throws(
        () => assertRestartDurablePhysicalTrustedClockPort({ ...clock }),
        /privately branded/u,
      );
    });

    await t.test("authority root replacement and nested owner custody are rejected", () => {
      const bundlePath = path.join(h.authorityRoot, PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE);
      const backup = `${h.authorityRoot}.backup`;
      fs.renameSync(h.authorityRoot, backup);
      fs.mkdirSync(h.authorityRoot, { mode: 0o700 });
      fs.copyFileSync(path.join(backup, PHYSICAL_TRUSTED_CLOCK_AUTHORITY_FILE), bundlePath);
      fs.chmodSync(bundlePath, 0o600);
      try {
        assert.throws(
          () => sampleRestartDurablePhysicalTrustedClock(clock),
          /authority root identity changed/u,
        );
      } finally {
        fs.rmSync(h.authorityRoot, { recursive: true, force: true });
        fs.renameSync(backup, h.authorityRoot);
      }

      const nestedAuthority = path.join(h.ownerRoot, "nested-clock-authority");
      fs.mkdirSync(nestedAuthority, { mode: 0o700 });
      writeBundle(nestedAuthority, setupResult.bundle);
      const otherRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-clock-nested-owner-"));
      fs.chmodSync(otherRoot, 0o700);
      t.after(() => fs.rmSync(otherRoot, { recursive: true, force: true }));
      const freshOwner = openProductionPhysicalMonotonicOwner({
        version: 1,
        target_domain: fixture.domain,
        session_nucleus_hash: fixture.nucleusHash,
        external_owner_root: otherRoot,
        context_domain: CLOCK_CONTEXT,
      });
      // Nest the authority below this fresh owner rather than the already
      // claimed owner so the disjoint-root rejection is the first failure.
      const nestedFresh = path.join(otherRoot, "authority");
      fs.mkdirSync(nestedFresh, { mode: 0o700 });
      writeBundle(nestedFresh, setupResult.bundle);
      assert.throws(
        () => openProductionPhysicalTrustedClockPort({
          version: 1,
          target_domain: fixture.domain,
          session_nucleus_hash: fixture.nucleusHash,
          port_id: "nested_clock_fixture",
          clock_id: fixture.clockId,
          uncertainty_ceiling_ms: 50,
          authority_root: nestedFresh,
          monotonic_head_owner: freshOwner,
        }),
        /roots must be disjoint/u,
      );
    });
  });
