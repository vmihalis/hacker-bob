"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const {
  MAX_MAPPING_LIFETIME_MS,
  MAX_UNCERTAINTY_MS,
  TRUSTED_CLOCK_MAPPING_DOMAIN,
  assertPhysicalTrustedClockPort,
  assertPhysicalTrustedClockSample,
  assertPhysicalTrustedClockTimestampNonFuture,
  assertPhysicalTrustedClockValidityWindow,
  createPhysicalTrustedClockPort,
  normalizeSignedPhysicalClockMapping,
  physicalClockMappingSigningMessage,
  publicKeyDigest,
  samplePhysicalTrustedClock,
} = require("../mcp/domains/physical/physical-trusted-clock.js");
const {
  hashCanonicalJson,
} = require("../mcp/core/verification/verification-contracts.js");

function digest(label) {
  return hashCanonicalJson({ label });
}

function timestamp(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function mappingPayload(keyPair, overrides = {}) {
  return {
    version: 1,
    clock_id: "physical-clock:trusted-clock-test-1",
    monotonic_epoch_id: digest("trusted-clock-monotonic-epoch-1"),
    mapping_generation: 1,
    reference_monotonic_ms: 1_000,
    reference_utc: "2026-07-18T12:00:00.000Z",
    max_uncertainty_ms: 25,
    not_before: "2026-07-18T11:55:00.000Z",
    expires_at: "2026-07-18T12:10:00.000Z",
    trust_root_epoch: 4,
    authority_epoch: 7,
    revocation_generation: 2,
    signer_key_id: "clock-key:trusted-clock-test-1",
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
    ...overrides,
  };
}

function signMapping(keyPair, payload) {
  const payloadDigest = hashCanonicalJson(payload);
  const signature = crypto.sign(
    null,
    physicalClockMappingSigningMessage(payloadDigest),
    keyPair.privateKey,
  ).toString("base64url");
  const basis = {
    version: 1,
    domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
    payload,
    payload_digest: payloadDigest,
    scheme: "ed25519",
    signature,
  };
  return {
    ...basis,
    signed_mapping_digest: hashCanonicalJson(basis),
  };
}

function currentTrust(mapping, keyPair, overrides = {}) {
  const payload = mapping.payload;
  return {
    version: 1,
    trusted: true,
    revoked: false,
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    current_mapping_generation: payload.mapping_generation,
    current_signed_mapping_digest: mapping.signed_mapping_digest,
    trust_root_epoch: payload.trust_root_epoch,
    authority_epoch: payload.authority_epoch,
    revocation_generation: payload.revocation_generation,
    signer_key_id: payload.signer_key_id,
    signer_public_key_digest: publicKeyDigest(keyPair.publicKey),
    public_key: keyPair.publicKey,
    ...overrides,
  };
}

function createFixture(options = {}) {
  const keyPair = options.keyPair || crypto.generateKeyPairSync("ed25519");
  const payload = mappingPayload(keyPair, options.payload || {});
  const control = {
    monotonic_ms: options.monotonicMs == null ? 1_500 : options.monotonicMs,
    mapping: signMapping(keyPair, payload),
    trust: null,
    monotonic_hook: null,
    mapping_hook: null,
    resolver_hook: null,
    monotonic_reads: 0,
    mapping_reads: 0,
    resolver_reads: 0,
    trust_queries: [],
  };
  control.trust = currentTrust(control.mapping, keyPair);

  const config = {
    port_id: options.portId || "trusted_clock_test_port",
    clock_id: payload.clock_id,
    monotonic_epoch_id: payload.monotonic_epoch_id,
    uncertainty_ceiling_ms: options.uncertaintyCeilingMs == null
      ? MAX_UNCERTAINTY_MS
      : options.uncertaintyCeilingMs,
    read_monotonic_ms: () => {
      control.monotonic_reads += 1;
      if (control.monotonic_hook) return control.monotonic_hook();
      return control.monotonic_ms;
    },
    read_signed_mapping: () => {
      control.mapping_reads += 1;
      if (control.mapping_hook) return control.mapping_hook();
      return control.mapping;
    },
    resolve_current_trust: (query) => {
      control.resolver_reads += 1;
      control.trust_queries.push(query);
      if (control.resolver_hook) return control.resolver_hook(query);
      return control.trust;
    },
  };
  const originalCallbacks = {
    read_monotonic_ms: config.read_monotonic_ms,
    read_signed_mapping: config.read_signed_mapping,
    resolve_current_trust: config.resolve_current_trust,
  };
  const port = createPhysicalTrustedClockPort(config);

  function setMapping(nextMapping, nextKeyPair = keyPair) {
    control.mapping = nextMapping;
    control.trust = currentTrust(nextMapping, nextKeyPair);
  }

  return { config, control, keyPair, originalCallbacks, port, setMapping };
}

function captureError(callback) {
  try {
    callback();
  } catch (error) {
    return error;
  }
  assert.fail("expected callback to throw");
}

test("signed monotonic mapping returns a frozen bounded UTC interval", () => {
  const fixture = createFixture();
  const sample = samplePhysicalTrustedClock(fixture.port);

  assert.deepEqual(sample, {
    version: 1,
    clock_id: "physical-clock:trusted-clock-test-1",
    monotonic_epoch_id: digest("trusted-clock-monotonic-epoch-1"),
    mapping_generation: 1,
    monotonic_ms: 1_500,
    trusted_utc: "2026-07-18T12:00:00.500Z",
    trusted_utc_earliest: "2026-07-18T12:00:00.475Z",
    trusted_utc_latest: "2026-07-18T12:00:00.525Z",
    max_uncertainty_ms: 25,
    signed_mapping_digest: fixture.control.mapping.signed_mapping_digest,
    trust_root_epoch: 4,
    authority_epoch: 7,
    revocation_generation: 2,
  });
  assert.ok(Object.isFrozen(sample));
  assert.equal(fixture.control.monotonic_reads, 2);
  assert.equal(fixture.control.mapping_reads, 1);
  assert.equal(fixture.control.resolver_reads, 1);
  assert.ok(Object.isFrozen(fixture.control.trust_queries[0]));
  assert.equal(
    fixture.control.trust_queries[0].signed_mapping_digest,
    fixture.control.mapping.signed_mapping_digest,
  );
  assert.ok(!Object.hasOwn(fixture.control.trust_queries[0], "signature"));
  assert.ok(!Object.hasOwn(fixture.control.trust_queries[0], "public_key"));

  fixture.control.monotonic_ms = 1_501;
  assert.equal(
    samplePhysicalTrustedClock(fixture.port).trusted_utc,
    "2026-07-18T12:00:00.501Z",
  );
});

test("the public port is privately branded and does not expose callbacks or key material", () => {
  const fixture = createFixture();
  assert.equal(assertPhysicalTrustedClockPort(fixture.port), fixture.port);
  assert.ok(Object.isFrozen(fixture.port));
  assert.deepEqual(Object.keys(fixture.port).sort(), [
    "clock_id",
    "mode",
    "monotonic_epoch_id",
    "port_id",
    "uncertainty_ceiling_ms",
    "version",
  ]);
  for (const callback of Object.values(fixture.originalCallbacks)) {
    assert.ok(!Object.values(fixture.port).includes(callback));
  }
  assert.throws(
    () => assertPhysicalTrustedClockPort({ ...fixture.port }),
    /privately branded live port/,
  );
  assert.throws(
    () => samplePhysicalTrustedClock(Object.freeze({ ...fixture.port })),
    /privately branded live port/,
  );

  fixture.config.clock_id = "physical-clock:mutated";
  fixture.config.monotonic_epoch_id = digest("mutated-epoch");
  fixture.config.read_monotonic_ms = () => 0;
  fixture.control.monotonic_ms = 1_501;
  assert.equal(samplePhysicalTrustedClock(fixture.port).monotonic_ms, 1_501);
});

test("mapping and output values are snapshotted against caller mutation", () => {
  const fixture = createFixture();
  const originalReference = fixture.control.mapping.payload.reference_utc;
  fixture.control.resolver_hook = (query) => {
    assert.ok(Object.isFrozen(query));
    assert.throws(() => {
      query.mapping_generation = 99;
    }, TypeError);
    fixture.control.mapping.payload.reference_utc = "2026-07-18T11:58:00.000Z";
    return fixture.control.trust;
  };
  const sample = samplePhysicalTrustedClock(fixture.port);
  assert.equal(sample.trusted_utc, "2026-07-18T12:00:00.500Z");
  assert.notEqual(fixture.control.mapping.payload.reference_utc, originalReference);
  assert.throws(() => {
    sample.trusted_utc = "2026-07-18T00:00:00.000Z";
  }, TypeError);
  assert.equal(sample.trusted_utc, "2026-07-18T12:00:00.500Z");
});

test("normalization rejects payload, digest, signature, and envelope drift", async (t) => {
  const fixture = createFixture();
  const valid = fixture.control.mapping;

  await t.test("canonical payload digest drift", () => {
    const altered = {
      ...valid,
      payload: { ...valid.payload, authority_epoch: valid.payload.authority_epoch + 1 },
    };
    assert.throws(() => normalizeSignedPhysicalClockMapping(altered), /payload_digest/);
  });

  await t.test("signed mapping digest drift", () => {
    const altered = { ...valid, signed_mapping_digest: digest("wrong-signed-mapping") };
    assert.throws(() => normalizeSignedPhysicalClockMapping(altered), /signed_mapping_digest/);
  });

  await t.test("signature is bound to the payload digest", () => {
    const payload = { ...valid.payload, authority_epoch: valid.payload.authority_epoch + 1 };
    const payloadDigest = hashCanonicalJson(payload);
    const basis = {
      version: 1,
      domain: TRUSTED_CLOCK_MAPPING_DOMAIN,
      payload,
      payload_digest: payloadDigest,
      scheme: "ed25519",
      signature: valid.signature,
    };
    const altered = { ...basis, signed_mapping_digest: hashCanonicalJson(basis) };
    const alteredFixture = createFixture();
    alteredFixture.control.mapping = altered;
    alteredFixture.control.trust = currentTrust(altered, fixture.keyPair, {
      public_key: fixture.keyPair.publicKey,
      signer_public_key_digest: publicKeyDigest(fixture.keyPair.publicKey),
    });
    assert.throws(
      () => samplePhysicalTrustedClock(alteredFixture.port),
      /signature is invalid/,
    );
  });

  await t.test("non-canonical signature and envelope domain", () => {
    assert.throws(
      () => normalizeSignedPhysicalClockMapping({ ...valid, signature: `${valid.signature}=` }),
      /canonical Ed25519 base64url/,
    );
    assert.throws(
      () => normalizeSignedPhysicalClockMapping({ ...valid, domain: "wrong-domain" }),
      /domain, version, or signature scheme/,
    );
  });

  await t.test("accessor and non-enumerable fields are rejected without invocation", () => {
    let getterCalls = 0;
    const payload = { ...valid.payload };
    Object.defineProperty(payload, "clock_id", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return valid.payload.clock_id;
      },
    });
    assert.throws(
      () => normalizeSignedPhysicalClockMapping({ ...valid, payload }),
      /enumerable data field/,
    );
    assert.equal(getterCalls, 0);

    const hidden = { ...valid };
    Object.defineProperty(hidden, "hidden", { value: "not-closed", enumerable: false });
    assert.throws(() => normalizeSignedPhysicalClockMapping(hidden), /unknown fields: hidden/);
  });
});

test("live trust rejects revocation and every authority/key/generation drift", async (t) => {
  const alternateKeyPair = crypto.generateKeyPairSync("ed25519");
  const cases = [
    ["untrusted", (fixture) => ({ ...fixture.control.trust, trusted: false })],
    ["revoked", (fixture) => ({ ...fixture.control.trust, revoked: true })],
    ["clock id", (fixture) => ({
      ...fixture.control.trust,
      clock_id: "physical-clock:other-clock",
    })],
    ["monotonic epoch", (fixture) => ({
      ...fixture.control.trust,
      monotonic_epoch_id: digest("other-monotonic-epoch"),
    })],
    ["mapping generation", (fixture) => ({
      ...fixture.control.trust,
      current_mapping_generation: fixture.control.trust.current_mapping_generation + 1,
    })],
    ["mapping digest", (fixture) => ({
      ...fixture.control.trust,
      current_signed_mapping_digest: digest("other-current-mapping"),
    })],
    ["trust root epoch", (fixture) => ({
      ...fixture.control.trust,
      trust_root_epoch: fixture.control.trust.trust_root_epoch + 1,
    })],
    ["authority epoch", (fixture) => ({
      ...fixture.control.trust,
      authority_epoch: fixture.control.trust.authority_epoch + 1,
    })],
    ["revocation generation", (fixture) => ({
      ...fixture.control.trust,
      revocation_generation: fixture.control.trust.revocation_generation + 1,
    })],
    ["signer key id", (fixture) => ({
      ...fixture.control.trust,
      signer_key_id: "clock-key:rotated",
    })],
    ["signer key rotation", (fixture) => ({
      ...fixture.control.trust,
      signer_public_key_digest: publicKeyDigest(alternateKeyPair.publicKey),
      public_key: alternateKeyPair.publicKey,
    })],
  ];

  for (const [name, mutate] of cases) {
    await t.test(name, () => {
      const fixture = createFixture();
      fixture.control.trust = mutate(fixture);
      assert.throws(() => samplePhysicalTrustedClock(fixture.port));
    });
  }

  await t.test("the public key digest must bind the returned key", () => {
    const fixture = createFixture();
    fixture.control.trust = {
      ...fixture.control.trust,
      signer_public_key_digest: digest("not-the-returned-key"),
    };
    assert.throws(() => samplePhysicalTrustedClock(fixture.port), /does not bind public_key/);
  });

  await t.test("trust is re-resolved on every sample", () => {
    const fixture = createFixture();
    samplePhysicalTrustedClock(fixture.port);
    fixture.control.monotonic_ms += 1;
    fixture.control.trust = { ...fixture.control.trust, revoked: true };
    assert.throws(() => samplePhysicalTrustedClock(fixture.port), /no longer trusted/);
    assert.equal(fixture.control.resolver_reads, 2);
  });
});

test("resolver and source outage, malformed, async, and thenable results fail closed", async (t) => {
  await t.test("resolver exception is sanitized", () => {
    const fixture = createFixture();
    fixture.control.resolver_hook = () => {
      throw new Error(`resolver-secret:${fixture.control.mapping.signature}`);
    };
    const error = captureError(() => samplePhysicalTrustedClock(fixture.port));
    assert.equal(error.message, "trusted clock authority is unavailable");
    assert.equal(error.cause, undefined);
    assert.ok(!error.message.includes(fixture.control.mapping.signature));
  });

  await t.test("mapping and monotonic exceptions are sanitized", () => {
    for (const source of ["mapping", "monotonic"]) {
      const fixture = createFixture();
      const secret = `callback-secret-${source}`;
      fixture.control[`${source}_hook`] = () => {
        throw new Error(secret);
      };
      const error = captureError(() => samplePhysicalTrustedClock(fixture.port));
      assert.equal(error.cause, undefined);
      assert.ok(!error.message.includes(secret));
      assert.match(error.message, /is unavailable/);
    }
  });

  await t.test("native promises and generic thenables are rejected", async () => {
    const asyncFixture = createFixture();
    asyncFixture.control.resolver_hook = () => Promise.resolve(asyncFixture.control.trust);
    assert.throws(
      () => samplePhysicalTrustedClock(asyncFixture.port),
      /must be synchronous/,
    );

    const rejectedFixture = createFixture();
    rejectedFixture.control.resolver_hook = async () => {
      throw new Error("async-resolver-secret");
    };
    const rejectedError = captureError(() => samplePhysicalTrustedClock(rejectedFixture.port));
    assert.equal(rejectedError.message, "trusted clock authority must be synchronous");
    assert.ok(!rejectedError.message.includes("async-resolver-secret"));
    await new Promise((resolve) => setImmediate(resolve));

    const thenableFixture = createFixture();
    thenableFixture.control.resolver_hook = () => ({
      get then() {
        throw new Error("thenable-secret");
      },
    });
    const error = captureError(() => samplePhysicalTrustedClock(thenableFixture.port));
    assert.equal(error.message, "trusted clock authority is unavailable");
    assert.equal(error.cause, undefined);
    assert.ok(!error.message.includes("thenable-secret"));
  });

  await t.test("missing, unknown, accessor, and wrong-key trust results are rejected", () => {
    const malformedResults = [
      {},
      { ...createFixture().control.trust, unknown: true },
      { ...createFixture().control.trust, public_key: "not-a-key" },
    ];
    for (const malformed of malformedResults) {
      const fixture = createFixture();
      fixture.control.resolver_hook = () => malformed;
      assert.throws(() => samplePhysicalTrustedClock(fixture.port));
    }

    const accessorFixture = createFixture();
    let getterCalls = 0;
    const accessorTrust = { ...accessorFixture.control.trust };
    Object.defineProperty(accessorTrust, "trusted", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return true;
      },
    });
    accessorFixture.control.resolver_hook = () => accessorTrust;
    assert.throws(
      () => samplePhysicalTrustedClock(accessorFixture.port),
      /enumerable data field/,
    );
    assert.equal(getterCalls, 0);
  });
});

test("sampling is non-reentrant and a failed nested call cannot mutate clock state", () => {
  const fixture = createFixture();
  fixture.control.resolver_hook = () => {
    assert.throws(
      () => samplePhysicalTrustedClock(fixture.port),
      /already in progress/,
    );
    return fixture.control.trust;
  };
  assert.equal(samplePhysicalTrustedClock(fixture.port).monotonic_ms, 1_500);
  fixture.control.resolver_hook = null;
  fixture.control.monotonic_ms = 1_501;
  assert.equal(samplePhysicalTrustedClock(fixture.port).monotonic_ms, 1_501);
});

test("sampling reflects resolver latency in the final monotonic observation", () => {
  const fixture = createFixture({
    payload: {
      expires_at: "2026-07-18T12:00:00.600Z",
    },
  });
  fixture.control.resolver_hook = () => {
    fixture.control.monotonic_ms = 1_600;
    return fixture.control.trust;
  };

  assert.throws(
    () => samplePhysicalTrustedClock(fixture.port),
    /outside the signed mapping validity window/,
  );
  assert.equal(fixture.control.monotonic_reads, 2);
});

test("monotonic and signed wall-clock rollback fail without committing partial state", async (t) => {
  await t.test("monotonic rollback", () => {
    const fixture = createFixture();
    samplePhysicalTrustedClock(fixture.port);
    fixture.control.monotonic_ms = 1_499;
    assert.throws(() => samplePhysicalTrustedClock(fixture.port), /monotonic clock moved backwards/);
    fixture.control.monotonic_ms = 1_501;
    assert.equal(samplePhysicalTrustedClock(fixture.port).monotonic_ms, 1_501);
  });

  await t.test("central wall-clock rollback", () => {
    const fixture = createFixture();
    samplePhysicalTrustedClock(fixture.port);
    const nextPayload = mappingPayload(fixture.keyPair, {
      mapping_generation: 2,
      reference_monotonic_ms: 1_501,
      reference_utc: "2026-07-18T11:59:00.000Z",
    });
    fixture.setMapping(signMapping(fixture.keyPair, nextPayload));
    fixture.control.monotonic_ms = 1_501;
    assert.throws(() => samplePhysicalTrustedClock(fixture.port), /wall clock moved backwards/);
  });

  await t.test("uncertainty interval rollback", () => {
    const fixture = createFixture({ payload: { max_uncertainty_ms: 100 } });
    samplePhysicalTrustedClock(fixture.port);
    const nextPayload = mappingPayload(fixture.keyPair, {
      mapping_generation: 2,
      reference_monotonic_ms: 1_501,
      reference_utc: "2026-07-18T12:00:00.501Z",
      max_uncertainty_ms: 200,
    });
    fixture.setMapping(signMapping(fixture.keyPair, nextPayload));
    fixture.control.monotonic_ms = 1_501;
    assert.throws(
      () => samplePhysicalTrustedClock(fixture.port),
      /uncertainty interval moved backwards/,
    );
  });
});

test("mapping rollback, same-generation forks, and stale restart mappings fail closed", async (t) => {
  await t.test("generation rollback", () => {
    const fixture = createFixture({ payload: { mapping_generation: 2 } });
    samplePhysicalTrustedClock(fixture.port);
    const older = signMapping(fixture.keyPair, mappingPayload(fixture.keyPair, {
      mapping_generation: 1,
    }));
    fixture.setMapping(older);
    fixture.control.monotonic_ms = 1_501;
    assert.throws(() => samplePhysicalTrustedClock(fixture.port), /generation moved backwards/);
  });

  await t.test("same-generation fork", () => {
    const fixture = createFixture({ payload: { mapping_generation: 2 } });
    samplePhysicalTrustedClock(fixture.port);
    const fork = signMapping(fixture.keyPair, mappingPayload(fixture.keyPair, {
      mapping_generation: 2,
      expires_at: "2026-07-18T12:09:59.999Z",
    }));
    fixture.setMapping(fork);
    fixture.control.monotonic_ms = 1_501;
    assert.throws(() => samplePhysicalTrustedClock(fixture.port), /forked/);
  });

  await t.test("a fresh port still requires the authority's exact current digest", () => {
    const fixture = createFixture({ payload: { mapping_generation: 2 } });
    const current = fixture.control.mapping;
    const staleFork = signMapping(fixture.keyPair, mappingPayload(fixture.keyPair, {
      mapping_generation: 2,
      expires_at: "2026-07-18T12:09:59.999Z",
    }));
    fixture.control.mapping = staleFork;
    fixture.control.trust = currentTrust(current, fixture.keyPair);
    assert.throws(
      () => samplePhysicalTrustedClock(fixture.port),
      /exact current mapping/,
    );
  });
});

test("mapping generation advances cannot roll clock authority epochs backwards", async (t) => {
  for (const [field, rollbackValue] of [
    ["trust_root_epoch", 3],
    ["authority_epoch", 6],
    ["revocation_generation", 1],
  ]) {
    await t.test(field, () => {
      const fixture = createFixture();
      samplePhysicalTrustedClock(fixture.port);
      const rollback = signMapping(fixture.keyPair, mappingPayload(fixture.keyPair, {
        mapping_generation: 2,
        reference_monotonic_ms: 1_501,
        reference_utc: "2026-07-18T12:00:00.501Z",
        [field]: rollbackValue,
      }));
      fixture.setMapping(rollback);
      fixture.control.monotonic_ms = 1_501;
      assert.throws(
        () => samplePhysicalTrustedClock(fixture.port),
        new RegExp(`${field} moved backwards`),
      );

      const recovered = signMapping(fixture.keyPair, mappingPayload(fixture.keyPair, {
        mapping_generation: 2,
        reference_monotonic_ms: 1_501,
        reference_utc: "2026-07-18T12:00:00.501Z",
      }));
      fixture.setMapping(recovered);
      assert.equal(samplePhysicalTrustedClock(fixture.port).mapping_generation, 2);
    });
  }

  await t.test("all authority epochs may advance with the mapping generation", () => {
    const fixture = createFixture();
    samplePhysicalTrustedClock(fixture.port);
    const advanced = signMapping(fixture.keyPair, mappingPayload(fixture.keyPair, {
      mapping_generation: 2,
      reference_monotonic_ms: 1_501,
      reference_utc: "2026-07-18T12:00:00.501Z",
      trust_root_epoch: 5,
      authority_epoch: 8,
      revocation_generation: 3,
    }));
    fixture.setMapping(advanced);
    fixture.control.monotonic_ms = 1_501;
    const sample = samplePhysicalTrustedClock(fixture.port);
    assert.equal(sample.mapping_generation, 2);
    assert.equal(sample.trust_root_epoch, 5);
    assert.equal(sample.authority_epoch, 8);
    assert.equal(sample.revocation_generation, 3);
  });
});

test("mapping validity uses inclusive not-before, exclusive expiry, and the full uncertainty interval", async (t) => {
  const baseUtc = Date.parse("2026-07-18T12:00:00.000Z");

  async function boundaryCase(name, payloadOverrides, options = {}) {
    await t.test(name, () => {
      const fixture = createFixture({
        monotonicMs: options.monotonicMs == null ? 1_000 : options.monotonicMs,
        payload: payloadOverrides,
        uncertaintyCeilingMs: options.uncertaintyCeilingMs,
      });
      if (options.error) {
        assert.throws(() => samplePhysicalTrustedClock(fixture.port), options.error);
      } else {
        assert.ok(samplePhysicalTrustedClock(fixture.port));
      }
    });
  }

  await boundaryCase("not-before exact with zero uncertainty is valid", {
    reference_utc: timestamp(baseUtc),
    not_before: timestamp(baseUtc),
    expires_at: timestamp(baseUtc + 60_000),
    max_uncertainty_ms: 0,
  });
  await boundaryCase("expiry exact is invalid", {
    reference_utc: timestamp(baseUtc + 59_999),
    not_before: timestamp(baseUtc),
    expires_at: timestamp(baseUtc + 60_000),
    max_uncertainty_ms: 0,
  }, { monotonicMs: 1_001, error: /outside the signed mapping validity window/ });
  await boundaryCase("uncertainty lower edge exact is valid", {
    reference_utc: timestamp(baseUtc + 100),
    not_before: timestamp(baseUtc),
    expires_at: timestamp(baseUtc + 60_000),
    max_uncertainty_ms: 100,
  });
  await boundaryCase("uncertainty below not-before is invalid", {
    reference_utc: timestamp(baseUtc + 99),
    not_before: timestamp(baseUtc),
    expires_at: timestamp(baseUtc + 60_000),
    max_uncertainty_ms: 100,
  }, { error: /outside the signed mapping validity window/ });
  await boundaryCase("uncertainty upper edge one millisecond before expiry is valid", {
    reference_utc: timestamp(baseUtc + 59_899),
    not_before: timestamp(baseUtc),
    expires_at: timestamp(baseUtc + 60_000),
    max_uncertainty_ms: 100,
  });
  await boundaryCase("uncertainty upper edge exact at expiry is invalid", {
    reference_utc: timestamp(baseUtc + 59_900),
    not_before: timestamp(baseUtc),
    expires_at: timestamp(baseUtc + 60_000),
    max_uncertainty_ms: 100,
  }, { error: /outside the signed mapping validity window/ });
  await boundaryCase("enrolled uncertainty ceiling is enforced", {
    reference_utc: timestamp(baseUtc + 1_000),
    not_before: timestamp(baseUtc),
    expires_at: timestamp(baseUtc + 60_000),
    max_uncertainty_ms: 101,
  }, { uncertaintyCeilingMs: 100, error: /uncertainty ceiling/ });
  await boundaryCase("future monotonic reference is invalid", {
    reference_monotonic_ms: 1_001,
    reference_utc: timestamp(baseUtc + 1_000),
    not_before: timestamp(baseUtc),
    expires_at: timestamp(baseUtc + 60_000),
    max_uncertainty_ms: 0,
  }, { monotonicMs: 1_000, error: /predates the signed clock mapping reference/ });
});

test("mapping lifetime and uncertainty hard caps enforce exact schema boundaries", () => {
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const start = Date.parse("2026-07-18T00:00:00.000Z");
  const exactLifetime = signMapping(keyPair, mappingPayload(keyPair, {
    reference_utc: timestamp(start + 1),
    not_before: timestamp(start),
    expires_at: timestamp(start + MAX_MAPPING_LIFETIME_MS),
    max_uncertainty_ms: MAX_UNCERTAINTY_MS,
  }));
  assert.ok(normalizeSignedPhysicalClockMapping(exactLifetime));

  const tooLong = signMapping(keyPair, mappingPayload(keyPair, {
    reference_utc: timestamp(start + 1),
    not_before: timestamp(start),
    expires_at: timestamp(start + MAX_MAPPING_LIFETIME_MS + 1),
  }));
  assert.throws(() => normalizeSignedPhysicalClockMapping(tooLong), /no longer than 24 hours/);

  const tooUncertain = signMapping(keyPair, mappingPayload(keyPair, {
    max_uncertainty_ms: MAX_UNCERTAINTY_MS + 1,
  }));
  assert.throws(() => normalizeSignedPhysicalClockMapping(tooUncertain), /through 60000/);

  const referenceAtExpiry = signMapping(keyPair, mappingPayload(keyPair, {
    reference_utc: "2026-07-18T12:10:00.000Z",
  }));
  assert.throws(() => normalizeSignedPhysicalClockMapping(referenceAtExpiry), /inside the mapping/);
});

test("conservative interval helpers require branded samples and exact uncertainty boundaries", () => {
  const fixture = createFixture();
  const sample = samplePhysicalTrustedClock(fixture.port);
  assert.equal(assertPhysicalTrustedClockSample(sample), sample);
  assert.equal(assertPhysicalTrustedClockValidityWindow(sample, {
    not_before: sample.trusted_utc_earliest,
    expires_at: "2026-07-18T12:00:00.526Z",
  }), sample);
  assert.throws(
    () => assertPhysicalTrustedClockValidityWindow(sample, {
      not_before: "2026-07-18T12:00:00.476Z",
      expires_at: "2026-07-18T12:00:01.000Z",
    }),
    /not yet admissible under trusted clock uncertainty/,
  );
  assert.throws(
    () => assertPhysicalTrustedClockValidityWindow(sample, {
      not_before: "2026-07-18T12:00:00.000Z",
      expires_at: sample.trusted_utc_latest,
    }),
    /has expired under trusted clock uncertainty/,
  );
  assert.equal(
    assertPhysicalTrustedClockTimestampNonFuture(sample, sample.trusted_utc_earliest),
    sample.trusted_utc_earliest,
  );
  assert.throws(
    () => assertPhysicalTrustedClockTimestampNonFuture(
      sample,
      "2026-07-18T12:00:00.476Z",
    ),
    /is in the future under trusted clock uncertainty/,
  );
  const clone = structuredClone(sample);
  assert.throws(() => assertPhysicalTrustedClockSample(clone), /privately branded live port/);
  assert.throws(
    () => assertPhysicalTrustedClockValidityWindow(clone, {
      not_before: sample.trusted_utc_earliest,
      expires_at: "2026-07-18T12:00:00.526Z",
    }),
    /privately branded live port/,
  );
});

test("public samples and failures do not leak callbacks, signatures, or keys", () => {
  const fixture = createFixture();
  const sampleJson = JSON.stringify(samplePhysicalTrustedClock(fixture.port));
  const portJson = JSON.stringify(fixture.port);
  const publicKeyPem = fixture.keyPair.publicKey.export({ type: "spki", format: "pem" });
  for (const publicText of [sampleJson, portJson]) {
    assert.ok(!publicText.includes(fixture.control.mapping.signature));
    assert.ok(!publicText.includes(publicKeyPem));
    assert.ok(!publicText.includes("read_signed_mapping"));
    assert.ok(!publicText.includes("resolve_current_trust"));
  }

  const invalid = {
    ...fixture.control.mapping,
    signature: `${fixture.control.mapping.signature.slice(0, -1)}${
      fixture.control.mapping.signature.endsWith("A") ? "B" : "A"
    }`,
  };
  invalid.signed_mapping_digest = hashCanonicalJson({
    version: invalid.version,
    domain: invalid.domain,
    payload: invalid.payload,
    payload_digest: invalid.payload_digest,
    scheme: invalid.scheme,
    signature: invalid.signature,
  });
  fixture.control.mapping = invalid;
  fixture.control.trust = currentTrust(invalid, fixture.keyPair);
  const error = captureError(() => samplePhysicalTrustedClock(fixture.port));
  assert.ok(!error.message.includes(invalid.signature));
  assert.ok(!error.message.includes(publicKeyPem));
  assert.equal(error.cause, undefined);
});
