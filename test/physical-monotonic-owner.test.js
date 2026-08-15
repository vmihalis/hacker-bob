"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  assertPhysicalMonotonicOwnerPort,
  assertProductionPhysicalExperimentMonotonicOwnerPort,
  assertProductionPhysicalMonotonicOwnerPort,
  claimProductionPhysicalExperimentMonotonicOwner,
  compareAndSetProductionPhysicalExperimentMonotonicOwnerState,
  compareAndSetPhysicalMonotonicOwnerState,
  describePhysicalMonotonicOwner,
  openProductionPhysicalMonotonicOwner,
  readProductionPhysicalExperimentMonotonicOwnerState,
  readPhysicalMonotonicOwnerState,
} = require("../mcp/domains/physical/physical-monotonic-owner.js");
const { sessionNucleusFromState } = require("../mcp/core/governance/governance-contracts.js");
const { sessionDir } = require("../mcp/core/io/paths.js");
const { normalizePhysicalScopeNucleusAxis } = require("../mcp/lib/physical-scope-axis.js");
const { buildInitialSessionState } = require("../mcp/core/session/session-state-contracts.js");
const { writeSessionStateDocument } = require("../mcp/core/session/session-state-store.js");
const {
  SANDBOX_AGENT_UID_ENV,
  SANDBOX_ISOLATION_ACK_ENV,
  SANDBOX_ISOLATION_ACK_TOKEN,
  SANDBOX_SIGNER_UID_ENV,
} = require("../mcp/core/ledger-integrity/index.js");
const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");

const CONTEXT = "hacker-bob/physical-experiment-row-head/v1";

function digest(label) {
  return hashCanonicalJson({ label });
}

function installPhysicalSession(domain) {
  const physicalScope = normalizePhysicalScopeNucleusAxis({
    version: 1,
    physical_enabled: true,
    policy_version: 1,
    policy_id: "physical_monotonic_owner_fixture",
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

function harness(t, { mechanismA = true } = {}) {
  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid == null || uid === 0) throw new Error("physical monotonic owner fixture requires non-root");
  const prior = Object.fromEntries([
    ["HOME", process.env.HOME],
    [SANDBOX_ISOLATION_ACK_ENV, process.env[SANDBOX_ISOLATION_ACK_ENV]],
    [SANDBOX_SIGNER_UID_ENV, process.env[SANDBOX_SIGNER_UID_ENV]],
    [SANDBOX_AGENT_UID_ENV, process.env[SANDBOX_AGENT_UID_ENV]],
  ]);
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-monotonic-owner-home-"));
  const externalRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-monotonic-owner-root-"));
  fs.chmodSync(home, 0o700);
  fs.chmodSync(externalRoot, 0o700);
  process.env.HOME = home;
  if (mechanismA) {
    process.env[SANDBOX_ISOLATION_ACK_ENV] = SANDBOX_ISOLATION_ACK_TOKEN;
    process.env[SANDBOX_SIGNER_UID_ENV] = String(uid);
    process.env[SANDBOX_AGENT_UID_ENV] = String(uid + 1);
  } else {
    delete process.env[SANDBOX_ISOLATION_ACK_ENV];
    delete process.env[SANDBOX_SIGNER_UID_ENV];
    delete process.env[SANDBOX_AGENT_UID_ENV];
  }
  t.after(() => {
    for (const [name, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(externalRoot, { recursive: true, force: true });
  });
  return { externalRoot, home };
}

function open(h, domain, nucleusHash, overrides = {}) {
  return openProductionPhysicalMonotonicOwner({
    version: 1,
    target_domain: domain,
    session_nucleus_hash: nucleusHash,
    external_owner_root: h.externalRoot,
    context_domain: CONTEXT,
    ...overrides,
  });
}

test("same-UID and lookalike monotonic owners remain non-authorizing", { concurrency: false }, (t) => {
  const h = harness(t, { mechanismA: false });
  const domain = "physical-monotonic-same-uid.example.com";
  const nucleus = installPhysicalSession(domain);
  const port = open(h, domain, nucleus.nucleus_hash);
  assert.equal(assertPhysicalMonotonicOwnerPort(port), port);
  assert.equal(describePhysicalMonotonicOwner(port).production_ready, false);
  assert.throws(() => assertProductionPhysicalMonotonicOwnerPort(port), /Mechanism-A/);
  assert.throws(() => JSON.stringify(port), /process-local/);
  assert.throws(
    () => assertPhysicalMonotonicOwnerPort({ ...port }),
    /privately branded/,
  );
  assert.throws(
    () => openProductionPhysicalMonotonicOwner({
      version: 1,
      target_domain: domain,
      session_nucleus_hash: nucleus.nucleus_hash,
      external_owner_root: h.externalRoot,
      context_domain: CONTEXT,
      production_ready: true,
    }),
    /fields are not exact/,
  );
});

test("Mechanism-A owner provides exact null-genesis CAS, cold reopen, and hostile closure",
  { concurrency: false }, (t) => {
    const h = harness(t);
    const domain = "physical-monotonic-production.example.com";
    const nucleus = installPhysicalSession(domain);
    let port = open(h, domain, nucleus.nucleus_hash);
    assert.equal(assertProductionPhysicalMonotonicOwnerPort(port), port);
    assert.equal(readPhysicalMonotonicOwnerState(port), null);
    const genesis = {
      phase: "prepared",
      generation: 0,
      pending_commit_digest: digest("pending-0"),
      row_record_digest: digest("row-0"),
    };
    assert.equal(compareAndSetPhysicalMonotonicOwnerState(port, null, genesis), true);
    assert.deepEqual(readPhysicalMonotonicOwnerState(port), genesis);
    assert.equal(Object.isFrozen(readPhysicalMonotonicOwnerState(port)), true);
    assert.equal(
      compareAndSetPhysicalMonotonicOwnerState(port, null, { generation: 99 }),
      false,
      "stale genesis cannot overwrite a committed owner head",
    );
    const committed = {
      phase: "committed",
      generation: 0,
      row_record_digest: digest("row-0"),
      local_row_anchor_digest: digest("local-row-anchor-0"),
    };
    assert.equal(compareAndSetPhysicalMonotonicOwnerState(port, genesis, committed), true);
    assert.equal(
      compareAndSetPhysicalMonotonicOwnerState(port, genesis, { generation: 1 }),
      false,
      "a stale prepared head cannot fork after promotion",
    );
    const large = {
      phase: "prepared",
      generation: 1,
      pending_commit_digest: digest("pending-1"),
      row_record_digest: digest("row-1"),
      bounded_payload: "x".repeat(64 * 1024),
    };
    assert.equal(compareAndSetPhysicalMonotonicOwnerState(port, committed, large), true);
    const before = describePhysicalMonotonicOwner(port);
    assert.equal(before.head_sequence, 3);
    assert.match(before.head_digest, /^[a-f0-9]{64}$/u);
    assert.match(before.state_digest, /^[a-f0-9]{64}$/u);

    // Lost acknowledgement is resolved by exact read, and cold reopen retains
    // the same internally issued slot/enrollment/head.
    assert.deepEqual(readPhysicalMonotonicOwnerState(port), large);
    port = open(h, domain, nucleus.nucleus_hash);
    const reopened = describePhysicalMonotonicOwner(port);
    assert.equal(reopened.slot_digest, before.slot_digest);
    assert.equal(reopened.enrollment_digest, before.enrollment_digest);
    assert.equal(reopened.head_digest, before.head_digest);
    assert.deepEqual(readPhysicalMonotonicOwnerState(port), large);

    const ack = process.env[SANDBOX_ISOLATION_ACK_ENV];
    delete process.env[SANDBOX_ISOLATION_ACK_ENV];
    assert.throws(
      () => readPhysicalMonotonicOwnerState(port),
      /lost live Mechanism-A custody/,
    );
    process.env[SANDBOX_ISOLATION_ACK_ENV] = ack;
    assert.deepEqual(readPhysicalMonotonicOwnerState(port), large);

    // One root cannot silently re-enroll another context or target/nucleus.
    assert.throws(
      () => open(h, domain, nucleus.nucleus_hash, {
        context_domain: "hacker-bob/another-owner-context/v1",
      }),
      /owner key binding drifted|authority drift/i,
    );
    const otherDomain = "physical-monotonic-cross-domain.example.com";
    const otherNucleus = installPhysicalSession(otherDomain);
    assert.throws(
      () => open(h, otherDomain, otherNucleus.nucleus_hash),
      /owner key binding drifted|authority drift/i,
    );

    const siblingSessionOwner = path.join(sessionDir(otherDomain), "owner-for-first-target");
    fs.mkdirSync(siblingSessionOwner, { mode: 0o700 });
    assert.throws(
      () => open(h, domain, nucleus.nucleus_hash, {
        external_owner_root: siblingSessionOwner,
      }),
      /disjoint from the entire Bob sessions tree/u,
    );

    // A local-session path cannot masquerade as independent retention.
    const nested = path.join(sessionDir(domain), "not-external-owner");
    fs.mkdirSync(nested, { mode: 0o700 });
    assert.throws(
      () => open(h, domain, nucleus.nucleus_hash, { external_owner_root: nested }),
      /disjoint/,
    );

    // Deleting an interior signed head leaves a detectable cold chain gap.
    const firstHead = path.join(h.externalRoot, "heads", "00000001.json");
    const saved = fs.readFileSync(firstHead);
    fs.unlinkSync(firstHead);
    assert.throws(
      () => readPhysicalMonotonicOwnerState(port),
      /head chain has a gap/,
    );
    fs.writeFileSync(firstHead, saved, { mode: 0o600, flag: "wx" });
    fs.chmodSync(firstHead, 0o600);
    assert.deepEqual(readPhysicalMonotonicOwnerState(port), large);

    // Signed bytes cannot be altered while retaining an authoritative brand.
    const currentHead = path.join(h.externalRoot, "heads", "00000003.json");
    const document = JSON.parse(fs.readFileSync(currentHead, "utf8"));
    document.state.generation = 999;
    fs.writeFileSync(currentHead, `${JSON.stringify(document)}\n`, { mode: 0o600 });
    assert.throws(
      () => readPhysicalMonotonicOwnerState(port),
      /signed monotonic head chain is invalid/,
    );
  });

test("the fixed experiment consumer survives cold reopen while retained raw ports cannot mutate or regress it",
  { concurrency: false }, (t) => {
    const h = harness(t);
    const domain = "physical-monotonic-exclusive-consumer.example.com";
    const nucleus = installPhysicalSession(domain);
    const claimBinding = {
      version: 1,
      target_domain: domain,
      session_nucleus_hash: nucleus.nucleus_hash,
      plan_hash: digest("exclusive-plan"),
      store_binding_digest: digest("exclusive-store-binding"),
      trust_binding_digest: digest("exclusive-trust-binding"),
      trust_head_digest: digest("exclusive-trust-head"),
      signer_owner_custody_digest: digest("exclusive-signer-custody"),
    };
    let rawPort = open(h, domain, nucleus.nucleus_hash);
    let consumerPort = claimProductionPhysicalExperimentMonotonicOwner(rawPort, claimBinding);
    assert.equal(assertProductionPhysicalExperimentMonotonicOwnerPort(consumerPort), consumerPort);
    assert.equal(readProductionPhysicalExperimentMonotonicOwnerState(consumerPort), null);
    assert.throws(
      () => readPhysicalMonotonicOwnerState(rawPort),
      /exclusively claimed/u,
    );
    assert.throws(
      () => compareAndSetPhysicalMonotonicOwnerState(rawPort, null, { generation: 1 }),
      /exclusively claimed/u,
    );

    const zero = "0".repeat(64);
    const committedZero = {
      monotonic_revision: 1,
      monotonic_position: 0,
      monotonic_value_digest: zero,
      phase: "committed",
    };
    assert.equal(
      compareAndSetProductionPhysicalExperimentMonotonicOwnerState(
        consumerPort,
        null,
        committedZero,
      ),
      true,
    );
    const committedOne = {
      monotonic_revision: 2,
      monotonic_position: 1,
      monotonic_value_digest: digest("committed-position-1"),
      phase: "committed",
    };
    assert.equal(
      compareAndSetProductionPhysicalExperimentMonotonicOwnerState(
        consumerPort,
        committedZero,
        committedOne,
      ),
      true,
    );
    assert.throws(
      () => compareAndSetProductionPhysicalExperimentMonotonicOwnerState(
        consumerPort,
        committedOne,
        {
          ...committedOne,
          monotonic_revision: 3,
          monotonic_position: 0,
          monotonic_value_digest: zero,
        },
      ),
      /regresses, skips, or rewrites/u,
    );
    assert.throws(
      () => compareAndSetProductionPhysicalExperimentMonotonicOwnerState(
        consumerPort,
        committedOne,
        {
          ...committedOne,
          monotonic_revision: 3,
          monotonic_position: 1,
          monotonic_value_digest: digest("rewritten-position-1"),
        },
      ),
      /regresses, skips, or rewrites/u,
    );
    assert.throws(
      () => compareAndSetProductionPhysicalExperimentMonotonicOwnerState(
        consumerPort,
        committedOne,
        {
          ...committedOne,
          monotonic_revision: 3,
          monotonic_position: 3,
          monotonic_value_digest: digest("skipped-position-2"),
        },
      ),
      /regresses, skips, or rewrites/u,
    );

    rawPort = open(h, domain, nucleus.nucleus_hash);
    assert.throws(
      () => compareAndSetPhysicalMonotonicOwnerState(rawPort, committedOne, committedZero),
      /exclusively claimed/u,
    );
    assert.throws(
      () => claimProductionPhysicalExperimentMonotonicOwner(rawPort, {
        ...claimBinding,
        plan_hash: digest("wrong-exclusive-plan"),
      }),
      /consumer binding drifted/u,
    );
    consumerPort = claimProductionPhysicalExperimentMonotonicOwner(rawPort, claimBinding);
    assert.deepEqual(
      readProductionPhysicalExperimentMonotonicOwnerState(consumerPort),
      committedOne,
    );
    assert.throws(
      () => claimProductionPhysicalExperimentMonotonicOwner(rawPort, {
        ...claimBinding,
        trust_head_digest: digest("wrong-exclusive-trust-head"),
      }),
      /consumer binding drifted/u,
    );
  });
