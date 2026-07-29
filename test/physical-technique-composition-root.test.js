"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");

const {
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const {
  assertProductionPhysicalTechniqueCompositionRoot,
  assertTestPhysicalTechniqueCompositionRoot,
  createProductionPhysicalTechniqueCompositionRoot,
  createTestPhysicalTechniqueCompositionRoot,
  describeTestPhysicalTechniqueCompositionRoot,
  executeProductionPhysicalTechniqueCompositionRoot,
  executeTestPhysicalTechniqueCompositionRoot,
} = require("../mcp/lib/physical-technique-composition-root.js");
const {
  createProductionPhysicalTechniqueExecutionPort,
  normalizePhysicalTechniqueExecutionResult,
} = require("../mcp/lib/physical-technique-runtime.js");

const digest = (label) => hashCanonicalJson({ label });

function enrollment(label, overrides = {}) {
  const kind = overrides.kind || "test_physical_technique_enrollment";
  const basis = {
    version: 1,
    kind,
    target_domain: `${label}.physical-technique.example`,
    family: "physical_observe",
    execution_ref: `physical-execution:${label}`,
    cell_ref: `physical-cell:${label}`,
    assignment_context_digest: digest(`${label}-assignment`),
    session_nucleus_hash: digest(`${label}-nucleus`),
    physical_scope_axis_digest: digest(`${label}-physical-axis`),
    technique_cell_id: `PH-C1-${label}`,
    signed_attempt_ref: `attempt:${label}`,
    attempt_ref: `physical-attempt:${label}`,
    technique_id: "credential.discovery",
    signed_grant_digest: digest(`${label}-signed-grant`),
    execution_request_digest: digest(`${label}-execution-request`),
    execution_lineage_digest: digest(`${label}-lineage`),
    composition_binding_digest: digest(`${label}-composition-binding`),
    ...overrides,
  };
  delete basis.admission_binding_digest;
  const domain = kind === "production_physical_technique_enrollment"
    ? "hacker-bob/production-physical-technique-composition-enrollment/v1"
    : "hacker-bob/test-only-physical-technique-composition-enrollment/v1";
  return {
    ...basis,
    admission_binding_digest: hashCanonicalJson({ domain, ...basis }),
  };
}

function request(enrolled, overrides = {}) {
  return {
    target_domain: enrolled.target_domain,
    family: enrolled.family,
    execution_ref: enrolled.execution_ref,
    cell_ref: enrolled.cell_ref,
    assignment_context_digest: enrolled.assignment_context_digest,
    session_nucleus_hash: enrolled.session_nucleus_hash,
    physical_scope_axis_digest: enrolled.physical_scope_axis_digest,
    ...overrides,
  };
}

function outcome(enrolled, overrides = {}) {
  return {
    version: 1,
    kind: "test_physical_technique_composition_outcome",
    ...request(enrolled),
    signed_grant_digest: enrolled.signed_grant_digest,
    execution_request_digest: enrolled.execution_request_digest,
    execution_lineage_digest: enrolled.execution_lineage_digest,
    attempt_ref: enrolled.attempt_ref,
    technique_id: enrolled.technique_id,
    execution_disposition: "stimulus_recorded",
    residual_effect_state: "restored",
    instrument_receipt_ref: `physical-execution-receipt:${enrolled.execution_ref.split(":")[1]}`,
    observation_refs: [`physical-observation:${enrolled.execution_ref.split(":")[1]}`],
    artifact_refs: [`artifact:${enrolled.execution_ref.split(":")[1]}`],
    verification_input_ref: `physical-verification-input:${enrolled.execution_ref.split(":")[1]}`,
    completion_evidence_digest: digest(`${enrolled.execution_ref}-completion`),
    cleanup_evidence_digest: digest(`${enrolled.execution_ref}-cleanup`),
    terminal_state: "closed",
    evidence_commit_state: "durable",
    cleanup_state: "restored",
    ...overrides,
  };
}

function createTestRoot(label, execute, enrollmentOverrides = {}) {
  const enrolled = enrollment(label, enrollmentOverrides);
  return {
    enrolled,
    root: createTestPhysicalTechniqueCompositionRoot({
      version: 1,
      enrollment: enrolled,
      execute,
    }),
  };
}

function fakeProductionInput(label, overrides = {}) {
  const enrolled = enrollment(label, { kind: "production_physical_technique_enrollment" });
  return {
    version: 1,
    enrollment: enrolled,
    provider_dispatch_bridge: Object.freeze({
      version: 1,
      production_ready: true,
      readiness() {
        return { production_ready: true };
      },
    }),
    provider_worker_vault_root: Object.freeze({
      version: 1,
      production_ready: true,
      execute() {},
    }),
    transaction_capability: Object.freeze({ production_ready: true }),
    ...overrides,
  };
}

test("missing runtime module edge is replaced by a private root assertion", () => {
  assert.throws(
    () => createProductionPhysicalTechniqueExecutionPort({
      composition_roots: [Object.freeze({})],
    }),
    (error) => error.code === "physical_technique_composition_root_untrusted"
      && error.code !== "MODULE_NOT_FOUND",
  );
});

test("production composition input is closed and rejects proxies, getters, and public primitives", () => {
  const proxied = new Proxy(fakeProductionInput("proxy-input"), {
    ownKeys() {
      throw new Error("proxy trap must not run");
    },
  });
  assert.throws(
    () => createProductionPhysicalTechniqueCompositionRoot(proxied),
    (error) => error.code === "physical_technique_composition_contract_invalid",
  );

  let getterCalls = 0;
  const getterInput = fakeProductionInput("getter-input");
  Object.defineProperty(getterInput, "provider_dispatch_bridge", {
    enumerable: true,
    get() {
      getterCalls += 1;
      throw new Error("getter must not run");
    },
  });
  assert.throws(
    () => createProductionPhysicalTechniqueCompositionRoot(getterInput),
    (error) => error.code === "physical_technique_composition_contract_invalid",
  );
  assert.equal(getterCalls, 0);

  for (const forbidden of [
    ["provider_id", "chameleon_ultra"],
    ["raw_command", Buffer.from([1, 2, 3])],
    ["execute", () => undefined],
    ["module_path", "/tmp/provider.js"],
    ["production_ready", true],
  ]) {
    assert.throws(
      () => createProductionPhysicalTechniqueCompositionRoot({
        ...fakeProductionInput(`forbidden-${forbidden[0]}`),
        [forbidden[0]]: forbidden[1],
      }),
      (error) => error.code === "physical_technique_composition_contract_invalid",
    );
  }
});

test("frozen duck types and test roots never acquire production authority", async () => {
  assert.throws(
    () => createProductionPhysicalTechniqueCompositionRoot(fakeProductionInput("duck")),
    (error) => error.code === "physical_technique_provider_dispatch_untrusted",
  );

  const { enrolled, root } = createTestRoot(
    "categorical-test-root",
    async () => outcome(enrolled),
  );
  assertTestPhysicalTechniqueCompositionRoot(root);
  assert.throws(
    () => assertProductionPhysicalTechniqueCompositionRoot(root),
    (error) => error.code === "physical_technique_composition_root_untrusted",
  );
  await assert.rejects(
    () => executeProductionPhysicalTechniqueCompositionRoot(root, request(enrolled)),
    (error) => error.code === "physical_technique_composition_root_untrusted",
  );
  assert.throws(
    () => createProductionPhysicalTechniqueExecutionPort({ composition_roots: [root] }),
    (error) => error.code === "physical_technique_composition_root_untrusted",
  );
});

test("qualified dependencies cannot bypass the worker-vault production spine", () => {
  // Run in an isolated process so hostile dependency-cache substitution cannot
  // affect any other test. The doubles model a future state in which both
  // private component assertions report fully qualified. Production execution
  // must still stop before either the legacy dispatch callback path or an
  // independently invoked worker transaction can cause a physical effect.
  const target = path.resolve(__dirname, "../mcp/lib/physical-technique-composition-root.js");
  const dispatchTarget = path.resolve(
    __dirname,
    "../packages/bob-instrument-broker/lib/physical-provider-dispatch.js",
  );
  const workerTarget = path.resolve(
    __dirname,
    "../packages/bob-instrument-broker/lib/provider-worker-vault-composition.js",
  );
  const script = `
    "use strict";
    const assert = require("node:assert/strict");
    const { hashCanonicalJson } = require(${JSON.stringify(
      path.resolve(__dirname, "../mcp/lib/verification-contracts.js"),
    )});
    const target = ${JSON.stringify(target)};
    const dispatchTarget = ${JSON.stringify(dispatchTarget)};
    const workerTarget = ${JSON.stringify(workerTarget)};
    const digest = (label) => hashCanonicalJson({ label });
    const calls = {
      dispatch_assert: 0,
      dispatch_project: 0,
      dispatch_execute: 0,
      worker_assert: 0,
      worker_readiness: 0,
      capability_assert: 0,
      worker_execute: 0,
    };
    const binding = Object.freeze({
      session_nucleus_hash: digest("spine-nucleus"),
      physical_scope_axis_digest: digest("spine-axis"),
      technique_cell_id: "PH-O0-spine",
      attempt_ref: "attempt:spine",
      signed_grant_digest: digest("spine-grant"),
      execution_request_digest: digest("spine-request"),
      execution_lineage_digest: digest("spine-lineage"),
      composition_binding_digest: digest("spine-composition"),
      dispatch_phase: "held",
      production_qualification: "qualified",
      production_blockers: Object.freeze([]),
    });
    const bridge = Object.freeze({ kind: "hostile-qualified-dispatch-double" });
    const transactionCapability = Object.freeze({ kind: "hostile-qualified-capability-double" });
    const workerRoot = Object.freeze({
      production_ready: true,
      hardware_access_authorized: true,
      execution_authority: true,
      execution_lineage_digest: binding.execution_lineage_digest,
      readiness() {
        calls.worker_readiness += 1;
        return Object.freeze({
          production_ready: true,
          hardware_access_authorized: true,
          execution_authority: true,
          requirements: Object.freeze([]),
        });
      },
      execute() {
        calls.worker_execute += 1;
        throw new Error("worker transaction must not run independently");
      },
    });
    const dispatchDouble = Object.freeze({
      assertPhysicalProviderDispatchBridge(value) {
        calls.dispatch_assert += 1;
        assert.equal(value, bridge);
        return value;
      },
      projectPhysicalProviderDispatchCompositionBinding(value) {
        calls.dispatch_project += 1;
        assert.equal(value, bridge);
        return binding;
      },
      async executePhysicalProviderDispatchComposition(value) {
        calls.dispatch_execute += 1;
        assert.equal(value, bridge);
        throw new Error("legacy dispatch must be unreachable");
      },
    });
    const workerDouble = Object.freeze({
      assertProviderWorkerVaultCompositionRoot(value) {
        calls.worker_assert += 1;
        assert.equal(value, workerRoot);
        return value;
      },
      assertProviderWorkerVaultProductionTransactionCapability(root, capability) {
        calls.capability_assert += 1;
        assert.equal(root, workerRoot);
        assert.equal(capability, transactionCapability);
        return capability;
      },
    });
    require.cache[dispatchTarget] = {
      id: dispatchTarget,
      filename: dispatchTarget,
      loaded: true,
      exports: dispatchDouble,
      children: [],
      paths: [],
    };
    require.cache[workerTarget] = {
      id: workerTarget,
      filename: workerTarget,
      loaded: true,
      exports: workerDouble,
      children: [],
      paths: [],
    };
    const composition = require(target);
    const enrollmentBasis = {
      version: 1,
      kind: "production_physical_technique_enrollment",
      target_domain: "spine.physical-technique.example",
      family: "physical_observe",
      execution_ref: "physical-execution:spine",
      cell_ref: "physical-cell:spine",
      assignment_context_digest: digest("spine-assignment"),
      session_nucleus_hash: binding.session_nucleus_hash,
      physical_scope_axis_digest: binding.physical_scope_axis_digest,
      technique_cell_id: binding.technique_cell_id,
      signed_attempt_ref: binding.attempt_ref,
      attempt_ref: "physical-attempt:spine",
      technique_id: "credential.discovery",
      signed_grant_digest: binding.signed_grant_digest,
      execution_request_digest: binding.execution_request_digest,
      execution_lineage_digest: binding.execution_lineage_digest,
      composition_binding_digest: binding.composition_binding_digest,
    };
    const enrollment = Object.freeze({
      ...enrollmentBasis,
      admission_binding_digest: hashCanonicalJson({
        domain: "hacker-bob/production-physical-technique-composition-enrollment/v1",
        ...enrollmentBasis,
      }),
    });
    const executionRequest = Object.freeze({
      target_domain: enrollment.target_domain,
      family: enrollment.family,
      execution_ref: enrollment.execution_ref,
      cell_ref: enrollment.cell_ref,
      assignment_context_digest: enrollment.assignment_context_digest,
      session_nucleus_hash: enrollment.session_nucleus_hash,
      physical_scope_axis_digest: enrollment.physical_scope_axis_digest,
    });
    (async () => {
      const root = composition.createProductionPhysicalTechniqueCompositionRoot({
        version: 1,
        enrollment,
        provider_dispatch_bridge: bridge,
        provider_worker_vault_root: workerRoot,
        transaction_capability: transactionCapability,
      });
      let first;
      try {
        await composition.executeProductionPhysicalTechniqueCompositionRoot(
          root,
          executionRequest,
        );
      } catch (error) {
        first = error;
      }
      assert.equal(first.code, "physical_technique_production_execution_spine_unavailable");
      assert.deepEqual(first.production_blockers, [
        "provider_worker_vault_dispatch_transaction_owner_missing",
        "provider_worker_vault_terminal_projection_owner_missing",
      ]);
      assert.equal(calls.dispatch_execute, 0);
      assert.equal(calls.worker_execute, 0);
      const afterFirst = { ...calls };
      await assert.rejects(
        () => composition.executeProductionPhysicalTechniqueCompositionRoot(
          root,
          executionRequest,
        ),
        (error) => error.code === "physical_technique_composition_replay",
      );
      assert.deepEqual(calls, afterFirst);
      process.stdout.write(JSON.stringify(calls));
    })().catch((error) => {
      process.stderr.write(error && error.stack ? error.stack : String(error));
      process.exitCode = 1;
    });
  `;
  const child = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), {
    dispatch_assert: 2,
    dispatch_project: 2,
    dispatch_execute: 0,
    worker_assert: 2,
    worker_readiness: 2,
    capability_assert: 2,
    worker_execute: 0,
  });
});

test("test root exposes only a digest-bound data handle and describes exact runtime identity", () => {
  const enrolled = enrollment("closed-surface");
  const root = createTestPhysicalTechniqueCompositionRoot({
    version: 1,
    enrollment: enrolled,
    execute: () => outcome(enrolled),
  });
  assert.deepEqual(Object.keys(root).sort(), ["kind", "root_binding_digest", "version"]);
  const serialized = JSON.stringify(root);
  for (const forbidden of [
    "provider_id",
    "command",
    "bytes",
    "callback",
    "module_path",
    "production_ready",
  ]) assert.equal(serialized.includes(forbidden), false, `root leaked ${forbidden}`);
  assert.deepEqual(describeTestPhysicalTechniqueCompositionRoot(root), request(enrolled));

  // A process-rehydrated or spread copy retains data but never the private
  // brand/state required to resume the one-use admission.
  const restartedClone = JSON.parse(serialized);
  assert.throws(
    () => assertTestPhysicalTechniqueCompositionRoot(restartedClone),
    (error) => error.code === "physical_technique_composition_root_untrusted",
  );
});

test("test execution yields only the report-safe projection after durable evidence and cleanup", async () => {
  const enrolled = enrollment("successful-execution");
  let calls = 0;
  const root = createTestPhysicalTechniqueCompositionRoot({
    version: 1,
    enrollment: enrolled,
    execute: async (boundRequest) => {
      calls += 1;
      assert.deepEqual(boundRequest, request(enrolled));
      return outcome(enrolled);
    },
  });
  const result = await executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled));
  assert.equal(calls, 1);
  assert.equal(result.execution_disposition, "stimulus_recorded");
  assert.equal(result.residual_effect_state, "restored");
  assert.equal(result.execution_ref, enrolled.execution_ref);
  assert.equal(result.session_nucleus_hash, enrolled.session_nucleus_hash);
  assert.equal(Object.hasOwn(result, "provider_id"), false);
  assert.equal(Object.hasOwn(result, "completion_evidence_digest"), false);
  assert.equal(Object.hasOwn(result, "cleanup_evidence_digest"), false);
  assert.deepEqual(normalizePhysicalTechniqueExecutionResult(result, {
    family: enrolled.family,
    execution_ref: enrolled.execution_ref,
    cell_ref: enrolled.cell_ref,
    assignment_context_digest: enrolled.assignment_context_digest,
    session_nucleus_hash: enrolled.session_nucleus_hash,
  }), result);
});

test("request identity drift fails before execution and exact identity remains usable", async () => {
  const enrolled = enrollment("request-drift");
  let calls = 0;
  const root = createTestPhysicalTechniqueCompositionRoot({
    version: 1,
    enrollment: enrolled,
    execute: () => {
      calls += 1;
      return outcome(enrolled);
    },
  });
  await assert.rejects(
    () => executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled, {
      assignment_context_digest: digest("transplanted-assignment"),
    })),
    (error) => error.code === "physical_technique_composition_binding_drift",
  );
  assert.equal(calls, 0);
  await executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled));
  assert.equal(calls, 1);
});

test("outcome identity transplant fails closed and consumes the one-use admission", async () => {
  const enrolled = enrollment("outcome-drift");
  const other = enrollment("outcome-drift-other");
  const root = createTestPhysicalTechniqueCompositionRoot({
    version: 1,
    enrollment: enrolled,
    execute: () => outcome(enrolled, {
      execution_ref: other.execution_ref,
      cell_ref: other.cell_ref,
    }),
  });
  await assert.rejects(
    () => executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled)),
    (error) => error.code === "physical_technique_composition_binding_drift",
  );
  await assert.rejects(
    () => executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled)),
    (error) => error.code === "physical_technique_composition_replay",
  );
});

test("cross-binding admission transplant and duplicate restart enrollment are rejected", () => {
  const enrolled = enrollment("cross-binding");
  const transplanted = enrollment("cross-binding", {
    composition_binding_digest: digest("another-composition"),
    admission_binding_digest: enrolled.admission_binding_digest,
  });
  // Preserve the old digest explicitly: the identity/composition mutation must
  // not be accepted merely because every scalar still has a valid shape.
  transplanted.admission_binding_digest = enrolled.admission_binding_digest;
  assert.throws(
    () => createTestPhysicalTechniqueCompositionRoot({
      version: 1,
      enrollment: transplanted,
      execute: () => outcome(transplanted),
    }),
    (error) => error.code === "physical_technique_composition_binding_drift",
  );

  const first = enrollment("duplicate-restart");
  createTestPhysicalTechniqueCompositionRoot({
    version: 1,
    enrollment: first,
    execute: () => outcome(first),
  });
  assert.throws(
    () => createTestPhysicalTechniqueCompositionRoot({
      version: 1,
      enrollment: { ...first },
      execute: () => outcome(first),
    }),
    (error) => error.code === "physical_technique_composition_replay",
  );
});

test("Proxy/getter outcomes and missing cleanup or evidence fail closed", async (t) => {
  await t.test("Proxy outcome", async () => {
    const enrolled = enrollment("proxy-outcome");
    const root = createTestPhysicalTechniqueCompositionRoot({
      version: 1,
      enrollment: enrolled,
      execute: () => new Proxy(outcome(enrolled), {
        ownKeys() {
          throw new Error("proxy trap must not run");
        },
      }),
    });
    await assert.rejects(
      () => executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled)),
      (error) => error.code === "physical_technique_composition_contract_invalid",
    );
  });

  await t.test("getter outcome", async () => {
    const enrolled = enrollment("getter-outcome");
    let getterCalls = 0;
    const hostile = outcome(enrolled);
    Object.defineProperty(hostile, "completion_evidence_digest", {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("getter must not run");
      },
    });
    const root = createTestPhysicalTechniqueCompositionRoot({
      version: 1,
      enrollment: enrolled,
      execute: () => hostile,
    });
    await assert.rejects(
      () => executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled)),
      (error) => error.code === "physical_technique_composition_contract_invalid",
    );
    assert.equal(getterCalls, 0);
  });

  for (const [label, override, code] of [
    ["missing-evidence", { completion_evidence_digest: null },
      "physical_technique_composition_contract_invalid"],
    ["missing-cleanup", { cleanup_state: "quarantined" },
      "physical_technique_composition_cleanup_missing"],
    ["unresolved-effect", { residual_effect_state: "unknown" },
      "physical_technique_composition_evidence_missing"],
  ]) {
    await t.test(label, async () => {
      const enrolled = enrollment(label);
      const root = createTestPhysicalTechniqueCompositionRoot({
        version: 1,
        enrollment: enrolled,
        execute: () => outcome(enrolled, override),
      });
      await assert.rejects(
        () => executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled)),
        (error) => error.code === code,
      );
    });
  }
});

test("successful execution and concurrent execution are strictly one-use", async () => {
  const enrolled = enrollment("one-use");
  let release;
  const pending = new Promise((resolve) => {
    release = resolve;
  });
  const root = createTestPhysicalTechniqueCompositionRoot({
    version: 1,
    enrollment: enrolled,
    execute: async () => {
      await pending;
      return outcome(enrolled);
    },
  });
  const first = executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled));
  await assert.rejects(
    () => executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled)),
    (error) => error.code === "physical_technique_composition_replay",
  );
  release();
  await first;
  await assert.rejects(
    () => executeTestPhysicalTechniqueCompositionRoot(root, request(enrolled)),
    (error) => error.code === "physical_technique_composition_replay",
  );
});
