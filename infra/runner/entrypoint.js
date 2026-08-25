"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const PAYLOAD_MAX_BYTES = 32 * 1024;
const STDERR_TAIL_MAX_BYTES = 2 * 1024;
const REPOSITORY_PATH = "/workspace/target-repo";
const ID_RE = /^[A-Za-z0-9_-]{10,128}$/;
const RUN_SLUG_RE = /^[A-Za-z0-9_-]{16,64}$/;
const TARGET_DOMAIN_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const SOURCE_COMMIT_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const EVM_TARGET_RE = /^eip155:([1-9][0-9]*):(0x[0-9a-f]{40})$/;
const REPOSITORY_RE = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\.git$/;
const PROJECTION_KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const CODEX_FORWARD_ENVIRONMENT = Object.freeze([
  "DEEPSEEK_API_KEY",
  "BOB_SESSIONS_ROOT",
  "BOB_PROJECTION_URL",
  "BOB_RUN_SLUG",
  "BOB_PROJECTION_KEY",
  "BOB_RUN_KIND",
  "BOB_RETEST_OF",
  "BOB_REPORT_SLUG",
  "RUNNER_SECRET",
]);

const PAYLOAD_KEYS = Object.freeze([
  "schemaVersion",
  "assessmentId",
  "runId",
  "runSlug",
  "target",
  "targetDomain",
  "targetKind",
  "runMode",
  "autonomy",
  "objective",
  "scope",
  "sourceRef",
  "kind",
  "retestOf",
]);

const LIFECYCLE_EVENTS = Object.freeze({
  SETUP: Object.freeze({ kind: "wait", register: "body", phase: "setup", message: "Session setup started." }),
  OPEN_FRONTIER: Object.freeze({ kind: "frontier", register: "breath", phase: "open frontier", message: "The assessment frontier is open." }),
  CLAIM_FREEZE: Object.freeze({ kind: "freeze", register: "strike", phase: "claim freeze", message: "The verified claim set is frozen." }),
  VERIFY: Object.freeze({ kind: "verify", register: "body", phase: "verify", message: "Independent verification is running." }),
  GRADE: Object.freeze({ kind: "grade", register: "body", phase: "grade", message: "Verified claims are being graded." }),
  REPORT: Object.freeze({ kind: "report", register: "strike", phase: "report", message: "The sealed report is being finalized." }),
});
const LIFECYCLE_ORDER = Object.freeze([
  "SETUP",
  "OPEN_FRONTIER",
  "CLAIM_FREEZE",
  "VERIFY",
  "GRADE",
  "REPORT",
]);
const LIFECYCLE_BY_PHASE = Object.freeze({
  setup: "SETUP",
  "open frontier": "OPEN_FRONTIER",
  "claim freeze": "CLAIM_FREEZE",
  verify: "VERIFY",
  grade: "GRADE",
  report: "REPORT",
});

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function exactHttpsEndpoint(value, pathname) {
  if (typeof value !== "string" || value.length === 0) return false;
  try {
    const endpoint = new URL(value);
    return (
      endpoint.protocol === "https:" &&
      endpoint.hostname.length > 0 &&
      endpoint.username === "" &&
      endpoint.password === "" &&
      endpoint.port === "" &&
      endpoint.search === "" &&
      endpoint.hash === "" &&
      endpoint.pathname === pathname
    );
  } catch {
    return false;
  }
}

function codexEnvironment(environment = process.env) {
  const result = {
    PATH: "/opt/codex-runtime/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: "/workspace",
    CODEX_HOME: "/opt/codex-home",
  };
  for (const name of CODEX_FORWARD_ENVIRONMENT) {
    const value = environment[name];
    if (typeof value === "string" && (value.length > 0 || name === "BOB_RETEST_OF")) result[name] = value;
  }
  return result;
}

function assertPlainObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requiredText(value, label, maxLength) {
  if (typeof value !== "string") throw new Error(`${label} must be a string`);
  const normalized = value.trim();
  if (
    !normalized ||
    value !== normalized ||
    normalized.length > maxLength ||
    /[\u0000-\u001f\u007f-\u009f]/.test(normalized)
  ) {
    throw new Error(`${label} is invalid`);
  }
  return normalized;
}

function parsePayloadJson(serialized = process.env.BOB_PAYLOAD_JSON) {
  if (typeof serialized !== "string" || serialized.length === 0) {
    throw new Error("BOB_PAYLOAD_JSON is required");
  }
  if (Buffer.byteLength(serialized, "utf8") > PAYLOAD_MAX_BYTES) {
    throw new Error(`BOB_PAYLOAD_JSON exceeds ${PAYLOAD_MAX_BYTES} bytes`);
  }
  let candidate;
  try {
    candidate = JSON.parse(serialized);
  } catch {
    throw new Error("BOB_PAYLOAD_JSON must contain valid JSON");
  }
  const payload = assertPlainObject(candidate, "runner payload");
  for (const key of Object.keys(payload)) {
    if (!PAYLOAD_KEYS.includes(key)) throw new Error(`runner payload contains unsupported field: ${key}`);
  }
  if (payload.schemaVersion !== 1) throw new Error("runner payload schemaVersion must equal 1");
  const normalized = {
    schemaVersion: 1,
    assessmentId: requiredText(payload.assessmentId, "assessmentId", 128),
    runId: requiredText(payload.runId, "runId", 128),
    runSlug: requiredText(payload.runSlug, "runSlug", 64),
    target: requiredText(payload.target, "target", 2048),
    targetDomain: requiredText(payload.targetDomain, "targetDomain", 256),
    targetKind: payload.targetKind,
    runMode: requiredText(payload.runMode, "runMode", 80),
    autonomy: payload.autonomy,
    objective: requiredText(payload.objective, "objective", 4000),
    kind: payload.kind,
    retestOf: payload.retestOf,
  };
  if (!ID_RE.test(normalized.assessmentId)) throw new Error("assessmentId has an invalid format");
  if (!ID_RE.test(normalized.runId)) throw new Error("runId has an invalid format");
  if (!RUN_SLUG_RE.test(normalized.runSlug)) throw new Error("runSlug has an invalid format");
  if (!TARGET_DOMAIN_RE.test(normalized.targetDomain)) throw new Error("targetDomain has an invalid format");
  if (!['web', 'repo', 'contract'].includes(normalized.targetKind)) throw new Error("targetKind is unsupported");
  if (normalized.autonomy !== "operator-approved") throw new Error("autonomy must be operator-approved");
  if (!['assessment', 'retest'].includes(normalized.kind)) throw new Error("kind is unsupported");
  if (
    !Array.isArray(normalized.retestOf) ||
    normalized.retestOf.length > 100 ||
    normalized.retestOf.some((value) => typeof value !== "string" || !SHA256_RE.test(value)) ||
    new Set(normalized.retestOf).size !== normalized.retestOf.length
  ) {
    throw new Error("retestOf must be a bounded array of unique SHA-256 fingerprints");
  }
  if (
    (normalized.kind === "assessment" && normalized.retestOf.length !== 0) ||
    (normalized.kind === "retest" && normalized.retestOf.length === 0)
  ) {
    throw new Error("kind and retestOf do not match");
  }
  if (payload.scope !== undefined) {
    const scope = assertPlainObject(payload.scope, "scope");
    if (Object.keys(scope).some((key) => key !== "notes")) throw new Error("scope contains unsupported fields");
    normalized.scope = { notes: requiredText(scope.notes, "scope.notes", 4000) };
  }
  if (payload.sourceRef !== undefined) {
    normalized.sourceRef = requiredText(payload.sourceRef, "sourceRef", 512);
  }
  if (normalized.targetKind !== "repo" && normalized.sourceRef !== undefined) {
    throw new Error("sourceRef is only allowed for repo targets");
  }
  if (normalized.targetKind === "web") {
    let url;
    try {
      url = new URL(normalized.target);
    } catch {
      throw new Error("web target must be a valid URL");
    }
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.port !== "" ||
      url.hostname !== normalized.targetDomain
    ) {
      throw new Error("web target must be HTTPS without userinfo or a port and match targetDomain");
    }
  } else if (normalized.targetKind === "repo") {
    const match = REPOSITORY_RE.exec(normalized.target);
    if (!match || match[1] === "." || match[1] === ".." || match[2] === "." || match[2] === "..") {
      throw new Error("repo target must be an exact canonical GitHub clone URL");
    }
    if (!SOURCE_COMMIT_RE.test(normalized.sourceRef || "")) {
      throw new Error("repo sourceRef must be an exact commit");
    }
    if (normalized.targetDomain !== repositorySelector(normalized.target, match[2])) {
      throw new Error("repo targetDomain does not match its canonical selector");
    }
  } else {
    const match = EVM_TARGET_RE.exec(normalized.target);
    if (!match || !Number.isSafeInteger(Number(match[1])) || Number(match[1]) <= 0) {
      throw new Error("contract target must be a canonical EVM CAIP-10 identity");
    }
    if (normalized.targetDomain !== contractSelector(match[1], match[2])) {
      throw new Error("contract targetDomain does not match its canonical selector");
    }
  }
  return normalized;
}

function repositorySelector(target, repositoryName) {
  const safeName = repositoryName.replace(/[^A-Za-z0-9._-]+/gu, "-").replace(/^-+|-+$/gu, "") || "repo";
  return `repo-${safeName}-${sha256Hex(target).slice(0, 8)}`;
}

function contractSelector(chainId, address) {
  const authority = JSON.stringify([["evm", chainId, address]]);
  return `sc-evm-${chainId}-${address.slice(2, 10)}-${sha256Hex(authority).slice(0, 8)}`;
}

function contractTuple(target) {
  const match = EVM_TARGET_RE.exec(target);
  if (!match) throw new Error("contract target must be an EVM CAIP-10 identity");
  return {
    chain_family: "evm",
    chain_id: match[1],
    address: match[2],
  };
}

function initialToolCall(payload) {
  if (payload.targetKind === "web") {
    return {
      name: "bob_init_session",
      args: {
        target_domain: payload.targetDomain,
        target_url: payload.target,
        deep_mode: payload.runMode === "deep",
      },
    };
  }
  if (payload.targetKind === "repo") {
    return {
      name: "bob_init_repo_session",
      args: {
        repo_path: REPOSITORY_PATH,
        target_domain: payload.targetDomain,
        source_url: payload.target,
        ...(payload.sourceRef ? { commit: payload.sourceRef } : {}),
        deep_mode: payload.runMode === "deep",
      },
    };
  }
  return {
    name: "bob_init_contract_session",
    args: {
      contracts: [contractTuple(payload.target)],
      deep_mode: payload.runMode === "deep",
    },
  };
}

function taskFor(payload) {
  const first = initialToolCall(payload);
  const scope = payload.scope ? `\nAuthorized scope notes: ${payload.scope.notes}` : "";
  return (
    `Run one authorized automated Hacker Bob ${payload.kind}.\n` +
    `Your first action MUST be the Bob MCP call ${first.name}(${JSON.stringify(first.args)}).\n` +
    `Require that call to return target_domain exactly ${JSON.stringify(payload.targetDomain)}; stop on any mismatch.\n` +
    `Objective: ${payload.objective}${scope}\n` +
    `Drive the full six-state lifecycle using only Bob MCP tools and finish with ` +
    `bob_finalize_report for target_domain ${JSON.stringify(payload.targetDomain)}.`
  );
}

function makeConvexClient() {
  const url = requiredEnvironment("BOB_CONVEX_URL");
  const runtimeRequire = require("module").createRequire("/opt/bob-runner/runtime/package.json");
  const { ConvexClient } = runtimeRequire("convex/browser");
  return new ConvexClient(url);
}

function sessionDirectory(domain) {
  return path.join(
    process.env.BOB_SESSIONS_ROOT || "/workspace/hacker-bob-sessions",
    domain,
  );
}

function sessionStateFor(domain) {
  try {
    return JSON.parse(fs.readFileSync(path.join(sessionDirectory(domain), "state.json"), "utf8"));
  } catch {
    return null;
  }
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalEventHash(runSlug, kind, phase, message) {
  return sha256Hex(JSON.stringify({ runSlug, kind, phase, message }));
}

const RESTART_FORWARD_STATUS_RANK = Object.freeze({
  provisioning: 0,
  running: 1,
  sealing: 2,
  sealed: 3,
});

function acceptsRunTransition(requested, current) {
  if (requested === current) return true;
  const requestedRank = RESTART_FORWARD_STATUS_RANK[requested];
  const currentRank = RESTART_FORWARD_STATUS_RANK[current];
  return requestedRank !== undefined
    && currentRank !== undefined
    && currentRank >= requestedRank;
}

async function transitionRun(client, secret, runSlug, status, phase) {
  const result = await client.mutation("runs:setStatus", {
    secret,
    slug: runSlug,
    status,
    phase,
  });
  if (!result || !acceptsRunTransition(status, result.status)) {
    throw new Error(`run status transition to ${status} was not accepted`);
  }
  return result;
}
async function resumeLifecycleTracker(client, runSlug) {
  const events = await client.query("runs:events", { slug: runSlug });
  if (!Array.isArray(events)) throw new Error("run event history returned an invalid result");
  let seq = 0;
  let phase = "setup";
  const emittedLifecycle = new Set();
  for (const event of events) {
    if (!event || !Number.isSafeInteger(event.seq) || event.seq < 1) {
      throw new Error("run event history contains an invalid sequence");
    }
    const lifecycleIndex = LIFECYCLE_ORDER.indexOf(LIFECYCLE_BY_PHASE[event.phase]);
    for (let index = 0; index <= lifecycleIndex; index += 1) {
      emittedLifecycle.add(LIFECYCLE_ORDER[index]);
    }
    if (event.seq > seq) {
      seq = event.seq;
      if (typeof event.phase === "string" && event.phase.length > 0) phase = event.phase;
    }
  }
  return { seq, lifecycle: null, phase, emittedLifecycle };
}


async function appendLifecycleEvent(client, secret, runSlug, tracker, event, clock) {
  const seq = tracker.seq + 1;
  const at = clock();
  if (!Number.isSafeInteger(at) || at <= 0) throw new Error("clock returned an invalid timestamp");
  await client.mutation("runs:appendEvent", {
    secret,
    slug: runSlug,
    seq,
    kind: event.kind,
    register: event.register,
    phase: event.phase,
    eventHash: canonicalEventHash(runSlug, event.kind, event.phase, event.message),
    payloadJson: JSON.stringify({ message: event.message }),
    at,
  });
  return { ...tracker, seq, phase: event.phase };
}

async function emitPhaseEvents(client, secret, runSlug, domain, tracker, clock) {
  const state = sessionStateFor(domain);
  const lifecycle = state && typeof state.lifecycle_state === "string" ? state.lifecycle_state : null;
  if (!lifecycle || lifecycle === tracker.lifecycle) return tracker;
  const targetIndex = LIFECYCLE_ORDER.indexOf(lifecycle);
  if (targetIndex < 0) return { ...tracker, lifecycle };
  const emitted = tracker.emittedLifecycle instanceof Set
    ? tracker.emittedLifecycle
    : new Set();
  let next = tracker;
  for (let index = 0; index <= targetIndex; index += 1) {
    const candidate = LIFECYCLE_ORDER[index];
    if (emitted.has(candidate)) continue;
    next = await appendLifecycleEvent(client, secret, runSlug, next, LIFECYCLE_EVENTS[candidate], clock);
    emitted.add(candidate);
  }
  return { ...next, lifecycle, emittedLifecycle: emitted };
}

function boundedTail(current, chunk) {
  const combined = Buffer.concat([current, Buffer.from(chunk)]);
  return combined.length <= STDERR_TAIL_MAX_BYTES
    ? combined
    : combined.subarray(combined.length - STDERR_TAIL_MAX_BYTES);
}

async function runSpawnedRunner(
  child,
  poll,
  { stdout = process.stdout, stderr = process.stderr } = {},
) {
  let stderrTail = Buffer.alloc(0);
  if (child.stdout) {
    child.stdout.on("data", (chunk) => {
      stdout.write(chunk);
    });
  }
  if (child.stderr) {
    child.stderr.on("data", (chunk) => {
      stderr.write(chunk);
      stderrTail = boundedTail(stderrTail, chunk);
    });
  }
  const completion = new Promise((resolve) => {
    let settled = false;
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };
    child.once("error", (error) => finish({ error }));
    child.once("close", (code, signal) => finish({ code, signal }));
  });
  let outcome = null;
  completion.then((value) => {
    outcome = value;
  });
  try {
    while (outcome === null) {
      await poll();
      if (outcome === null) await Promise.race([completion, poll.delay()]);
    }
    await poll();
  } catch (error) {
    if (outcome === null) {
      if (typeof child.kill === "function") {
        try { child.kill("SIGKILL"); } catch {}
      }
      child.stdout?.destroy?.();
      child.stderr?.destroy?.();
      if (typeof child.unref === "function") child.unref();
    }
    throw error;
  }
  if (outcome.error) throw outcome.error;
  return {
    code: Number.isInteger(outcome.code) ? outcome.code : 1,
    signal: outcome.signal || null,
    stderrTail: stderrTail.toString("utf8"),
  };
}

function loadReceiptReader() {
  const engineRoot = process.env.BOB_ENGINE_ROOT || "/opt/hacker-bob";
  return require(path.join(engineRoot, "mcp/finalization-receipt.js")).readFinalizationReceipt;
}

function verifyFinalizationReceipt(payload) {
  const receipt = loadReceiptReader()(payload.targetDomain).receipt;
  const expectedReportSlug = `${payload.runSlug}-report`;
  if (receipt.runSlug !== payload.runSlug) throw new Error("finalization receipt runSlug mismatch");
  if (receipt.targetDomain !== payload.targetDomain) throw new Error("finalization receipt targetDomain mismatch");
  if (receipt.reportSlug !== expectedReportSlug) throw new Error("finalization receipt reportSlug mismatch");
  const projectionRequired = Boolean(process.env.BOB_PROJECTION_URL);
  if (receipt.projection.required !== projectionRequired) {
    throw new Error("finalization receipt projection requirement mismatch");
  }
  if (receipt.projection.required && !receipt.projection.succeeded) {
    throw new Error("finalization receipt does not prove successful projection");
  }

  const directory = sessionDirectory(payload.targetDomain);
  const reportPath = path.join(directory, "report.md");
  if (!fs.existsSync(reportPath)) throw new Error("finalized report is missing");
  const reportContentHash = sha256Hex(fs.readFileSync(reportPath));
  if (reportContentHash !== receipt.reportContentHash) {
    throw new Error("finalized report hash does not match receipt");
  }
  const artifactPath = path.join(directory, "finding-artifact.json");
  const sidecarPath = path.join(directory, "finding-artifact.sha256");
  const artifactPresent = fs.existsSync(artifactPath);
  const sidecarPresent = fs.existsSync(sidecarPath);
  if (!receipt.artifact.emitted) {
    if (artifactPresent || sidecarPresent) throw new Error("clean receipt conflicts with finding artifact files");
    return receipt;
  }
  if (!artifactPresent || !sidecarPresent) throw new Error("emitted finding artifact or sidecar is missing");
  const content = fs.readFileSync(artifactPath);
  const contentHash = sha256Hex(content);
  if (contentHash !== receipt.artifact.sha256) throw new Error("finding artifact hash does not match receipt");
  const sidecar = fs.readFileSync(sidecarPath, "utf8");
  if (sidecar !== `${contentHash}  finding-artifact.json\n`) {
    throw new Error("finding artifact sidecar does not match content");
  }
  let artifact;
  try {
    artifact = JSON.parse(content.toString("utf8"));
  } catch {
    throw new Error("finding artifact is not valid JSON");
  }
  if (!artifact || typeof artifact !== "object" || !Array.isArray(artifact.findings)) {
    throw new Error("finding artifact does not contain a findings array");
  }
  if (artifact.findings.length !== receipt.artifact.findingCount) {
    throw new Error("finding artifact count does not match receipt");
  }
  return receipt;
}

function pbkdf2Hash(password, saltHex, iterations) {
  return crypto
    .pbkdf2Sync(password, Buffer.from(saltHex, "hex"), iterations, 32, "sha256")
    .toString("hex");
}

async function completeHostedRun(client, secret, payload, receipt, sealedAt) {
  const accessSalt = crypto.randomBytes(16).toString("hex");
  const accessIter = 100000;
  const password = crypto.randomBytes(24).toString("hex");
  const result = await client.mutation("reports:completeHostedRun", {
    secret,
    runSlug: payload.runSlug,
    modelJson: JSON.stringify(receipt.consoleReport),
    accessHash: pbkdf2Hash(password, accessSalt, accessIter),
    accessSalt,
    accessIter,
    freezeHash: receipt.freezeHash,
    sealedAt,
  });
  if (
    !result ||
    (result.status !== "created" && result.status !== "existing") ||
    result.slug !== `${payload.runSlug}-report`
  ) {
    throw new Error("hosted completion returned an invalid result");
  }
  return result;
}

function redactFailure(value) {
  let message = value instanceof Error ? value.message : String(value);
  for (const name of [
    "RUNNER_SECRET",
    "BOB_PROJECTION_KEY",
    "DEEPSEEK_API_KEY",
    "BOB_CONVEX_URL",
  ]) {
    const secret = process.env[name];
    if (secret && secret.length >= 4) message = message.split(secret).join("[REDACTED]");
  }
  message = message
    .replace(/\b(authorization|cookie|password|secret|token|api[_-]?key|private[_-]?key)\b\s*[:=]\s*\S+/gi, "$1=[REDACTED]")
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ")
    .trim();
  return message.slice(0, STDERR_TAIL_MAX_BYTES) || "runner execution failed";
}

async function main({
  clientFactory = makeConvexClient,
  spawnFactory = spawn,
  clock = () => Date.now(),
  delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
} = {}) {
  let client = null;
  let payload = null;
  let secret = null;
  let completionCommitted = false;
  let sequenceInitialized = false;
  let exitCode = 1;
  let tracker = {
    seq: 0,
    lifecycle: null,
    phase: "setup",
    emittedLifecycle: new Set(),
  };
  try {
    payload = parsePayloadJson();
    secret = requiredEnvironment("RUNNER_SECRET");
    requiredEnvironment("DEEPSEEK_API_KEY");
    requiredEnvironment("BOB_SESSIONS_ROOT");
    const projectionKey = requiredEnvironment("BOB_PROJECTION_KEY");
    const projectionUrl = requiredEnvironment("BOB_PROJECTION_URL");
    const convexUrl = requiredEnvironment("BOB_CONVEX_URL");
    if (!PROJECTION_KEY_RE.test(projectionKey)) throw new Error("BOB_PROJECTION_KEY has an invalid format");
    if (!exactHttpsEndpoint(projectionUrl, "/api/findings")) {
      throw new Error("BOB_PROJECTION_URL must be an exact HTTPS /api/findings endpoint");
    }
    if (!exactHttpsEndpoint(convexUrl, "/")) {
      throw new Error("BOB_CONVEX_URL must be an exact HTTPS origin");
    }
    if (process.env.BOB_RUN_SLUG !== payload.runSlug) throw new Error("BOB_RUN_SLUG does not match runner payload");
    if (process.env.BOB_RUN_KIND !== payload.kind) throw new Error("BOB_RUN_KIND does not match runner payload");
    if (process.env.BOB_RETEST_OF !== payload.retestOf.join(",")) {
      throw new Error("BOB_RETEST_OF does not match runner payload");
    }
    if (process.env.BOB_REPORT_SLUG !== `${payload.runSlug}-report`) {
      throw new Error("BOB_REPORT_SLUG does not match deterministic report slug");
    }
    client = await clientFactory();
    tracker = await resumeLifecycleTracker(client, payload.runSlug);
    sequenceInitialized = true;
    await transitionRun(client, secret, payload.runSlug, "provisioning", "setup");
    await transitionRun(client, secret, payload.runSlug, "running", "open frontier");

    const child = spawnFactory(
      "node",
      ["/opt/codex-home/run-codex.js", taskFor(payload)],
      {
        cwd: "/opt/bob-runner",
        env: codexEnvironment(),
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const poll = async () => {
      tracker = await emitPhaseEvents(
        client,
        secret,
        payload.runSlug,
        payload.targetDomain,
        tracker,
        clock,
      );
    };
    poll.delay = () => delay(1000);
    const execution = await runSpawnedRunner(child, poll);
    if (execution.code !== 0) {
      throw new Error(
        `Codex runner exited with code ${execution.code}${execution.signal ? ` (${execution.signal})` : ""}: ${execution.stderrTail}`,
      );
    }

    const receipt = verifyFinalizationReceipt(payload);
    const sealedAt = clock();
    await transitionRun(client, secret, payload.runSlug, "sealing", "report");
    tracker = await appendLifecycleEvent(client, secret, payload.runSlug, tracker, {
      kind: "report",
      register: "body",
      phase: "report",
      message: "The finalization receipt was verified.",
    }, clock);
    const report = await completeHostedRun(client, secret, payload, receipt, sealedAt);
    completionCommitted = true;
    exitCode = 0;
    console.log(JSON.stringify({
      status: "done",
      runSlug: payload.runSlug,
      reportSlug: report.slug,
      findingCount: receipt.consoleReport.findings.length,
    }));
  } catch (error) {
    if (client && payload && secret && !completionCommitted) {
      let failureStatusAccepted = false;
      try {
        const statusResult = await client.mutation("runs:setStatus", {
          secret,
          slug: payload.runSlug,
          status: "failed",
          phase: tracker.phase,
        });
        failureStatusAccepted = statusResult?.status === "failed";
      } catch {
        // The original failure remains authoritative; still close the client.
      }
      if (sequenceInitialized && failureStatusAccepted) {
        try {
          tracker = await appendLifecycleEvent(client, secret, payload.runSlug, tracker, {
            kind: "wait",
            register: "body",
            phase: tracker.phase,
            message: "Runner execution failed.",
          }, clock);
        } catch {
          // The event transport may share the failed control-plane dependency.
        }
      }
    }
    console.error(`[runner] ${redactFailure(error)}`);
  } finally {
    if (client && typeof client.close === "function") {
      try {
        await client.close();
      } catch (error) {
        console.error(`[runner] client close failed: ${redactFailure(error)}`);
        if (!completionCommitted) exitCode = 1;
      }
    }
  }
  return exitCode;
}

module.exports = Object.freeze({
  PAYLOAD_MAX_BYTES,
  REPOSITORY_PATH,
  appendLifecycleEvent,
  canonicalEventHash,
  completeHostedRun,
  contractTuple,
  emitPhaseEvents,
  initialToolCall,
  main,
  parsePayloadJson,
  redactFailure,
  runSpawnedRunner,
  resumeLifecycleTracker,
  sessionStateFor,
  taskFor,
  verifyFinalizationReceipt,
});

if (require.main === module) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(`[runner] ${redactFailure(error)}`);
      process.exitCode = 1;
    });
}
