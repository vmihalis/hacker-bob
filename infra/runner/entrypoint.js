"use strict";

// EC2 runner entrypoint. Runs inside the runner-ec2 container, spawned by the
// dispatch service with env-only secrets and BOB_PAYLOAD_PATH=/opt/payload.json.
//
// Flow: payload -> Convex run lifecycle (provisioning -> running, then
// sealed -> destroyed) -> dsh headless run of the Bob orchestrator composition
// -> report publish -> exit code. The Bob MCP server performs finalization
// internally (finding-artifact.json + /api/findings projection, Phase 2), so
// the entrypoint only needs to drive lifecycle status, watch the engine's own
// session state for the live witness, and publish the sealed report.
//
// Exit codes: 0 = assessment completed (report sealed/projected); 1 = failure
// (run marked failed in Convex).

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

function fail(message) {
  console.error(`[runner] ${message}`);
  process.exit(1);
}

function envOrFail(name) {
  const value = process.env[name];
  if (!value) fail(`${name} is required`);
  return value;
}

function readPayload() {
  const payloadPath = process.env.BOB_PAYLOAD_PATH;
  if (!payloadPath || !fs.existsSync(payloadPath)) fail("BOB_PAYLOAD_PATH missing or unreadable");
  try {
    const payload = JSON.parse(fs.readFileSync(payloadPath, "utf8"));
    if (payload.schemaVersion !== 1) fail(`unsupported payload schemaVersion ${payload.schemaVersion}`);
    return payload;
  } catch (error) {
    fail(`payload parse failed: ${error.message}`);
  }
}

function makeConvex() {
  // The convex client needs the .convex.cloud URL; the projection URL
  // (.convex.site) is HTTP-only.
  const url = envOrFail("BOB_CONVEX_URL");
  const { ConvexClient } = require("/opt/hacker-bob/node_modules/convex/dist/index.js");
  return new ConvexClient(url);
}

function setStatus(client, secret, slug, status, extra = {}) {
  return client.mutation("runs:setStatus", {
    secret,
    slug,
    status,
    ...extra,
  });
}

function appendEvent(client, secret, slug, event) {
  return client.mutation("runs:appendEvent", { secret, slug, ...event });
}

function sessionStateFor(domain) {
  const statePath = path.join(
    process.env.BOB_SESSIONS_ROOT || "/workspace/hacker-bob-sessions",
    domain,
    "state.json",
  );
  try {
    return JSON.parse(fs.readFileSync(statePath, "utf8"));
  } catch {
    return null;
  }
}

// Watch the ENGINE's own session state (Bob canonical) and mirror lifecycle
// changes into the live witness: one appendEvent per phase change.
function emitPhaseEvents(client, secret, slug, domain, previous) {
  const state = sessionStateFor(domain);
  if (!state) return previous;
  const lifecycle = typeof state.lifecycle_state === "string" ? state.lifecycle_state : null;
  if (lifecycle && lifecycle !== previous) {
    const phase = lifecycle.toLowerCase().replace(/_/g, " ");
    appendEvent(client, secret, slug, {
      seq: Date.now(),
      kind: "wait",
      register: "body",
      phase,
      message: `session entered ${lifecycle}`,
    });
    return lifecycle;
  }
  return previous;
}

function pbkdf2Hash(password, saltHex, iterations) {
  return crypto
    .pbkdf2Sync(password, Buffer.from(saltHex, "hex"), iterations, 32, "sha256")
    .toString("hex");
}

// Publish the sealed report into the retained console. Console-only for
// Release A (consoleVisible); the PBKDF2 access material is generated so the
// row is complete, but external /r links are not issued yet.
function publishReport(client, payload, artifact) {
  const secret = envOrFail("REPORTS_SECRET");
  const slug = `${payload.runSlug}-report`;
  const salt = crypto.randomBytes(16).toString("hex");
  const iterations = 100000;
  const password = crypto.randomBytes(24).toString("hex");
  const accessHash = pbkdf2Hash(password, salt, iterations);
  const result = client.mutation("reports:publish", {
    secret,
    slug,
    publicationKey: crypto.randomBytes(24).toString("hex"),
    publicationFingerprint: crypto
      .createHash("sha256")
      .update(JSON.stringify(artifact))
      .digest("hex"),
    domain: payload.targetDomain,
    recipient: payload.runSlug,
    method: "automated",
    date: new Date().toISOString(),
    modelJson: JSON.stringify(artifact),
    accessHash,
    accessSalt: salt,
    accessIter: iterations,
    consoleVisible: true,
    runSlug: payload.runSlug,
  });
  return result;
}

function taskFor(payload) {
  const scope = payload.scope && payload.scope.notes ? `\nScope notes: ${payload.scope.notes}` : "";
  return (
    `Run one authorized automated Hacker Bob assessment now.\n` +
    `Target: ${payload.target} (domain ${payload.targetDomain}, kind ${payload.targetKind}).\n` +
    `Objective: ${payload.objective}${scope}\n` +
    `Drive the full six-state lifecycle with the mcp__hacker-bob__* tools and finish ` +
    `with bob_finalize_report. End your final message with the verdict and the number ` +
    `of verified reportable findings.`
  );
}

function main() {
  const payload = readPayload();
  const secret = envOrFail("RUNNER_SECRET");
  const slug = payload.runSlug;
  const domain = payload.targetDomain;
  const client = makeConvex();

  setStatus(client, secret, slug, "provisioning", { phase: "setup" });
  setStatus(client, secret, slug, "running", { phase: "open frontier" });
  appendEvent(client, secret, slug, {
    seq: Date.now(),
    kind: "wait",
    register: "body",
    phase: "setup",
    message: `dispatched assessment of ${payload.target}`,
  });

  const dshArgs = [
    "--profile", "bob-runner",
    taskFor(payload),
  ];
  const result = spawnSync("dsh", dshArgs, {
    cwd: "/opt/bob-runner",
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: "/workspace",
      DSH_HOME: "/workspace/.dsh",
    },
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 100 * 60 * 1000, // dispatch service kills the container at its own 90-minute cap
  });

  let lifecycle = null;
  // The dsh process owns the run; the live witness gets phase transitions from
  // the engine's state.json. Coarse here: final statuses only, plus a best
  // effort sweep if we captured anything.
  const state = sessionStateFor(domain);
  if (state && typeof state.lifecycle_state === "string") lifecycle = state.lifecycle_state;

  if (result.status !== 0) {
    setStatus(client, secret, slug, "failed", { phase: lifecycle || null });
    appendEvent(client, secret, slug, {
      seq: Date.now(),
      kind: "wait",
      register: "body",
      phase: lifecycle ? lifecycle.toLowerCase().replace(/_/g, " ") : "report",
      message: `runner exited ${result.status}`,
    });
    fail(`dsh exited ${result.status}: ${String(result.stderr || "").slice(0, 2000)}`);
  }

  const artifactPath = path.join(
    process.env.BOB_SESSIONS_ROOT || "/workspace/hacker-bob-sessions",
    domain,
    "finding-artifact.json",
  );
  if (!fs.existsSync(artifactPath)) {
    setStatus(client, secret, slug, "failed", { phase: "report" });
    fail("dsh completed but no finding-artifact.json was sealed");
  }
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));

  // Projection already happened inside bob_finalize_report (Phase 2); publish
  // the sealed report, then close the run: sealed -> destroyed.
  const report = publishReport(client, payload, artifact);
  const reportSlug = report && typeof report === "object" && report.slug
    ? report.slug
    : `${slug}-report`;

  setStatus(client, secret, slug, "sealing", { phase: "report" });
  setStatus(client, secret, slug, "sealed", {
    phase: "report",
    reportSlug,
    sealedAt: Date.now(),
  });
  appendEvent(client, secret, slug, {
    seq: Date.now(),
    kind: "wait",
    register: "body",
    phase: "report",
    message: `sealed report ${reportSlug}`,
  });
  setStatus(client, secret, slug, "destroyed", { destroyedAt: Date.now() });

  console.log(
    JSON.stringify({
      status: "done",
      runSlug: slug,
      reportSlug,
      findingCount: Array.isArray(artifact.findings) ? artifact.findings.length : 0,
    }),
  );
  process.exit(0);
}

main();
