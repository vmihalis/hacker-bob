"use strict";

// Container-exec seam for the smart-contract host runners (forge / halmos /
// anchor / cargo / sui / aptos). The 7 runners route their build/test-binary
// child through this single seam instead of spawning the tool directly.
//
// STRUCTURAL CLOSE — namespace exclusion of the signing key.
// The signer key (.handoff-signing-key-ed25519.json, 0400) and the audit-graded
// ledgers live in the session tree under sessionDir(domain). The container route
// mounts ONLY the harness workdir (the validated, isUnderHome-resolved build
// tree) at /work:rw and NEVER the session tree. The container user is uid 1000
// (a NON-signer, NON-root). So agent-authored test/build code that tries to read
// the signing key — by absolute path or via a planted symlink — resolves to a
// path that does not exist inside the container filesystem namespace and gets
// ENOENT/EACCES. This is the exact EACCES the prior CAP_SETUID uid-drop tried to
// buy, now bought by namespace exclusion (which needs no root) instead of an
// in-process setuid (which needs CAP_SETUID and could never fire on a deployment
// the isolation probe blesses).
//
// NETWORK — the SC evaluators fork public RPC, so the SC container runs with
// --network bridge + a pinned --dns (the allowNetwork path). Egress to a public
// RPC does NOT expose the local key (the key is not in the namespace), so opening
// egress is safe here; this is the one deliberate divergence from the OSS-image
// default (--network none). The RPC fork URL still flows through
// filterResolvedPublicRpcEndpoints upstream in each runner (unchanged), so only
// policy-approved HTTPS public endpoints are reachable.
//
// ENV SCRUB — directSmartContractSubprocessEnv is applied by each runner at the
// call site, so this seam receives an already-scrubbed env in baseOpts.env. On
// the container route that scrubbed map is threaded into the container via
// repeated --env KEY=VALUE (never baked into the image); on the degrade route it
// is forwarded to spawn unchanged. Secret/proxy/RPC keys are stripped before they
// reach the tool on either route.
//
// ROUTE DECISION — container-when-available-else-DEGRADE.
// The seam picks CONTAINER iff Docker is reachable AND an SC-toolchain image tag
// is resolvable (operator-only env channel, out of model reach). Otherwise it
// DEGRADES to direct host execution — byte-identical to a bare
// spawn(bin, args, baseOpts) — so the dev box and in-flight sessions keep working
// with no hard crash. The degrade route is NEVER silently trusted: it emits a
// loud stderr warning AND surfaces container_isolated:false on the returned
// child, and the verdict gate (sandbox-isolation-gate.js) independently downgrades
// SC-backed reportable findings when the live key-isolation probe says
// not-isolated. The route decision uses the operator env channel + a real runtime
// probe, NEVER a model-supplied argument, so a prompt-injected evaluator cannot
// force the un-isolated host path while claiming isolation.

const childProcess = require("child_process");
const crypto = require("crypto");
const { spawn } = childProcess;

// Operator-only image-tag channel. Out of model reach, mirroring the other
// BOB_SANDBOX_*/BOB_SC_* env channels. The seam NEVER builds the image; it
// consumes a tag the operator pinned (see buildDockerfileScToolchain in
// repo-env.js for the image contract / provisioning recipe).
const SC_TOOLCHAIN_IMAGE_ENV = "BOB_SC_TOOLCHAIN_IMAGE";

// Documented default tag name. The operator pins this to a digest when they
// build/publish the SC-toolchain image; the literal default is only a name, not
// a guarantee the image is present (presence is probed via the runtime).
const SC_TOOLCHAIN_IMAGE_DEFAULT = "bob-sc-toolchain:pinned";

// Pinned DNS for the RPC-fork bridge, matching the OSS run path so the host
// resolver (which may shadow secret tokens via /etc/hosts or a local stub
// resolver) is bypassed.
const SC_CONTAINER_DNS = "1.1.1.1";

// The non-signer, non-root container user. Inherited verbatim from the OSS run
// convention; uid 1000 is not the signer uid and not root.
const SC_CONTAINER_USER = "1000:1000";

// The error code the seam throws when it REFUSES a host-as-signer SC run on an
// isolated signer (HIGH-1 primary mechanism, key-exposure prevention, mode-
// independent). The runner maps this to a blocked-run reason so a verdict producer
// records the refusal rather than a host-as-signer row.
const SC_ISOLATION_REFUSED_CODE = "sc_isolation_refused";

// In-container mount points.
const SC_CONTAINER_WORKDIR = "/work";

// A spy registry so the routing guard can prove every runner dispatches through
// THIS seam at runtime (not via a brittle source-grep). Each call appends a
// {tool, route} record; a test installs a spy and asserts all 7 tools dispatch.
const ROUTED_SC_RUNNERS = [];
let routeSpy = null;

function setRouteSpy(fn) {
  routeSpy = typeof fn === "function" ? fn : null;
}

function recordRoute(tool, route) {
  const record = { tool, route };
  ROUTED_SC_RUNNERS.push(record);
  if (routeSpy) {
    try { routeSpy(record); } catch {}
  }
  return record;
}

function resolveScToolchainImageTag() {
  const raw = process.env[SC_TOOLCHAIN_IMAGE_ENV];
  if (typeof raw === "string" && raw.trim()) return raw.trim();
  return null;
}

// Per-process cache of the real-daemon docker-availability probe. The probe is an
// execFileSync('docker','--version') with a 5s timeout — a synchronous event-loop
// block worst-case 5s. Docker daemon presence does not change within a server
// process lifetime, so the probe runs at most ONCE per process; subsequent SC runs
// read the cached boolean. The runtime-override branches (tests/stubs) are NOT
// cached — they win every call so a test can flip availability per case. A
// test-only reset (__resetDockerProbeCache) clears the cache between cases.
let cachedDockerAvailable = null;

// Synchronous docker-availability probe. The runners call this seam
// synchronously inside `new Promise`, so the route must resolve without an
// await. A short-timeout `docker --version` is the same liveness check
// dockerIsAvailable performs (async); a stub runtime overrides it in tests.
function dockerAvailableSync(runtime) {
  if (runtime && typeof runtime.dockerAvailable === "boolean") {
    return runtime.dockerAvailable;
  }
  if (runtime && typeof runtime.dockerAvailableSync === "function") {
    try { return runtime.dockerAvailableSync() === true; } catch { return false; }
  }
  // The runtime override is resolved above (it must win every call). Below this
  // line is the real-daemon probe, cached per process to remove the repeated 5s
  // worst-case block from the hot SC route.
  if (cachedDockerAvailable !== null) return cachedDockerAvailable;
  try {
    // Referenced through the module object (not a destructured binding) so a test
    // can stub the real-daemon probe and assert it runs at most once per process.
    childProcess.execFileSync("docker", ["--version"], { timeout: 5000, stdio: "ignore" });
    cachedDockerAvailable = true;
  } catch {
    cachedDockerAvailable = false;
  }
  return cachedDockerAvailable;
}

// Test-only: clear the per-process docker-probe cache so a suite can exercise the
// real-daemon probe path deterministically between cases. Production never calls
// this (the cache is intentionally process-lifetime).
function __resetDockerProbeCache() {
  cachedDockerAvailable = null;
}

// Build the docker-run argv for an SC tool. ONE mount (the harness workdir, RW),
// NEVER the session tree; non-signer --user; --network bridge + --dns for the
// RPC fork; the scrubbed env threaded via --env. This mirrors the OSS
// buildDockerRunArgv flag set but with the SC-specific single-mount /
// always-network shape. Exported so the stubbed-runtime test can assert the argv
// without a real Docker daemon.
function buildScContainerArgv({ workdir, imageTag, tool, toolArgs, env, containerName }) {
  if (typeof workdir !== "string" || !workdir.trim()) {
    throw new Error("buildScContainerArgv requires a workdir (the harness build tree)");
  }
  if (typeof imageTag !== "string" || !imageTag.trim()) {
    throw new Error("buildScContainerArgv requires an SC-toolchain image tag");
  }
  if (typeof tool !== "string" || !tool.trim()) {
    throw new Error("buildScContainerArgv requires the tool name");
  }
  const args = ["run", "--rm"];
  // --name gives the DAEMON a stable handle for THIS container. The runner's
  // timeout-kill targets the docker CLIENT process group; killing the client (and
  // SIGKILL is NOT signal-proxied) does NOT stop a daemon-managed container — it
  // detaches and keeps holding its --cpus/--memory/--pids. So on the timeout path the
  // runner ALSO calls child.teardownContainer() (`docker kill <name>`), which tells
  // the daemon to SIGKILL this named container; --rm then removes it on exit. --init
  // reaps in-container PID-1 children only ONCE the container stops, and --rm removes
  // it only ON exit, so neither alone reaps a container whose client was killed —
  // the named daemon-side kill is what actually frees the held resources.
  if (typeof containerName === "string" && containerName.trim()) {
    args.push("--name", containerName);
  }
  args.push("--init");
  // RPC fork needs egress; pin DNS to bypass the host resolver. Egress does NOT
  // expose the local key (the key is not in the namespace).
  args.push("--network", "bridge");
  args.push("--dns", SC_CONTAINER_DNS);
  // Sandbox hardening, mirroring the OSS run path. cap-drop ALL + no-new-privileges
  // + a non-signer non-root user + resource caps + read-only root.
  args.push("--cap-drop", "ALL");
  args.push("--security-opt", "no-new-privileges");
  args.push("--user", SC_CONTAINER_USER);
  args.push("--cpus", "2");
  args.push("--memory", "4g");
  args.push("--pids-limit", "1024");
  args.push("--read-only");
  // An exec-capable scratch tmpfs (build systems stage binaries under $TMPDIR);
  // nosuid+nodev keep privilege escalation closed.
  args.push("--tmpfs", "/tmp:size=512m,exec,nosuid,nodev");
  // A writable HOME on the read-only root. Toolchains write to $HOME/.cache,
  // $HOME/.foundry, $HOME/.cargo, etc.; point HOME at the writable /work mount.
  args.push("--env", `HOME=${SC_CONTAINER_WORKDIR}`);
  // THE single mount: the harness build tree, writable, at /work. The session
  // tree (sessionDir / signing key / audit-graded ledgers) is NEVER passed as a
  // -v, so it is excluded from the container filesystem namespace. cwd is /work.
  args.push("-v", `${workdir}:${SC_CONTAINER_WORKDIR}:rw`);
  args.push("--workdir", SC_CONTAINER_WORKDIR);
  // Thread the already-scrubbed env via --env (never baked into the image). HOME
  // is set above; do not let a caller-supplied HOME override the writable mount.
  if (env && typeof env === "object") {
    for (const [key, value] of Object.entries(env)) {
      if (key === "HOME") continue;
      if (value === undefined || value === null) continue;
      args.push("--env", `${key}=${value}`);
    }
  }
  args.push(imageTag);
  args.push(tool);
  for (const token of Array.isArray(toolArgs) ? toolArgs : []) {
    args.push(token);
  }
  return args;
}

// The single seam the 7 SC runners route through. Same (bin, args, baseOpts)
// signature as the prior direct-spawn helper, so each runner's call site changes
// only the import + the function name; the returned object is a ChildProcess with
// the SAME stdout/stderr/close/error contract the runners already wire (timeout
// process-group kill, byte-cap, JSON parse all untouched).
//
// CONTAINER route iff Docker is reachable AND an SC-toolchain image tag resolves;
// otherwise DEGRADE to direct host execution (byte-identical to a bare spawn).
function scSubprocessContainerExec(bin, args, baseOpts = {}, runtime = null) {
  const imageTag = resolveScToolchainImageTag() || (runtime && runtime.imageTag) || null;
  const haveDocker = dockerAvailableSync(runtime);
  const containerRoute = Boolean(haveDocker && imageTag);

  if (!containerRoute) {
    // HIGH-1 PRIMARY MECHANISM — REFUSE-ON-ISOLATED (fail-closed at the source, in ANY
    // mode). When the live signer-key probe says the signer is isolated AND the
    // container route is unavailable, a degrade host spawn would run the SC tool AS THE
    // SIGNER (byte-identical spawn) — so agent-authored Solidity/Move/Rust in the
    // test/build could read the 0400 key and forge a MAC-valid verdict row. REFUSE
    // rather than run host-as-signer: this is KEY-EXPOSURE PREVENTION, not a
    // verdict-trust downgrade. Refusing fires regardless of mode (including explicit
    // degrade) because once the host-as-signer process runs the key exposure is
    // irreversible — downgrading the resulting verdict cannot un-expose the key. The
    // recorded container_isolated field + the gate-level consult are the durable,
    // audit-graded backstop for the OTHER routes (the container route, or a same-uid
    // box where the row is minted but gate-downgraded under degrade). On a same-uid
    // (non-isolated) box the probe is not isolated, so this never fires and the seam
    // degrades exactly as before (CONSTRAINT 7 backward-compat).
    if (shouldRefuseHostAsSignerScRun(baseOpts)) {
      recordRoute(bin, "refuse");
      emitScIsolationRefusal(bin, { haveDocker, imageTag });
      const error = new Error(
        `SC isolation refused: ${bin} cannot run host-as-signer on an `
        + "isolated signer with no SC-toolchain image; set BOB_SC_TOOLCHAIN_IMAGE",
      );
      error.code = SC_ISOLATION_REFUSED_CODE;
      throw error;
    }
    recordRoute(bin, "degrade");
    // Degrade is NEVER silent: a loud stderr line plus a structured marker on the
    // returned child so a headless harness that discards stderr still sees it.
    emitScDegradeWarning(bin, { haveDocker, imageTag });
    const child = spawn(bin, args, baseOpts);
    try {
      Object.defineProperty(child, "container_isolated", { value: false, enumerable: true });
    } catch {}
    return child;
  }

  recordRoute(bin, "container");
  const resolvedImageTag = imageTag || SC_TOOLCHAIN_IMAGE_DEFAULT;
  // A unique daemon-side handle for THIS container. Generated here (not in
  // buildScContainerArgv, which stays a pure argv builder) so the teardown call can
  // target exactly this container by name.
  const containerName = `bob-sc-${crypto.randomBytes(8).toString("hex")}`;
  const dockerArgs = buildScContainerArgv({
    workdir: baseOpts.cwd,
    imageTag: resolvedImageTag,
    tool: bin,
    toolArgs: args,
    env: baseOpts.env,
    containerName,
  });
  // Spawn the docker client. The runner's timeout-kill targets THIS client's process
  // group, but killing the client does NOT stop the daemon-managed container — so on
  // the timeout path the runner ALSO calls child.teardownContainer() (below), which
  // issues `docker kill <name>` to make the daemon reap the named container; --rm then
  // removes it. detached:true preserves the runner's process-group kill semantics over
  // the docker client.
  const spawnOpts = {
    stdio: baseOpts.stdio || ["ignore", "pipe", "pipe"],
    detached: baseOpts.detached === true,
  };
  const child = spawn("docker", dockerArgs, spawnOpts);
  try {
    Object.defineProperty(child, "container_isolated", { value: true, enumerable: true });
  } catch {}
  try {
    Object.defineProperty(child, "container_name", { value: containerName, enumerable: true });
  } catch {}
  try {
    // Best-effort daemon-side teardown the runner invokes ONLY on the timeout path.
    // async execFile with a no-op callback => never throws and never blocks the event
    // loop; `docker kill` tells the daemon to SIGKILL the named container (the client
    // kill alone leaves it running), and --rm removes it on exit. A second call (the
    // SIGKILL escalation) or a call after the container already exited is harmless —
    // the no-op callback swallows the "no such container" error.
    Object.defineProperty(child, "teardownContainer", {
      value: () => {
        try { childProcess.execFile("docker", ["kill", containerName], () => {}); } catch {}
      },
      enumerable: false,
    });
  } catch {}
  return child;
}

// Decide whether to REFUSE a degrade (host-as-signer) SC run. True iff ALL of:
//   * the resolved attestation mode is "enforce" (the operator opted into the
//     fail-closed posture; degrade still mints the row, gate-downgraded);
//   * a target_domain is available to probe (baseOpts.targetDomain — threaded from
//     the runner; absent on a domain-less call path, where we cannot probe and so
//     degrade as before rather than refuse blindly);
//   * the LIVE signer-key probe reports the signer is isolated (a distinct signer
//     uid owns the 0400 key) — the ONLY case where a host-as-signer run is a
//     forgery vector; on a same-uid box the probe is not isolated, so we degrade.
// The probe + mode are read from the operator env channel + a real syscall, NEVER
// a model-supplied argument, so a prompt-injected evaluator cannot force or suppress
// the refusal. Any probe/require failure fails SAFE to "do not refuse" (degrade,
// which is still loud and still gate-downgraded) rather than hard-crashing the run.
function shouldRefuseHostAsSignerScRun(baseOpts) {
  const targetDomain = baseOpts && typeof baseOpts.targetDomain === "string"
    ? baseOpts.targetDomain
    : null;
  if (!targetDomain) return false;
  // Refuse the host-as-signer SC run whenever the signer key is ISOLATED, in ANY
  // mode. On an isolated-signer box, running agent-authored SC build/test code as
  // the signer would let it read the 0400 key and forge a MAC-valid row for ANY
  // keyed ledger (not just this family's), so a per-family container_isolated
  // downgrade is insufficient — the run must not happen at all. This covers all
  // seven SC families (the seam is shared) and closes the degrade+isolated gap.
  //
  // Refuse is KEY-EXPOSURE PREVENTION, not a verdict-trust downgrade — and the two are
  // not interchangeable. Refusing is correct even under explicit
  // BOB_SANDBOX_ATTESTATION_MODE=degrade: degrade only DOWNGRADES a verdict's trust, but
  // downgrading a verdict cannot UN-EXPOSE a key that agent-authored Solidity/Move/Rust
  // already read while running as the signer. The exposure is irreversible the moment the
  // host-as-signer process runs, so the only safe action is to never run it. Refuse is
  // therefore keyed on isolation ALONE (mode-independent); degrade-vs-block is the
  // verdict-trust knob applied AFTER a run that did NOT expose the key (the container or
  // same-uid routes). degrade keeps producing only on an UN-isolated (same-uid) box,
  // where the probe is not isolated and this never fires.
  let probe;
  try {
    const { probeVerdictLedgerKeyIsolation } = require("../../../core/ledger-integrity/sandbox-isolation-attest.js");
    probe = probeVerdictLedgerKeyIsolation(targetDomain);
  } catch {
    return false;
  }
  return Boolean(probe && probe.isolated === true);
}

function emitScIsolationRefusal(tool, { haveDocker, imageTag } = {}) {
  const reason = !haveDocker
    ? "docker unavailable"
    : (!imageTag ? "no SC-toolchain image" : "isolation unavailable");
  const line =
    `SC TOOLCHAIN ISOLATION REFUSED: refusing to run ${tool} host-as-signer `
    + `on an isolated signer (${reason}) to prevent signing-key exposure; `
    + "set BOB_SC_TOOLCHAIN_IMAGE to run containerized";
  try {
    process.stderr.write(line + "\n");
  } catch {}
  return line;
}

function emitScDegradeWarning(tool, { haveDocker, imageTag } = {}) {
  const reason = !haveDocker
    ? "docker unavailable"
    : (!imageTag ? "no SC-toolchain image" : "isolation unavailable");
  const line =
    `SC TOOLCHAIN NOT CONTAINER-ISOLATED: running ${tool} directly as the server uid ` +
    `(${reason}); verdict gate will treat SC-backed findings as un-isolated`;
  try {
    process.stderr.write(line + "\n");
  } catch {}
  return line;
}

module.exports = {
  scSubprocessContainerExec,
  buildScContainerArgv,
  dockerAvailableSync,
  __resetDockerProbeCache,
  resolveScToolchainImageTag,
  emitScDegradeWarning,
  emitScIsolationRefusal,
  shouldRefuseHostAsSignerScRun,
  setRouteSpy,
  ROUTED_SC_RUNNERS,
  SC_TOOLCHAIN_IMAGE_ENV,
  SC_TOOLCHAIN_IMAGE_DEFAULT,
  SC_ISOLATION_REFUSED_CODE,
  SC_CONTAINER_USER,
  SC_CONTAINER_WORKDIR,
  SC_CONTAINER_DNS,
};
