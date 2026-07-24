"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const { performance } = require("node:perf_hooks");

const native = require(path.join(__dirname, "..", "..", "lib", "native-acceptor.js"));

function frame(body) {
  const payload = Buffer.from(body);
  const output = Buffer.allocUnsafe(payload.length + 4);
  output.writeUInt32BE(payload.length, 0);
  payload.copy(output, 4);
  return output;
}

async function readFrame(socket) {
  let buffered = Buffer.alloc(0);
  while (buffered.length < 4) {
    const [chunk] = await once(socket, "data");
    buffered = Buffer.concat([buffered, chunk]);
  }
  const length = buffered.readUInt32BE(0);
  while (buffered.length < length + 4) {
    const [chunk] = await once(socket, "data");
    buffered = Buffer.concat([buffered, chunk]);
  }
  return buffered.subarray(4, length + 4);
}

function saturatePool() {
  let completed = 0;
  const tasks = Array.from({ length: 4 }, (_, index) => new Promise((resolve, reject) => {
    crypto.pbkdf2(
      `pool-blocker-${index}`,
      "hacker-bob-native-pool-saturation",
      2_000_000,
      32,
      "sha256",
      (error) => {
        completed += 1;
        if (error) reject(error);
        else resolve();
      },
    );
  }));
  return {
    completed: () => completed,
    done: Promise.all(tasks),
  };
}

async function delay(milliseconds) {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function createListener(root, label, socketName = label) {
  const socketPath = path.join(root, `${socketName}.sock`);
  const config = native.createDarwinNativeUnixAcceptor({
    adapter_id: `pool_${label}`,
    socket_path: socketPath,
  });
  return {
    listener: native.openDarwinNativeUnixAcceptor(config),
    socketPath,
  };
}

async function createConnection(root, label) {
  const { listener, socketPath } = createListener(root, label);
  const pending = native.acceptDarwinNativeUnixConnection(listener);
  const client = net.createConnection({ path: socketPath, allowHalfOpen: true });
  client.on("error", () => {});
  await once(client, "connect");
  const connection = await pending;
  native.inspectDarwinNativeAcceptedConnectionPeer(
    connection,
    crypto.randomBytes(18).toString("base64url"),
  );
  return { client, connection, listener };
}

function closeFixture(fixture) {
  try { native.closeDarwinNativeAcceptedConnection(fixture.connection); } catch {}
  try { native.closeDarwinNativeUnixAcceptor(fixture.listener); } catch {}
  fixture.client?.destroy();
}

async function expectRejected(promise) {
  try {
    await promise;
    return null;
  } catch (error) {
    return error?.code || null;
  }
}

async function acceptCancellation(root) {
  const fixture = createListener(root, "accept_cancel", "a");
  const blockers = saturatePool();
  await delay(15);
  const pending = native.acceptDarwinNativeUnixConnection(fixture.listener);
  const started = performance.now();
  native.closeDarwinNativeUnixAcceptor(fixture.listener);
  const code = await expectRejected(pending);
  const elapsed_ms = performance.now() - started;
  const blockers_completed_at_rejection = blockers.completed();
  await blockers.done;
  return { blockers_completed_at_rejection, code, elapsed_ms };
}

async function queuedReadDeadline(root) {
  const fixture = await createConnection(root, "r");
  try {
    const challenge = native.writeDarwinNativeAcceptedConnectionChallenge(
      fixture.connection,
      frame("challenge"),
      1_000,
    );
    await readFrame(fixture.client);
    await challenge;
    const blockers = saturatePool();
    await delay(15);
    const started = performance.now();
    const code = await expectRejected(
      native.readDarwinNativeAcceptedConnectionRequest(fixture.connection, 40),
    );
    const elapsed_ms = performance.now() - started;
    const blockers_completed_at_rejection = blockers.completed();
    await blockers.done;
    return { blockers_completed_at_rejection, code, elapsed_ms };
  } finally {
    closeFixture(fixture);
  }
}

async function queuedResponseDeadline(root) {
  const fixture = await createConnection(root, "s");
  try {
    const challenge = native.writeDarwinNativeAcceptedConnectionChallenge(
      fixture.connection,
      frame("challenge"),
      1_000,
    );
    await readFrame(fixture.client);
    await challenge;
    fixture.client.write(frame("request"));
    await native.readDarwinNativeAcceptedConnectionRequest(fixture.connection, 1_000);
    let response_bytes = 0;
    fixture.client.on("data", (chunk) => { response_bytes += chunk.length; });
    const blockers = saturatePool();
    await delay(15);
    const started = performance.now();
    const code = await expectRejected(
      native.writeDarwinNativeAcceptedConnectionResponse(
        fixture.connection,
        frame("response-after-deadline"),
        40,
      ),
    );
    const elapsed_ms = performance.now() - started;
    const blockers_completed_at_rejection = blockers.completed();
    await blockers.done;
    await delay(30);
    return {
      blockers_completed_at_rejection,
      code,
      elapsed_ms,
      response_bytes,
    };
  } finally {
    closeFixture(fixture);
  }
}

(async () => {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "bnp-")),
  );
  fs.chmodSync(root, 0o700);
  try {
    const result = {
      accept: await acceptCancellation(root),
      read: await queuedReadDeadline(root),
      response: await queuedResponseDeadline(root),
    };
    process.stdout.write(JSON.stringify(result));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
})().catch((error) => {
  process.stderr.write(`${error?.stack || error}\n`);
  process.exitCode = 1;
});
