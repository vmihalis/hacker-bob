"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { assertCallbackUrlSafe } = require("../infra/runner/callback-ssrf-guard.js");

// Guard/restore RUNNER_CALLBACK_ALLOWED_HOST around every test so the env var never leaks
// between cases (some cases intentionally clear it to prove the fail-closed default).
function withAllowedHostEnv(value, fn) {
  const previous = process.env.RUNNER_CALLBACK_ALLOWED_HOST;
  if (value === undefined) {
    delete process.env.RUNNER_CALLBACK_ALLOWED_HOST;
  } else {
    process.env.RUNNER_CALLBACK_ALLOWED_HOST = value;
  }
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      if (previous === undefined) {
        delete process.env.RUNNER_CALLBACK_ALLOWED_HOST;
      } else {
        process.env.RUNNER_CALLBACK_ALLOWED_HOST = previous;
      }
    });
}

test("accepts an allowlisted host that is itself a public IPv4 literal", async () => {
  // A literal public IP avoids any real DNS/network call (net.isIP fast path short-circuits
  // the DNS lookup branch entirely).
  const publicHost = "93.184.216.34"; // public unicast address, used here as a literal only
  const accepted = await assertCallbackUrlSafe(`https://${publicHost}/callback`, {
    allowedHost: publicHost,
  });
  assert.equal(accepted.host, publicHost);
  assert.equal(accepted.url, `https://${publicHost}/callback`);
});

test("rejects when hostname does not match the allowlisted host", async () => {
  await assert.rejects(
    () => assertCallbackUrlSafe("https://93.184.216.34/callback", {
      allowedHost: "203.0.113.55",
    }),
    /not the allowlisted callback host/,
  );
});

test("rejects http:// even for the allowlisted host", async () => {
  await assert.rejects(
    () => assertCallbackUrlSafe("http://93.184.216.34/callback", {
      allowedHost: "93.184.216.34",
    }),
    /https/,
  );
});

test("rejects the allowlisted host literal as 127.0.0.1", async () => {
  await assert.rejects(
    () => assertCallbackUrlSafe("https://127.0.0.1/callback", {
      allowedHost: "127.0.0.1",
    }),
    /blocked internal\/private host/,
  );
});

test("rejects the allowlisted host literal as 169.254.169.254 (metadata)", async () => {
  await assert.rejects(
    () => assertCallbackUrlSafe("https://169.254.169.254/callback", {
      allowedHost: "169.254.169.254",
    }),
    /blocked internal\/private host/,
  );
});

test("rejects the allowlisted host literal as a 10.0.0.0/8 address", async () => {
  await assert.rejects(
    () => assertCallbackUrlSafe("https://10.1.2.3/callback", {
      allowedHost: "10.1.2.3",
    }),
    /blocked internal\/private host/,
  );
});

test("rejects the allowlisted host literal as a 192.168.0.0/16 address", async () => {
  await assert.rejects(
    () => assertCallbackUrlSafe("https://192.168.1.1/callback", {
      allowedHost: "192.168.1.1",
    }),
    /blocked internal\/private host/,
  );
});

test("rejects a .internal/.local/localhost literal hostname", async () => {
  for (const host of ["seal.internal", "seal.local", "localhost"]) {
    await assert.rejects(
      () => assertCallbackUrlSafe(`https://${host}/callback`, {
        allowedHost: host,
      }),
      /blocked internal\/private host/,
      `${host} must be rejected`,
    );
  }
});

test("DNS-rebind: allowlisted hostname passes, but resolved address is private/metadata", async () => {
  const allowedHost = "seal.example.com";
  const stubLookup = (hostname, options, callback) => {
    assert.equal(hostname, allowedHost);
    assert.deepEqual(options, { all: true });
    // Simulate a rebind: the resolver hands back the cloud metadata address even though the
    // hostname string itself matched the allowlist and isn't itself a literal/blocked name.
    callback(null, [{ address: "169.254.169.254", family: 4 }]);
  };

  await assert.rejects(
    () => assertCallbackUrlSafe(`https://${allowedHost}/callback`, {
      allowedHost,
      lookup: stubLookup,
    }),
    /resolved to a blocked internal\/private address/,
  );
});

test("DNS-rebind: rejects when only one of several resolved addresses is private", async () => {
  const allowedHost = "seal.example.com";
  const stubLookup = (hostname, options, callback) => {
    callback(null, [
      { address: "93.184.216.34", family: 4 },
      { address: "10.0.0.5", family: 4 },
    ]);
  };

  await assert.rejects(
    () => assertCallbackUrlSafe(`https://${allowedHost}/callback`, {
      allowedHost,
      lookup: stubLookup,
    }),
    /resolved to a blocked internal\/private address/,
  );
});

test("accepts a hostname (non-literal) whose stubbed resolution is entirely public", async () => {
  const allowedHost = "seal.example.com";
  const stubLookup = (hostname, options, callback) => {
    callback(null, [{ address: "93.184.216.34", family: 4 }]);
  };

  const result = await assertCallbackUrlSafe(`https://${allowedHost}/callback`, {
    allowedHost,
    lookup: stubLookup,
  });
  assert.equal(result.host, allowedHost);
});

test("rejects when DNS resolution returns zero addresses", async () => {
  const allowedHost = "seal.example.com";
  const stubLookup = (hostname, options, callback) => {
    callback(null, []);
  };

  await assert.rejects(
    () => assertCallbackUrlSafe(`https://${allowedHost}/callback`, {
      allowedHost,
      lookup: stubLookup,
    }),
    /DNS lookup returned no addresses/,
  );
});

test("throws when no allowlist is configured (options.allowedHost unset and env unset)", async () => {
  await withAllowedHostEnv(undefined, async () => {
    await assert.rejects(
      () => assertCallbackUrlSafe("https://93.184.216.34/callback", {}),
      /No callback allowlist configured/,
    );
  });
});

test("falls back to RUNNER_CALLBACK_ALLOWED_HOST env when options.allowedHost is unset", async () => {
  await withAllowedHostEnv("93.184.216.34", async () => {
    const result = await assertCallbackUrlSafe("https://93.184.216.34/callback", {});
    assert.equal(result.host, "93.184.216.34");
  });
});

test("rejects on a malformed URL", async () => {
  await assert.rejects(
    () => assertCallbackUrlSafe("not-a-url", { allowedHost: "93.184.216.34" }),
    /Invalid callbackUrl/,
  );
});
