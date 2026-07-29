"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const buildContract = require("../lib/native-build-contract.js");

const ROOT = path.resolve(__dirname, "..");
const CLIENT_MODULE = path.join(ROOT, "lib", "native-client.js");
const LOADER_MODULE = path.join(ROOT, "lib", "native-binding-loader.js");
const BUILD_CONTRACT_MODULE = path.join(ROOT, "lib", "native-build-contract.js");
const BINDING_PATH = path.join(ROOT, "build", "Release", "trusted_clock_client.node");
const SERVICE_PATH = path.join(ROOT, "build", "Release", "trusted_clock_service");
const PROCESS_MARK = Symbol.for(
  "hacker-bob.instrument-trusted-clock-native-darwin.client-opened.v1",
);
const FIXTURE_PATHS = Object.freeze([
  "binding.gyp",
  "lib/native-binding-loader.js",
  "lib/native-build-contract.js",
  "lib/native-client.js",
  "lib/source-contract.js",
  "native/trusted_clock_client.cc",
  "native/trusted_clock_node.cc",
  "native/trusted_clock_protocol.h",
  "native/trusted_clock_service.cc",
  "package.json",
  "scripts/write-build-receipt.js",
  "build/Release/trusted_clock_client.node",
  "build/Release/trusted_clock_service",
  "build/Release/trusted_clock_local_build_receipt.json",
]);

function runChild(source, cwd = ROOT) {
  const result = spawnSync(process.execPath, ["-e", source], {
    cwd,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, "");
  return JSON.parse(result.stdout);
}

function copyFixture(t) {
  const parent = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "hb-clock-native-")),
  );
  const root = path.join(parent, "package");
  fs.mkdirSync(root, { mode: 0o700 });
  for (const relative of FIXTURE_PATHS) {
    const source = path.join(ROOT, relative);
    const destination = path.join(root, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
    fs.copyFileSync(source, destination);
    fs.chmodSync(destination, fs.statSync(source).mode & 0o777);
  }
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return root;
}

function reason(error, code, reasonCode) {
  return error?.code === code && error?.reason_code === reasonCode;
}

test("local build receipt binds the exact native source and two-artifact suite", () => {
  assert.deepEqual(buildContract.DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_SOURCE_PATHS, [
    "binding.gyp",
    "lib/native-binding-loader.js",
    "lib/native-build-contract.js",
    "lib/native-client.js",
    "lib/source-contract.js",
    "native/trusted_clock_client.cc",
    "native/trusted_clock_node.cc",
    "native/trusted_clock_protocol.h",
    "native/trusted_clock_service.cc",
    "package.json",
    "scripts/write-build-receipt.js",
  ]);
  const build = buildContract.verifyDarwinTrustedClockLocalBuild(ROOT);
  assert.equal(build.kind, "verified_darwin_trusted_clock_local_source_build");
  assert.equal(build.assurance, "local_source_build_receipt_non_authorizing");
  assert.equal(build.node_api_client_path, BINDING_PATH);
  assert.match(build.receipt_sha256, /^[a-f0-9]{64}$/u);
  assert.match(build.source_set_sha256, /^[a-f0-9]{64}$/u);
  assert.match(build.node_api_client_sha256, /^[a-f0-9]{64}$/u);
  assert.match(build.service_sha256, /^[a-f0-9]{64}$/u);
  assert.equal(build.signed_release_verified, false);
  assert.equal(build.native_loaded_image_attested, false);
  assert.equal(build.immutable_installation_verified, false);
  assert.equal(build.provisioning_verified, false);
  assert.equal(build.hil_verified, false);
  assert.equal(build.production_ready, false);
  assert.ok(build.production_blockers.includes(
    "trusted_clock_local_source_build_not_release_authenticated",
  ));
  assert.ok(build.production_blockers.includes(
    "trusted_clock_same_process_preimport_runtime_integrity_unproven",
  ));
  assert.ok(build.production_blockers.includes(
    "trusted_clock_native_client_same_process_capability_custody_not_isolated",
  ));
});

test("import is inert and explicit zero-config construction loads only the fixed build", () => {
  const result = runChild([
    '"use strict";',
    `const clientPath=${JSON.stringify(CLIENT_MODULE)};`,
    `const bindingPath=${JSON.stringify(BINDING_PATH)};`,
    `const mark=Symbol.for(${JSON.stringify(Symbol.keyFor(PROCESS_MARK))});`,
    "const beforeCache=Object.hasOwn(require.cache,bindingPath);",
    "const beforeMark=Object.hasOwn(process,mark);",
    "const clock=require(clientPath);",
    "const afterImportCache=Object.hasOwn(require.cache,bindingPath);",
    "const afterImportMark=Object.hasOwn(process,mark);",
    "const client=clock.createDarwinTrustedClockNativeClient();",
    "process.stdout.write(JSON.stringify({beforeCache,beforeMark,afterImportCache,afterImportMark,productionReady:client.production_ready,nativeLoaded:client.native_client_loaded,signed:client.signed_release_verified,attested:client.native_attested,authoritative:client.authoritative,fixedEndpoint:client.fixed_endpoint,zeroConfiguration:client.zero_configuration,oneShot:client.one_shot,branded:clock.assertDarwinTrustedClockNativeClient(client)===client}));",
  ].join(""));
  assert.deepEqual(result, {
    beforeCache: false,
    beforeMark: false,
    afterImportCache: false,
    afterImportMark: false,
    productionReady: false,
    nativeLoaded: true,
    signed: false,
    attested: false,
    authoritative: false,
    fixedEndpoint: true,
    zeroConfiguration: true,
    oneShot: true,
    branded: true,
  });
});

test("unprovisioned native client fails before socket access and consumes its one sample", () => {
  const result = runChild([
    '"use strict";',
    `const clock=require(${JSON.stringify(CLIENT_MODULE)});`,
    "const client=clock.createDarwinTrustedClockNativeClient();",
    "let first=null;let second=null;",
    "try{client.sample();}catch(error){first={code:error.code,reason:error.reason_code};}",
    "try{client.sample();}catch(error){second={code:error.code,reason:error.reason_code};}",
    "process.stdout.write(JSON.stringify({first,second}));",
  ].join(""));
  assert.deepEqual(result, {
    first: {
      code: "darwin_trusted_clock_native_client_rejected",
      reason: "native_enrollment_unprovisioned",
    },
    second: {
      code: "darwin_trusted_clock_native_client_rejected",
      reason: "native_client_sample_consumed",
    },
  });
});

test("post-construction CommonJS caches expose only inert tombstones", () => {
  const result = runChild([
    '"use strict";',
    `const clientPath=${JSON.stringify(CLIENT_MODULE)};`,
    `const loaderPath=${JSON.stringify(LOADER_MODULE)};`,
    `const bindingPath=${JSON.stringify(BINDING_PATH)};`,
    "const clock=require(clientPath);",
    "const client=clock.createDarwinTrustedClockNativeClient();",
    "const bindingCached=require.cache[bindingPath].exports;",
    "const loaderCached=require.cache[loaderPath].exports;",
    "const bindingRequired=require(bindingPath);",
    "const loaderRequired=require(loaderPath);",
    "const inspect=(value)=>{const keys=Reflect.ownKeys(value);return {keys,frozen:Object.isFrozen(value),nullPrototype:Object.getPrototypeOf(value)===null,descriptorsExact:keys.every((key)=>{const descriptor=Object.getOwnPropertyDescriptor(value,key);return Object.hasOwn(descriptor,'value')&&descriptor.writable===false&&descriptor.enumerable===true&&descriptor.configurable===false;}),functionCount:keys.filter((key)=>typeof value[key]==='function').length,version:value.version,kind:value.kind,callableSurfaceExposed:value.callable_surface_exposed,productionReady:value.production_ready};};",
    "let sampleReason=null;",
    "try{client.sample();}catch(error){sampleReason=error.reason_code;}",
    "process.stdout.write(JSON.stringify({bindingSame:bindingCached===bindingRequired,loaderSame:loaderCached===loaderRequired,binding:inspect(bindingRequired),loader:inspect(loaderRequired),bindingFunctionType:typeof bindingRequired.sampleTrustedClockNative,loaderFunctionType:typeof loaderRequired.loadDarwinTrustedClockNativeBindingOnce,sampleReason}));",
  ].join(""));
  const expectedKeys = [
    "version", "kind", "callable_surface_exposed", "production_ready",
  ];
  assert.deepEqual(result, {
    bindingSame: true,
    loaderSame: true,
    binding: {
      keys: expectedKeys,
      frozen: true,
      nullPrototype: true,
      descriptorsExact: true,
      functionCount: 0,
      version: 1,
      kind: "darwin_trusted_clock_native_binding_private_cache_tombstone",
      callableSurfaceExposed: false,
      productionReady: false,
    },
    loader: {
      keys: expectedKeys,
      frozen: true,
      nullPrototype: true,
      descriptorsExact: true,
      functionCount: 0,
      version: 1,
      kind: "darwin_trusted_clock_loader_private_cache_tombstone",
      callableSurfaceExposed: false,
      productionReady: false,
    },
    bindingFunctionType: "undefined",
    loaderFunctionType: "undefined",
    sampleReason: "native_enrollment_unprovisioned",
  });
});

test("caller-selected construction and sample inputs fail closed and consume one-shot state", () => {
  let result = runChild([
    '"use strict";',
    `const clock=require(${JSON.stringify(CLIENT_MODULE)});`,
    "let first=null;let second=null;let secondReady=null;",
    "try{clock.createDarwinTrustedClockNativeClient({socket_path:'/tmp/fake'});}catch(error){first=error.reason_code;}",
    "try{const client=clock.createDarwinTrustedClockNativeClient();secondReady=client.production_ready;}catch(error){second=error.reason_code;}",
    "process.stdout.write(JSON.stringify({first,second,secondReady}));",
  ].join(""));
  assert.deepEqual(result, {
    first: "native_client_argument_injection",
    second: null,
    secondReady: false,
  });

  result = runChild([
    '"use strict";',
    `const clock=require(${JSON.stringify(CLIENT_MODULE)});`,
    "const client=clock.createDarwinTrustedClockNativeClient();",
    "let first=null;let second=null;",
    "try{client.sample('/tmp/fake');}catch(error){first=error.reason_code;}",
    "try{client.sample();}catch(error){second=error.reason_code;}",
    "process.stdout.write(JSON.stringify({first,second}));",
  ].join(""));
  assert.deepEqual(result, {
    first: "native_sample_argument_injection",
    second: "native_client_sample_consumed",
  });
});

test("preexisting native cache forgery and host dlopen drift reject before native use", () => {
  let result = runChild([
    '"use strict";',
    `const clientPath=${JSON.stringify(CLIENT_MODULE)};`,
    `const bindingPath=${JSON.stringify(BINDING_PATH)};`,
    "const clock=require(clientPath);",
    "require.cache[bindingPath]={exports:Object.freeze({sampleTrustedClockNative(){return {};}})};",
    "let code=null;let reason=null;",
    "try{clock.createDarwinTrustedClockNativeClient();}catch(error){code=error.code;reason=error.reason_code;}",
    "process.stdout.write(JSON.stringify({code,reason}));",
  ].join(""));
  assert.deepEqual(result, {
    code: "darwin_trusted_clock_native_client_rejected",
    reason: "native_binding_unavailable_or_untrusted",
  });

  result = runChild([
    '"use strict";',
    `const clientPath=${JSON.stringify(CLIENT_MODULE)};`,
    "const clock=require(clientPath);",
    "Object.defineProperty(process,'dlopen',{value:function fakeDlopen(){},writable:true,enumerable:true,configurable:true});",
    "let code=null;let reason=null;",
    "try{clock.createDarwinTrustedClockNativeClient();}catch(error){code=error.code;reason=error.reason_code;}",
    "process.stdout.write(JSON.stringify({code,reason}));",
  ].join(""));
  assert.deepEqual(result, {
    code: "darwin_trusted_clock_native_client_rejected",
    reason: "native_binding_unavailable_or_untrusted",
  });
});

test("internal loader and build-contract CommonJS cache substitution cannot inject callbacks", () => {
  let result = runChild([
    '"use strict";',
    `const clientPath=${JSON.stringify(CLIENT_MODULE)};`,
    `const loaderPath=${JSON.stringify(LOADER_MODULE)};`,
    "let calls=0;",
    "require.cache[loaderPath]={exports:Object.freeze({loadDarwinTrustedClockNativeBindingOnce(){calls+=1;return {sample(){calls+=1;}};}})};",
    "let code=null;let reason=null;",
    "try{require(clientPath);}catch(error){code=error.code;reason=error.reason_code;}",
    "process.stdout.write(JSON.stringify({code,reason,calls}));",
  ].join(""));
  assert.deepEqual(result, {
    code: "darwin_trusted_clock_native_client_rejected",
    reason: "native_loader_cache_prepopulated",
    calls: 0,
  });

  result = runChild([
    '"use strict";',
    `const loaderPath=${JSON.stringify(LOADER_MODULE)};`,
    `const contractPath=${JSON.stringify(BUILD_CONTRACT_MODULE)};`,
    "let calls=0;",
    "require.cache[contractPath]={exports:Object.freeze({verifyDarwinTrustedClockLocalBuild(){calls+=1;return {};}})};",
    "let code=null;let reason=null;",
    "try{require(loaderPath);}catch(error){code=error.code;reason=error.reason_code;}",
    "process.stdout.write(JSON.stringify({code,reason,calls}));",
  ].join(""));
  assert.deepEqual(result, {
    code: "darwin_trusted_clock_native_binding_rejected",
    reason: "build_contract_cache_prepopulated",
    calls: 0,
  });
});

test("post-import validation-intrinsic mutation fails closed without invoking drift", () => {
  const result = runChild([
    '"use strict";',
    `const clientPath=${JSON.stringify(CLIENT_MODULE)};`,
    "const clock=require(clientPath);",
    "const path=require('node:path');",
    "let calls=0;",
    "Object.isFrozen=()=>{calls+=1;return true;};",
    "Array.prototype.join=function(){calls+=1;throw new Error('join drift');};",
    "Array.prototype.push=function(){calls+=1;throw new Error('push drift');};",
    "Array.prototype.sort=function(){calls+=1;throw new Error('sort drift');};",
    "Buffer.alloc=function(){calls+=1;throw new Error('alloc drift');};",
    "Buffer.from=function(){calls+=1;throw new Error('from drift');};",
    "Buffer.prototype.fill=function(){calls+=1;throw new Error('fill drift');};",
    "Buffer.prototype.toString=function(){calls+=1;throw new Error('toString drift');};",
    "Buffer.prototype.writeBigUInt64BE=function(){calls+=1;throw new Error('write drift');};",
    "path.join=function(){calls+=1;throw new Error('join path drift');};",
    "path.resolve=function(){calls+=1;throw new Error('resolve path drift');};",
    "let code=null;let reason=null;",
    "try{clock.createDarwinTrustedClockNativeClient();}catch(error){code=error.code;reason=error.reason_code;}",
    "process.stdout.write(JSON.stringify({calls,code,reason}));",
  ].join(""));
  assert.deepEqual(result, {
    calls: 0,
    code: "darwin_trusted_clock_native_client_rejected",
    reason: "native_binding_unavailable_or_untrusted",
  });
});

test("raw native wrapper itself rejects arguments and atomically consumes the call", () => {
  const result = runChild([
    '"use strict";',
    `const raw=require(${JSON.stringify(BINDING_PATH)});`,
    "let first=null;let second=null;",
    "try{raw.sampleTrustedClockNative({socket_path:'/tmp/fake'});}catch(error){first=error.code;}",
    "try{raw.sampleTrustedClockNative();}catch(error){second=error.code;}",
    "process.stdout.write(JSON.stringify({first,second}));",
  ].join(""));
  assert.deepEqual(result, {
    first: "darwin_trusted_clock_native_argument_injection",
    second: "darwin_trusted_clock_native_sample_consumed",
  });
});

test("unprovisioned standalone service exits before launchd activation", () => {
  const result = spawnSync(SERVICE_PATH, [], {
    encoding: "utf8",
    timeout: 2000,
  });
  assert.equal(result.status, 1);
  assert.equal(result.signal, null);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
});

test("loaded native cache is immutable and CommonJS reload cannot reopen the client", () => {
  const result = runChild([
    '"use strict";',
    `const clientPath=${JSON.stringify(CLIENT_MODULE)};`,
    `const bindingPath=${JSON.stringify(BINDING_PATH)};`,
    "let clock=require(clientPath);",
    "clock.createDarwinTrustedClockNativeClient();",
    "const descriptor=Object.getOwnPropertyDescriptor(require.cache,bindingPath);",
    "let replacementRejected=false;",
    "try{Object.defineProperty(require.cache,bindingPath,{value:{exports:{}},writable:true,enumerable:true,configurable:true});}catch{replacementRejected=true;}",
    "delete require.cache[clientPath];",
    "clock=require(clientPath);",
    "let reopenReason=null;",
    "try{clock.createDarwinTrustedClockNativeClient();}catch(error){reopenReason=error.reason_code;}",
    "process.stdout.write(JSON.stringify({writable:descriptor.writable,configurable:descriptor.configurable,replacementRejected,reopenReason}));",
  ].join(""));
  assert.deepEqual(result, {
    writable: false,
    configurable: false,
    replacementRejected: true,
    reopenReason: "native_client_process_one_shot_consumed",
  });
});

test("source, artifact, receipt-authority, and prebuild tamper all fail closed", (t) => {
  let fixture = copyFixture(t);
  assert.equal(
    buildContract.verifyDarwinTrustedClockLocalBuild(fixture).production_ready,
    false,
  );
  fs.appendFileSync(path.join(fixture, "binding.gyp"), "\n");
  assert.throws(
    () => buildContract.verifyDarwinTrustedClockLocalBuild(fixture),
    (error) => error?.code === "darwin_trusted_clock_local_build_rejected",
  );

  fixture = copyFixture(t);
  fs.appendFileSync(
    path.join(fixture, "build", "Release", "trusted_clock_client.node"),
    Buffer.from([0]),
  );
  assert.throws(
    () => buildContract.verifyDarwinTrustedClockLocalBuild(fixture),
    (error) => error?.code === "darwin_trusted_clock_local_build_rejected",
  );

  fixture = copyFixture(t);
  const receiptPath = path.join(
    fixture,
    buildContract.DARWIN_TRUSTED_CLOCK_LOCAL_BUILD_RECEIPT_PATH,
  );
  const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  receipt.production_ready = true;
  fs.writeFileSync(
    receiptPath,
    `${buildContract._canonicalJsonForBuildReceipt(receipt)}\n`,
    { mode: 0o600 },
  );
  assert.throws(
    () => buildContract.verifyDarwinTrustedClockLocalBuild(fixture),
    (error) => reason(
      error,
      "darwin_trusted_clock_local_build_rejected",
      "build_receipt_authority_claim_invalid",
    ),
  );

  fixture = copyFixture(t);
  const prebuild = path.join(
    fixture,
    "prebuilds",
    "darwin-arm64",
    "trusted-clock-native-release.json",
  );
  fs.mkdirSync(path.dirname(prebuild), { recursive: true, mode: 0o700 });
  fs.writeFileSync(prebuild, "{}\n", { mode: 0o600 });
  const loader = path.join(fixture, "lib", "native-binding-loader.js");
  const result = runChild([
    '"use strict";',
    `const loader=require(${JSON.stringify(loader)});`,
    "let code=null;let reason=null;",
    "try{loader.loadDarwinTrustedClockNativeBindingOnce();}catch(error){code=error.code;reason=error.reason_code;}",
    "process.stdout.write(JSON.stringify({code,reason}));",
  ].join(""), fixture);
  assert.deepEqual(result, {
    code: "darwin_trusted_clock_native_binding_rejected",
    reason: "signed_prebuild_verifier_and_trust_root_missing",
  });
});

test("package allowlist remains source-only and excludes local products and receipts", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.equal(manifest.gypfile, false);
  assert.ok(manifest.files.includes("binding.gyp"));
  assert.ok(manifest.files.includes("scripts/*.js"));
  assert.ok(manifest.files.includes("test/*.test.js"));
  assert.ok(!manifest.files.some((entry) => /(?:build|prebuild|\.node)/u.test(entry)));
  assert.equal(manifest.exports["./native-client"], "./lib/native-client.js");
  assert.equal(manifest.exports["./build-contract"], undefined);
});
