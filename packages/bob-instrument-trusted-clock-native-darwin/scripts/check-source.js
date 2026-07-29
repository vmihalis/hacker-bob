"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const HEADER = path.join(ROOT, "native", "trusted_clock_protocol.h");
const SERVICE = path.join(ROOT, "native", "trusted_clock_service.cc");
const CLIENT = path.join(ROOT, "native", "trusted_clock_client.cc");
const NODE_WRAPPER = path.join(ROOT, "native", "trusted_clock_node.cc");
const BINDING = path.join(ROOT, "binding.gyp");
const headerText = fs.readFileSync(HEADER, "utf8");
const serviceText = fs.readFileSync(SERVICE, "utf8");
const clientText = fs.readFileSync(CLIENT, "utf8");
const nodeWrapperText = fs.readFileSync(NODE_WRAPPER, "utf8");
const bindingText = fs.readFileSync(BINDING, "utf8");
const allSource = `${headerText}\n${serviceText}\n${clientText}\n${nodeWrapperText}\n${bindingText}`;

function requirePattern(text, label, pattern) {
  if (!pattern.test(text)) throw new Error(`trusted-clock structural invariant missing: ${label}`);
}

function requireOrder(text, label, first, second) {
  const firstIndex = text.indexOf(first);
  const secondIndex = text.indexOf(second);
  if (firstIndex < 0 || secondIndex < 0 || firstIndex >= secondIndex) {
    throw new Error(`trusted-clock source order invalid: ${label}`);
  }
}

for (const required of [
  "HB_CLOCK_SOURCE_PROVISIONED = 0",
  "io.hacker-bob.physical.trusted-clockd",
  "io.hacker-bob.physical.trusted-clock-client",
  "_hackerbobclock",
  "/private/var/run/hacker-bob/physical-trusted-clock-v1.sock",
  "UNPROVISIONED",
  "LOCAL_PEERTOKEN",
  "LOCAL_PEERPID",
  "getpeereid(",
  "audit_token_to_pidversion(",
  "SecCodeCopyGuestWithAttributes(",
  "kSecGuestAttributeAudit",
  "mach_continuous_time(",
  "kern.bootsessionuuid",
  "sysctlbyname(",
  "launch_activate_socket(",
  "SecRandomCopyBytes(",
  "HB_CLOCK_MAX_SAMPLES_PER_CONNECTION = 1",
  "HB_CLOCK_IO_TIMEOUT_SECONDS = 2",
  "SO_RCVTIMEO",
  "SO_SNDTIMEO",
  "SO_NOSIGPIPE",
  "FD_CLOEXEC",
  "NAPI_MODULE(NODE_GYP_MODULE_NAME, Initialize)",
  "sampleTrustedClockNative",
  "g_sample_consumed.exchange(true",
  "trusted_clock_client.cc",
  "trusted_clock_service.cc",
]) {
  if (!allSource.includes(required)) {
    throw new Error(`trusted-clock native invariant missing: ${required}`);
  }
}

requirePattern(headerText, "exact frame and one-sample bounds",
  /HB_CLOCK_REQUEST_BYTES = 64,[\s\S]*HB_CLOCK_RESPONSE_BYTES = 232,[\s\S]*HB_CLOCK_MAX_SAMPLES_PER_CONNECTION = 1/u);
requirePattern(headerText, "unprovisioned principal ids",
  /HB_CLOCK_SERVICE_UID = UINT32_MAX;[\s\S]*HB_CLOCK_CLIENT_UID = UINT32_MAX;/u);
for (const [label, text] of [["service", serviceText], ["client", clientText]]) {
  requirePattern(text, `${label} connected descriptor custody`,
    /bool ConfigureConnectedSocket\(int descriptor\)[\s\S]{0,1200}?F_SETFD[\s\S]{0,400}?FD_CLOEXEC[\s\S]{0,400}?SO_NOSIGPIPE[\s\S]{0,400}?SO_RCVTIMEO[\s\S]{0,400}?SO_SNDTIMEO/u);
  requirePattern(text, `${label} volatile scrub primitive`,
    /void SecureZero\(void\* bytes, size_t length\)[\s\S]{0,180}?volatile uint8_t\*/u);
  requirePattern(text, `${label} peer-request-response RAII scrub`,
    /ScopedScrub peer_scrub[\s\S]*ScopedScrub request_scrub[\s\S]*ScopedScrub response_scrub/u);
  requirePattern(text, `${label} exact frame end-of-stream check`,
    /bool ReadEndOfStream\(int descriptor\)/u);
  requirePattern(text, `${label} kernel peer identity and live code binding`,
    /bool ReadPeerIdentity\([\s\S]{0,1800}?LOCAL_PEERTOKEN[\s\S]{0,500}?LOCAL_PEERPID[\s\S]{0,500}?getpeereid\([\s\S]{0,800}?audit_token_to_pidversion[\s\S]{0,500}?expected_uid[\s\S]{0,700}?CheckCodeRequirement/u);
  requirePattern(text, `${label} audit-token SecCode requirement validation`,
    /kSecGuestAttributeAudit[\s\S]{0,900}?SecCodeCopyGuestWithAttributes\([\s\S]{0,900}?SecRequirementCreateWithString\([\s\S]{0,500}?SecCodeCheckValidity\(/u);
}
requirePattern(serviceText, "launchd listener type/path/CLOEXEC validation",
  /bool ValidateLaunchdListener\(int descriptor\)[\s\S]{0,1800}?FD_CLOEXEC[\s\S]{0,500}?SO_TYPE[\s\S]{0,500}?SOCK_STREAM[\s\S]{0,500}?SO_ACCEPTCONN[\s\S]{0,700}?getsockname\([\s\S]{0,700}?HB_CLOCK_SOCKET_PATH/u);
requirePattern(serviceText, "accepted descriptor configured before request",
  /ConfigureConnectedSocket\(connection\)\s*&& HandleOneConnection\(connection\)/u);
requirePattern(serviceText, "boot UUID and derived buffers scrubbed",
  /ScopedScrub first_scrub[\s\S]*ScopedScrub second_scrub[\s\S]*ScopedScrub challenge_digest_scrub[\s\S]*ScopedScrub boot_epoch_scrub/u);
requirePattern(serviceText, "double-read boot epoch surrounds continuous clock",
  /ReadBootSession\(first,[\s\S]{0,500}?mach_continuous_time\(\)[\s\S]{0,500}?ReadBootSession\(second,[\s\S]{0,300}?memcmp\(first, second,/u);
const serviceMain = serviceText.slice(serviceText.indexOf("int main("));
requireOrder(serviceMain, "listener validation precedes accept loop",
  "if (!ValidateLaunchdListener(listener))", "const int connection = accept(");
requireOrder(clientText, "timeouts and SO_NOSIGPIPE precede connect",
  "if (!ConfigureConnectedSocket(connection))", "if (connect(connection");
requirePattern(clientText, "client half-close and response EOF",
  /WriteExact\(connection,[\s\S]{0,300}?shutdown\(connection, SHUT_WR\)[\s\S]{0,300}?ReadExact\(connection,[\s\S]{0,300}?ReadEndOfStream\(connection\)/u);
requirePattern(clientText, "derived response digests scrubbed",
  /ScopedScrub challenge_scrub[\s\S]*ScopedScrub sample_scrub/u);

for (const forbidden of [
  { label: "process.hrtime", pattern: /process\.hrtime/u },
  { label: "CLOCK_REALTIME", pattern: /CLOCK_REALTIME/u },
  { label: "mach_absolute_time", pattern: /mach_absolute_time/u },
  { label: "gettimeofday", pattern: /gettimeofday/u },
  { label: "environment-selected socket", pattern: /getenv\s*\(/u },
  { label: "argument-selected socket", pattern: /--(?:socket|path|clock)/u },
]) {
  if (forbidden.pattern.test(allSource)) {
    throw new Error(`forbidden trusted-clock source dependency: ${forbidden.label}`);
  }
}

if (!/extern "C" int hb_trusted_clock_sample\(hb_clock_source_sample\* output\)/u
  .test(clientText)) {
  throw new Error("trusted-clock client must expose only its fixed output-buffer API");
}
if (/hb_trusted_clock_sample\([^)]*,/u.test(clientText)) {
  throw new Error("trusted-clock client API accepts caller-selected inputs");
}
const clientSample = clientText.slice(clientText.indexOf(
  'extern "C" int hb_trusted_clock_sample',
));
requireOrder(clientSample, "unprovisioned client rejection precedes socket creation",
  "if (!QualifiedEnrollmentPresent())", "if (!ConnectFixedEndpoint(&connection))");
requireOrder(serviceMain, "unprovisioned service rejection precedes launchd activation",
  "if (argc != 1 || !QualifiedEnrollmentPresent())", "launch_activate_socket(");
requirePattern(nodeWrapperText, "zero-argument Node-API sample",
  /size_t argc = 0;[\s\S]{0,500}?argc != 0[\s\S]{0,800}?g_sample_consumed\.exchange\(true,[\s\S]{0,500}?hb_trusted_clock_sample\(&sample\)/u);
requirePattern(nodeWrapperText, "native sample and output scrub",
  /hb_clock_source_sample sample\{\};[\s\S]{0,200}?ScopedSampleScrub scrub\(&sample\)/u);
requirePattern(bindingText, "explicit Node 20 N-API 9 wrapper target",
  /"target_name": "trusted_clock_client"[\s\S]*"native\/trusted_clock_node\.cc"[\s\S]*"NAPI_VERSION=9"/u);
requirePattern(bindingText, "standalone service target",
  /"target_name": "trusted_clock_service"[\s\S]{0,200}?"type": "executable"/u);

if (process.platform !== "darwin" || process.arch !== "arm64") {
  throw new Error("Darwin arm64 is required for trusted-clock native source checks");
}

function capture(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `${command} failed`);
  }
  return result.stdout.trim();
}

const sdk = capture("/usr/bin/xcrun", ["--sdk", "macosx", "--show-sdk-path"]);
const clang = capture("/usr/bin/xcrun", ["--find", "clang++"]);
for (const source of [SERVICE, CLIENT]) {
  const result = spawnSync(clang, [
    "-std=c++17",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wpedantic",
    "-Wshadow",
    "-Wconversion",
    "-Wsign-conversion",
    "-Wno-deprecated-declarations",
    "-Wno-unused-const-variable",
    "-D_FORTIFY_SOURCE=2",
    "-mmacosx-version-min=13.0",
    "-isysroot",
    sdk,
    "-fsyntax-only",
    source,
  ], { encoding: "utf8" });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || "strict source check failed\n");
    process.exit(result.status || 1);
  }
}
