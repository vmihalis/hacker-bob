"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  classifyRepoReachability,
  detectNetworkReachability,
  safeReadText,
} = require("../mcp/lib/reachability.js");
const {
  computeReachabilityDisposition,
  normalizeReachabilityDispositionStamp,
} = require("../mcp/lib/reachability-ceiling.js");

function withRepo(files, fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-reachability-"));
  try {
    for (const [rel, content] of Object.entries(files)) {
      const filePath = path.join(root, rel);
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, content, "utf8");
    }
    return fn(root, Object.keys(files).sort());
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function projectionFor(files) {
  return {
    modules: files
      .filter((rel) => /\.(c|cc|cpp|cxx|h|hh|hpp)$/i.test(rel) || path.basename(rel) === "CMakeLists.txt")
      .map((rel) => ({
        rel,
        language: path.extname(rel).toLowerCase() === ".cpp" ? "cpp" : "c",
        nativeSource: /\.(c|cc|cpp|cxx|h|hh|hpp)$/i.test(rel),
        nativeBuild: path.basename(rel) === "CMakeLists.txt",
      })),
  };
}

test("classifyRepoReachability keeps local native parsers at AV:L / medium", () => withRepo({
  "CMakeLists.txt": "cmake_minimum_required(VERSION 3.22)\nproject(local C)\n",
  "src/decode.c": "int decode(const unsigned char *buf, int len){ return len > 0 ? buf[0] : 0; }\n",
}, (root, files) => {
  const result = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const stamp = result.perSurface.get("src/decode.c");

  assert.equal(result.reachability.network_reachable, false);
  assert.equal(result.reachability.max_credible_severity_ceiling, "medium");
  assert.equal(stamp.attack_vector, "local");
  assert.equal(stamp.severity_ceiling, "medium");
}));

test("classifyRepoReachability detects network daemon anchors deterministically", () => withRepo({
  "CMakeLists.txt": "cmake_minimum_required(VERSION 3.22)\nproject(daemon C)\n",
  "daemon/server.c": [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
  ].join("\n"),
  "parsers/conf.c": "int parse_conf(const char *b, int n){ return n > 0 ? b[0] : 0; }\n",
}, (root, files) => {
  const first = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const second = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const daemon = first.perSurface.get("daemon/server.c");
  const parser = first.perSurface.get("parsers/conf.c");

  assert.deepEqual(first.reachability, second.reachability);
  assert.equal(first.reachability.network_reachable, true);
  assert.equal(first.reachability.max_credible_severity_ceiling, "critical");
  assert.equal(daemon.attack_vector, "network");
  assert.equal(daemon.severity_ceiling, "critical");
  assert.equal(parser.attack_vector, "local");
  assert.equal(parser.severity_ceiling, "medium");
  assert.deepEqual(parser.network_reachable_anchors, []);
  assert.deepEqual(parser.network_reachable_dirs, []);
}));

test("detectNetworkReachability handles digit XDR tokens and ignores non-shipping demos", () => withRepo({
  "src/proto_xdr.c": "int xdr_msg(XDR *xdrs, struct msg *m){ return xdr_uint32_t(xdrs, &m->id); }\n",
  "examples/echo_server.c": "int main(void){ int fd = socket(AF_INET, SOCK_STREAM, 0); listen(fd, 16); return fd; }\n",
}, (root, files) => {
  const reachable = detectNetworkReachability(root, files);
  assert.equal(reachable.network_reachable, true);
  assert.ok(reachable.signals.some((signal) => signal === "net_call:src/proto_xdr.c"));
  assert.ok(!reachable.signals.some((signal) => signal.includes("examples/echo_server.c")));
}));

test("safeReadText refuses symlink escapes outside the repo root", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bob-reachability-root-"));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "bob-reachability-outside-"));
  try {
    fs.mkdirSync(path.join(root, "src"), { recursive: true });
    const outsideFile = path.join(outside, "server.c");
    fs.writeFileSync(outsideFile, "int main(void){ int fd = socket(AF_INET, SOCK_STREAM, 0); listen(fd, 16); return fd; }\n");
    try {
      fs.symlinkSync(outsideFile, path.join(root, "src", "server.c"));
    } catch {
      return;
    }

    assert.equal(safeReadText(root, "src/server.c"), null);
    const reachable = detectNetworkReachability(root, ["src/server.c"]);
    assert.equal(reachable.network_reachable, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("top-level src server anchors do not promote sibling parser files to AV:N", () => withRepo({
  "CMakeLists.txt": "cmake_minimum_required(VERSION 3.22)\nproject(src_server C)\n",
  "src/server.c": [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
  ].join("\n"),
  "src/parser.c": "int parse(const char *b, int n){ return n > 0 ? b[0] : 0; }\n",
}, (root, files) => {
  const result = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const server = result.perSurface.get("src/server.c");
  const parser = result.perSurface.get("src/parser.c");

  assert.equal(result.reachability.network_reachable, true);
  assert.equal(server.attack_vector, "network");
  assert.equal(parser.attack_vector, "local");
  assert.equal(parser.severity_ceiling, "medium");
  assert.ok(result.reachability.native_attack_vector_map.network_reachable_anchors.includes("src/server.c"));
  assert.ok(!result.reachability.native_attack_vector_map.network_reachable_dirs.includes("src"));
}));

test("semantic top-level server dirs can promote sibling native handlers", () => withRepo({
  "CMakeLists.txt": "cmake_minimum_required(VERSION 3.22)\nproject(server_dir C)\n",
  "server/httpd.c": [
    "#include <sys/socket.h>",
    "#include <netinet/in.h>",
    "int serve(void){",
    "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
    "  listen(fd, 16);",
    "  return fd;",
    "}",
  ].join("\n"),
  "server/handler.c": "int handle(const char *b, int n){ return n > 0 ? b[0] : 0; }\n",
}, (root, files) => {
  const result = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const handler = result.perSurface.get("server/handler.c");

  assert.equal(handler.attack_vector, "network");
  assert.equal(handler.severity_ceiling, "critical");
  assert.ok(result.reachability.native_attack_vector_map.network_reachable_dirs.includes("server"));
}));

test("server path hints do not exhaust concrete net_call attribution", () => {
  const files = {};
  for (let i = 0; i < 18; i += 1) {
    files[`server/daemon-${String(i).padStart(2, "0")}.c`] = [
      "#include <sys/socket.h>",
      "#include <netinet/in.h>",
      `int serve_${i}(void){`,
      "  int fd = socket(AF_INET, SOCK_STREAM, 0);",
      "  listen(fd, 16);",
      "  return fd;",
      "}",
    ].join("\n");
  }
  withRepo(files, (root, rels) => {
    const reachable = detectNetworkReachability(root, rels);
    const netCalls = reachable.signals.filter((signal) => signal.startsWith("net_call:"));

    assert.equal(reachable.network_reachable, true);
    assert.ok(netCalls.length > 1, "content scans should produce multiple net_call anchors");
  });
});

test("token-only native headers do not create network reachability", () => withRepo({
  "server/socket_types.h": [
    "#include <netinet/in.h>",
    "struct socket_config {",
    "  struct sockaddr_in bind_addr;",
    "  int kind;",
    "};",
    "#define DEFAULT_KIND SOCK_STREAM",
  ].join("\n"),
  "src/parser.c": "int parse(const char *b, int n){ return n > 0 ? b[0] : 0; }\n",
}, (root, files) => {
  const reachable = detectNetworkReachability(root, files);
  const result = classifyRepoReachability({ repoRoot: root, files, projection: projectionFor(files) });
  const header = result.perSurface.get("server/socket_types.h");

  assert.equal(reachable.network_reachable, false);
  assert.equal(header.attack_vector, "local");
  assert.equal(header.severity_ceiling, "medium");
}));

test("computeReachabilityDisposition caps, certifies, and preserves unknowns", () => {
  assert.deepEqual(
    computeReachabilityDisposition("high", {
      severity_ceiling: "medium",
      attack_vector: "local",
      network_reachable: false,
    }),
    {
      recorded_severity: "high",
      severity_ceiling: "medium",
      attack_vector: "local",
      network_reachable: false,
      graded_severity: "medium",
      disposition: "capped",
      defensible: false,
      reachability_source: "heuristic",
    },
  );

  assert.deepEqual(
    computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
    }),
    {
      recorded_severity: "high",
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      graded_severity: "high",
      disposition: "lifted",
      defensible: true,
      reachability_source: "heuristic",
    },
  );

  assert.deepEqual(
    computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      reachability_divergence: "invalid reachability assertion in C-ABC123: malformed",
    }),
    {
      recorded_severity: "high",
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      graded_severity: "high",
      disposition: "lifted",
      defensible: false,
      reachability_source: "heuristic",
      reachability_divergence: "invalid reachability assertion in C-ABC123: malformed",
    },
  );

  assert.deepEqual(
    computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      reachability_source: "asserted",
      call_path: "listener -> parser -> sink",
    }),
    {
      recorded_severity: "high",
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      graded_severity: "high",
      disposition: "lifted",
      defensible: false,
      reachability_source: "asserted",
      call_path: "listener -> parser -> sink",
    },
  );

  assert.throws(
    () => computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      reachability_source: "asserted-v2",
    }),
    /reachability\.reachability_source must be one of/,
  );
  assert.throws(
    () => computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      reachability_source: "asserted",
    }),
    /reachability\.call_path is required when reachability_source is "asserted"/,
  );
  assert.throws(
    () => computeReachabilityDisposition("high", {
      severity_ceiling: "critical",
      attack_vector: "network",
      network_reachable: true,
      call_path: "listener -> parser -> sink",
    }),
    /reachability\.call_path is only allowed when reachability_source is "asserted"/,
  );

  assert.deepEqual(
    computeReachabilityDisposition("medium", null),
    {
      recorded_severity: "medium",
      severity_ceiling: "unknown",
      attack_vector: "unknown",
      network_reachable: null,
      graded_severity: "medium",
      disposition: "unknown",
      defensible: false,
      reachability_source: "none",
    },
  );
});

test("normalizeReachabilityDispositionStamp rejects impossible provenance combinations", () => {
  const base = {
    recorded_severity: "high",
    severity_ceiling: "critical",
    attack_vector: "network",
    network_reachable: true,
    graded_severity: "high",
    disposition: "lifted",
    defensible: true,
  };
  assert.throws(
    () => normalizeReachabilityDispositionStamp({
      ...base,
      reachability_source: "none",
    }),
    /reachability\.reachability_source must not be "none" unless disposition is "unknown"/,
  );
  assert.throws(
    () => normalizeReachabilityDispositionStamp({
      ...base,
      reachability_source: "asserted",
    }),
    /reachability\.call_path is required when reachability_source is "asserted"/,
  );
  assert.throws(
    () => normalizeReachabilityDispositionStamp({
      ...base,
      reachability_source: "heuristic",
      call_path: "listener -> parser -> sink",
    }),
    /reachability\.call_path is only allowed when reachability_source is "asserted"/,
  );
  assert.throws(
    () => normalizeReachabilityDispositionStamp({
      ...base,
      reachability_source: "asserted",
      call_path: "listener -> parser\n## forged grade section -> sink",
    }),
    /reachability\.call_path must not contain line breaks/,
  );
  assert.throws(
    () => normalizeReachabilityDispositionStamp({
      ...base,
      severity_ceiling: "unknown",
      attack_vector: "unknown",
      network_reachable: null,
      disposition: "unknown",
      reachability_source: "asserted",
    }),
    /reachability\.reachability_source must be "none" when disposition is "unknown"/,
  );
  assert.deepEqual(
    normalizeReachabilityDispositionStamp({
      ...base,
      reachability_source: "asserted",
      call_path: "listener -> parser -> sink",
    }),
    {
      ...base,
      reachability_source: "asserted",
      call_path: "listener -> parser -> sink",
    },
  );
});
