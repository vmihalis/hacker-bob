"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const {
  assertSafeDomain,
  invariantRunsJsonlPath,
  invariantVerifiedJsonlPath,
  sessionsRoot,
} = require("./paths.js");
const {
  parseFindingId,
} = require("./validation.js");
const {
  suggestInvariantsForFinding,
  CROSS_STACK_CONSUME_TEMPLATE_ID,
} = require("./invariant-template-corpus.js");
const {
  DEFAULT_ARTIFACT_READ_MAX_BYTES,
  appendJsonlLine,
  withSessionLock,
} = require("./storage.js");
const { ERROR_CODES } = require("./envelope.js");
const { hashCanonicalJson } = require("./verification-contracts.js");
// Cycle B: KEY invariant-runs.jsonl rows with a domain-separated ed25519 signature so a
// forged row needs the signing key, not just a recomputable content hash. signed at
// WRITE inside withInvariantSessionWriteLock; verified at the read-time re-derivation
// sites (readInvariantRunRowForVerification, proof-bundle readInvariantRunRow). Reuses
// Cycle A's signRowWithMac/verifyRowWithMac (NOT a new MAC). Old unsigned rows are
// accepted-with-warning (assertRowMacOrLegacy {legacy}); only NEW rows carry row_mac.
// This does NOT close F3 — the private key is still 0600 at the agent uid, so a same-uid
// actor can mint a valid row_mac; F2 collapses INTO F3. The genuine close is Cycle C.
const {
  assertRowMac,
  assertRowMacOrLegacy,
  INVARIANT_RUN_MAC_CONTEXT,
  OFFENSIVE_ROW_MAC_CONTEXT,
} = require("./offensive-row-mac.js");
const {
  signRowViaIsolatedSignerOrLocal,
  resolveRowVerifierSafely,
} = require("./handoff-signing-key.js");
const {
  readOffensiveCaptureBytesSecure,
} = require("./claim-freeze.js");
const {
  readOffensiveRunRecords,
} = require("./claims.js");
// REFUTING-ARM (universal): an FV finding is CONFIRMED only by an executed
// two-sided differential whose negative arm FLIPS — never by a single passing
// run. We reuse the OSS repro gate's verdict vocabulary AND its branch order so a
// verified FV verdict is graded identically to a verified reproduction
// (LEDGER consistency). adjudicateInvariantDifferential below is the violation-
// semantics retarget of repro-replay-verifier.js::adjudicateDifferential.
const {
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
} = require("./repro-replay-verifier.js");

const INVARIANT_VERIFIED_VERSION = 1;
const INVARIANT_VERIFIED_MAX_RECORDS = 2000;

const TEST_FUNCTION_PREFIX = "testBobInvariant_";
const TEST_CONTRACT_PREFIX = "BobInvariantTest_";
const SESSION_WRITE_LOCK_ATTEMPTS = 120;
const SESSION_WRITE_LOCK_DELAY_MS = 25;
const READ_CHUNK_BYTES = 64 * 1024;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function normalizeRequiredFindingId(finding) {
  if (!finding || finding.finding_id == null) {
    throw new Error("finding.finding_id must be the Bob F-N id for the final finding");
  }
  return parseFindingId(finding.finding_id, "finding.finding_id");
}

function resolveInvariantRunsFilePath(filePath, { createDir = false } = {}) {
  const nominalDir = path.dirname(filePath);
  if (createDir) {
    fs.mkdirSync(nominalDir, { recursive: true });
  }
  if (!fs.existsSync(nominalDir)) {
    return filePath;
  }
  const realRoot = fs.realpathSync(sessionsRoot());
  const realDir = fs.realpathSync(nominalDir);
  const expectedDir = path.join(realRoot, path.basename(nominalDir));
  if (realDir !== expectedDir) {
    throw new Error(`invariant-runs.jsonl directory must stay inside its session root without domain-directory symlinks: ${nominalDir}`);
  }
  return path.join(realDir, path.basename(filePath));
}

function readInvariantRunsFileUtf8(filePath, { symlinkAsEmpty = false } = {}) {
  const noFollowFlag = fs.constants.O_NOFOLLOW || 0;
  if (!noFollowFlag) {
    let entry = null;
    try {
      entry = fs.lstatSync(filePath);
    } catch (error) {
      if (error && error.code === "ENOENT") return "";
      throw error;
    }
    if (entry.isSymbolicLink()) {
      if (symlinkAsEmpty) return "";
      throw new Error(`invariant-runs.jsonl must be a regular file, not a symlink: ${filePath}`);
    }
  }
  const flags = fs.constants.O_RDONLY | noFollowFlag;
  let fd = null;
  try {
    fd = fs.openSync(filePath, flags);
  } catch (error) {
    if (error && error.code === "ENOENT") return "";
    if (error && error.code === "ELOOP") {
      if (symlinkAsEmpty) return "";
      throw new Error(`invariant-runs.jsonl must be a regular file, not a symlink: ${filePath}`);
    }
    throw error;
  }

  try {
    const entry = fs.fstatSync(fd);
    if (!entry.isFile()) {
      throw new Error(`invariant-runs.jsonl must be a regular file: ${filePath}`);
    }
    if (entry.nlink > 1) {
      if (symlinkAsEmpty) return "";
      throw new Error(`invariant-runs.jsonl must not be hard-linked: ${filePath}`);
    }
    if (DEFAULT_ARTIFACT_READ_MAX_BYTES != null && entry.size > DEFAULT_ARTIFACT_READ_MAX_BYTES) {
      throw new Error(`invariant-runs.jsonl exceeds read cap of ${DEFAULT_ARTIFACT_READ_MAX_BYTES} bytes: ${filePath}`);
    }
    return readFdUtf8Capped(fd, filePath, DEFAULT_ARTIFACT_READ_MAX_BYTES);
  } finally {
    try { fs.closeSync(fd); } catch {}
  }
}

function readFdUtf8Capped(fd, filePath, maxBytes) {
  const chunks = [];
  let total = 0;
  const chunkSize = maxBytes == null
    ? READ_CHUNK_BYTES
    : Math.min(READ_CHUNK_BYTES, maxBytes + 1);
  const buffer = Buffer.allocUnsafe(chunkSize);
  while (true) {
    const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
    if (bytesRead === 0) break;
    total += bytesRead;
    if (maxBytes != null && total > maxBytes) {
      throw new Error(`invariant-runs.jsonl exceeds read cap of ${maxBytes} bytes: ${filePath}`);
    }
    chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
  }
  return Buffer.concat(chunks, total).toString("utf8");
}

function readJsonlRuns(filePath, { symlinkAsEmpty = false } = {}) {
  const raw = readInvariantRunsFileUtf8(filePath, { symlinkAsEmpty });
  if (raw.length === 0) return [];
  const lines = raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const records = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      records.push(JSON.parse(lines[i]));
    } catch (err) {
      throw new Error(`Malformed invariant-runs.jsonl at line ${i + 1}: ${err.message || String(err)}`);
    }
  }
  return records;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isSessionLockBusy(error) {
  return error
    && error.code === ERROR_CODES.STATE_CONFLICT
    && /Session lock busy/i.test(error.message || "");
}

async function withInvariantSessionWriteLock(domain, callback) {
  for (let attempt = 0; attempt < SESSION_WRITE_LOCK_ATTEMPTS; attempt += 1) {
    try {
      return withSessionLock(domain, callback);
    } catch (error) {
      if (!isSessionLockBusy(error) || attempt + 1 >= SESSION_WRITE_LOCK_ATTEMPTS) {
        throw error;
      }
      await sleep(SESSION_WRITE_LOCK_DELAY_MS);
    }
  }
  throw new Error("unreachable invariant session lock retry state");
}

function writeJsonlRuns(filePath, runs) {
  const sorted = runs.slice().sort((a, b) => {
    const aHash = typeof a.run_hash === "string" ? a.run_hash : "";
    const bHash = typeof b.run_hash === "string" ? b.run_hash : "";
    return aHash.localeCompare(bHash);
  });
  const realFilePath = resolveInvariantRunsFilePath(filePath, { createDir: true });
  const retention = serializeInvariantRunsWithinCap(sorted, realFilePath);
  const realDir = fs.realpathSync(path.dirname(realFilePath));
  writeFileThroughExclusiveSiblingTemp(realDir, path.basename(filePath), retention.content, "invariant-runs.jsonl");
  return {
    total: sorted.length,
    retained: retention.retained,
    dropped: retention.dropped,
    max_bytes: DEFAULT_ARTIFACT_READ_MAX_BYTES,
  };
}

function serializeInvariantRuns(runs) {
  if (runs.length === 0) return "";
  return `${runs.map((run) => JSON.stringify(run)).join("\n")}\n`;
}

function invariantRunTimestamp(run) {
  const timestamp = run && typeof run.recorded_at === "string" ? Date.parse(run.recorded_at) : NaN;
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function compareInvariantRunsForRetention(a, b) {
  const timeDelta = invariantRunTimestamp(b) - invariantRunTimestamp(a);
  if (timeDelta !== 0) return timeDelta;
  const aHash = a && typeof a.run_hash === "string" ? a.run_hash : "";
  const bHash = b && typeof b.run_hash === "string" ? b.run_hash : "";
  return bHash.localeCompare(aHash);
}

function serializeInvariantRunsWithinCap(sortedRuns, filePath) {
  const maxBytes = DEFAULT_ARTIFACT_READ_MAX_BYTES;
  if (maxBytes == null) {
    return {
      content: serializeInvariantRuns(sortedRuns),
      retained: sortedRuns.length,
      dropped: 0,
    };
  }
  for (const run of sortedRuns) {
    const singleRecord = serializeInvariantRuns([run]);
    if (Buffer.byteLength(singleRecord, "utf8") > maxBytes) {
      throw new Error(`invariant-runs.jsonl record exceeds write cap of ${maxBytes} bytes: ${filePath}`);
    }
  }

  let retained = sortedRuns.slice();
  let content = serializeInvariantRuns(retained);
  if (Buffer.byteLength(content, "utf8") <= maxBytes) {
    return {
      content,
      retained: retained.length,
      dropped: 0,
    };
  }

  retained = sortedRuns.slice().sort(compareInvariantRunsForRetention);
  while (retained.length > 0) {
    const ordered = retained.slice().sort((a, b) => {
      const aHash = typeof a.run_hash === "string" ? a.run_hash : "";
      const bHash = typeof b.run_hash === "string" ? b.run_hash : "";
      return aHash.localeCompare(bHash);
    });
    content = serializeInvariantRuns(ordered);
    if (Buffer.byteLength(content, "utf8") <= maxBytes) {
      return {
        content,
        retained: retained.length,
        dropped: sortedRuns.length - retained.length,
      };
    }
    retained.pop();
  }
  return {
    content: "",
    retained: 0,
    dropped: sortedRuns.length,
  };
}

function deriveTestNamesFromTemplate(template, finding, slotValues = null) {
  const sliceForName = (input) => {
    const cleaned = String(input || "").replace(/[^A-Za-z0-9]/g, "_").replace(/_+/g, "_").replace(/^_|_$/g, "");
    return cleaned.slice(0, 32) || "Generic";
  };
  const slotIdentity = isPlainObject(slotValues) && Object.keys(slotValues).length > 0
    ? `:${hashCanonicalJson(slotValues)}`
    : "";
  const idHash = crypto
    .createHash("sha256")
    .update(`${template.template_id}:${finding.finding_hash || finding.title || ""}${slotIdentity}`)
    .digest("hex")
    .slice(0, 8);
  const baseName = sliceForName(template.template_id);
  return {
    contract_name: `${TEST_CONTRACT_PREFIX}${baseName}_${idHash}`,
    function_name: `${TEST_FUNCTION_PREFIX}${baseName}_${idHash}`,
  };
}

function renameTestFunction(testBody, functionName) {
  const body = String(testBody);
  const matches = findSolidityFunctionDeclarations(body);
  if (matches.length !== 1) {
    throw new Error(`Invariant template must contain exactly one function declaration; found ${matches.length}`);
  }
  const match = matches[0];
  return `${body.slice(0, match.nameStart)}${functionName}${body.slice(match.nameEnd)}`;
}

function findSolidityFunctionDeclarations(body) {
  const matches = [];
  let i = 0;
  let atLineStart = true;
  let inLineComment = false;
  let inBlockComment = false;
  let inString = null;

  while (i < body.length) {
    const char = body[i];
    const next = body[i + 1];

    if (inString) {
      if (char === "\\") {
        i += 2;
        continue;
      }
      if (char === inString) {
        inString = null;
      }
      i += 1;
      continue;
    }

    if (inLineComment) {
      if (char === "\n") {
        inLineComment = false;
        atLineStart = true;
      }
      i += 1;
      continue;
    }

    if (inBlockComment) {
      if (char === "*" && next === "/") {
        inBlockComment = false;
        i += 2;
        continue;
      }
      if (char === "\n") atLineStart = true;
      i += 1;
      continue;
    }

    if (char === "/" && next === "/") {
      inLineComment = true;
      i += 2;
      continue;
    }
    if (char === "/" && next === "*") {
      inBlockComment = true;
      i += 2;
      continue;
    }
    if (char === "\"" || char === "'") {
      inString = char;
      atLineStart = false;
      i += 1;
      continue;
    }
    if (char === "\n") {
      atLineStart = true;
      i += 1;
      continue;
    }
    if (atLineStart && (char === " " || char === "\t")) {
      i += 1;
      continue;
    }
    if (atLineStart && body.startsWith("function", i) && /\s/.test(body[i + "function".length] || "")) {
      let cursor = i + "function".length;
      while (/\s/.test(body[cursor] || "")) cursor += 1;
      const nameStart = cursor;
      if (!/[A-Za-z_$]/.test(body[cursor] || "")) {
        atLineStart = false;
        i += 1;
        continue;
      }
      cursor += 1;
      while (/[A-Za-z0-9_$]/.test(body[cursor] || "")) cursor += 1;
      const nameEnd = cursor;
      cursor = skipSolidityWhitespaceAndBlockComments(body, cursor);
      if (body[cursor] === "(") {
        matches.push({ nameStart, nameEnd });
      }
      atLineStart = false;
      i = cursor + 1;
      continue;
    }
    atLineStart = false;
    i += 1;
  }
  return matches;
}

function skipSolidityWhitespaceAndBlockComments(body, cursor) {
  while (cursor < body.length) {
    while (/\s/.test(body[cursor] || "")) cursor += 1;
    if (body[cursor] === "/" && body[cursor + 1] === "*") {
      cursor += 2;
      while (cursor < body.length && !(body[cursor] === "*" && body[cursor + 1] === "/")) {
        cursor += 1;
      }
      if (cursor < body.length) cursor += 2;
      continue;
    }
    break;
  }
  return cursor;
}

function buildTestSource({ contractName, functionBody }) {
  const lines = [
    "// SPDX-License-Identifier: UNLICENSED",
    "pragma solidity >=0.8.0;",
    "",
    "import \"forge-std/Test.sol\";",
    "",
    `contract ${contractName} is Test {`,
    "    address public target;",
    "",
    "    function setUp() public virtual {",
    "        // The runner expects the harness to override setUp via inheritance",
    "        // when the template references concrete contracts.",
    "    }",
    "",
    // CROSS-STACK CONSUME (corpus-injected, NOT agent-authored). The bytes the stack-A
    // attack captured are delivered as the hex-encoded BOB_CONSUMED_ARTIFACT subprocess
    // env var. vm.envOr returns the empty default when ABSENT, so the control arm (empty
    // env) and any old template that never calls this read the empty value — backward
    // compatible. A template that consumes the artifact feeds these bytes into the
    // violated call; the empty-env control is the discriminator that proves the artifact
    // MATTERED (the flip), never an asserted format. vm.parseBytes decodes the env's hex.
    ...indentLines([
      "function bobConsumedArtifact() internal view returns (bytes memory) {",
      "    string memory hexStr = vm.envOr(\"BOB_CONSUMED_ARTIFACT\", string(\"\"));",
      "    if (bytes(hexStr).length == 0) return bytes(\"\");",
      "    return vm.parseBytes(string.concat(\"0x\", hexStr));",
      "}",
      "",
      "function bobHasConsumedArtifact() internal view returns (bool) {",
      "    return bobConsumedArtifact().length > 0;",
      "}",
    ].join("\n"), 4).split("\n"),
    "",
    indentLines(functionBody, 4),
    "}",
    "",
  ];
  return lines.join("\n");
}

function indentLines(text, spaces) {
  const padding = " ".repeat(spaces);
  return String(text)
    .split(/\r?\n/)
    .map((line) => (line.length === 0 ? line : `${padding}${line}`))
    .join("\n");
}

function isUnderPath(parent, child) {
  const parentPath = path.resolve(parent);
  const childPath = path.resolve(child);
  return childPath === parentPath || childPath.startsWith(parentPath + path.sep);
}

function isUnderHome(absPath) {
  let home = os.homedir();
  try { home = fs.realpathSync(home); } catch {}
  return isUnderPath(home, absPath);
}

function assertHarnessPath(harnessPath) {
  const resolved = path.resolve(harnessPath);
  if (!isUnderHome(resolved)) {
    throw new Error(`Foundry harness path must live under the user home directory; received: ${resolved}`);
  }
  if (!fs.existsSync(resolved)) {
    throw new Error(`Foundry harness path does not exist: ${resolved}`);
  }
  const realResolved = fs.realpathSync(resolved);
  if (!isUnderHome(realResolved)) {
    throw new Error(`Foundry harness path must live under the user home directory after symlink resolution; resolved to: ${realResolved}`);
  }
  if (!fs.statSync(realResolved).isDirectory()) {
    throw new Error(`Foundry harness path must be a directory: ${realResolved}`);
  }
  return realResolved;
}

function ensureHarnessTestDir(harnessPath) {
  const harnessDir = assertHarnessPath(harnessPath);
  const testDir = path.join(harnessDir, "test");
  if (!fs.existsSync(testDir)) {
    throw new Error(`Foundry harness has no test/ directory: ${testDir}`);
  }
  const realTestDir = fs.realpathSync(testDir);
  if (!isUnderPath(harnessDir, realTestDir) || !fs.statSync(realTestDir).isDirectory()) {
    throw new Error(`Foundry harness test/ directory must stay inside the harness: ${testDir}`);
  }
  const bobDir = path.join(realTestDir, "bob-invariants");
  if (!fs.existsSync(bobDir)) fs.mkdirSync(bobDir, { recursive: true });
  const realBobDir = fs.realpathSync(bobDir);
  if (!isUnderPath(realTestDir, realBobDir) || !fs.statSync(realBobDir).isDirectory()) {
    throw new Error(`Foundry invariant output directory must stay inside the harness test/ directory: ${bobDir}`);
  }
  return realBobDir;
}

function writeFileThroughExclusiveSiblingTemp(realDir, fileName, content, label) {
  if (path.basename(fileName) !== fileName) {
    throw new Error(`${label} file name must be a basename: ${fileName}`);
  }
  if (!fs.statSync(realDir).isDirectory()) {
    throw new Error(`${label} directory must be a directory: ${realDir}`);
  }
  const targetPath = path.join(realDir, fileName);
  if (!isUnderPath(realDir, targetPath)) {
    throw new Error(`${label} path must stay inside the target directory: ${targetPath}`);
  }

  const tempName = `.${fileName}.${process.pid}.${Date.now()}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  const tempPath = path.join(realDir, tempName);
  const flags = fs.constants.O_WRONLY
    | fs.constants.O_CREAT
    | fs.constants.O_EXCL
    | (fs.constants.O_NOFOLLOW || 0);
  let fd = null;
  try {
    fd = fs.openSync(tempPath, flags, 0o600);
    fs.writeFileSync(fd, content, "utf8");
    try { fs.fsyncSync(fd); } catch {}
    fs.closeSync(fd);
    fd = null;

    // This catches symlink swaps of the already resolved directory path before
    // the final rename. Replacing the directory with a new directory at the
    // same pathname is outside ND-007's portable Node attacker model.
    const currentDir = fs.realpathSync(realDir);
    if (currentDir !== realDir) {
      throw new Error(`${label} directory changed during write: ${realDir}`);
    }

    fs.renameSync(tempPath, targetPath);

    const cleanupFinalEntry = () => {
      try { fs.unlinkSync(targetPath); } catch {}
    };
    const failFinalValidation = (message) => {
      cleanupFinalEntry();
      throw new Error(message);
    };
    let finalLstat;
    try {
      finalLstat = fs.lstatSync(targetPath);
    } catch {
      failFinalValidation(`${label} file must be a regular file inside the target directory: ${targetPath}`);
    }
    if (finalLstat.nlink > 1) {
      failFinalValidation(`${label} file must not be hard-linked: ${targetPath}`);
    }
    let finalRealPath;
    let finalStat;
    try {
      finalRealPath = fs.realpathSync(targetPath);
      finalStat = fs.statSync(finalRealPath);
    } catch {
      failFinalValidation(`${label} file must be a regular file inside the target directory: ${targetPath}`);
    }
    if (finalLstat.isSymbolicLink() || !finalStat.isFile() || !isUnderPath(realDir, finalRealPath)) {
      failFinalValidation(`${label} file must be a regular file inside the target directory: ${targetPath}`);
    }
    return targetPath;
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
    try { fs.unlinkSync(tempPath); } catch {}
  }
}

function writeInvariantSourceFile(outputDir, fileName, source) {
  const realOutputDir = fs.realpathSync(outputDir);
  return writeFileThroughExclusiveSiblingTemp(realOutputDir, fileName, source, "Foundry invariant test");
}

// MINT ≠ CONFIRM. classifyFoundryOutcome maps ONE run to its honest per-run
// PRIMITIVE (test_passed/test_failed/fork_blocked/...). A primitive is an
// OBSERVATION, never a confirmation: a bare test_passed from a single run does
// NOT mint a verified finding. CONFIRM is the adjudicated FLIP over a
// {positive_run_hash, control_run_hash} pair, computed by
// adjudicateInvariantDifferential / verifyInvariantDifferential below and
// written only to the MCP-owned invariant-verified.jsonl ledger.
function classifyFoundryOutcome(rawResult) {
  if (!isPlainObject(rawResult)) return "unknown";
  const reason = typeof rawResult.reason === "string"
    ? rawResult.reason
    : (typeof rawResult.kind === "string" ? rawResult.kind : null);
  if (reason === "foundry_fork" || reason === "rpc_unreachable" || (reason && reason.startsWith("no_fork_endpoints"))) {
    return "fork_blocked";
  }
  if (reason === "forge_not_in_path") return "forge_missing";
  if (Array.isArray(rawResult.tests)) {
    const failures = rawResult.tests.filter((t) => {
      if (!t) return false;
      if (t.success === false) return true;
      return typeof t.status === "string" && /^fail/i.test(t.status);
    });
    if (failures.length > 0) return "test_failed";
    if (rawResult.summary && Number(rawResult.summary.failed) > 0) return "test_failed";
    if (rawResult.ok === true || rawResult.tests.some((t) => t && (t.success === true || t.status === "Pass"))) {
      return "test_passed";
    }
  }
  if (rawResult.summary && Number(rawResult.summary.failed) > 0) return "test_failed";
  if (typeof rawResult.ok === "boolean") return rawResult.ok ? "test_passed" : "test_failed";
  if (typeof rawResult.success === "boolean") {
    return rawResult.success ? "test_passed" : "test_failed";
  }
  return "unknown";
}

// EXECUTED-TEST IDENTITY BINDING (HIGH-1). generated_source_hash pins what was WRITTEN;
// it cannot prove WHICH test forge actually RAN. The shadow-test poison: a dishonest agent
// adds a harness .t.sol whose contract name CONTAINS the generated name; an unanchored
// --match-contract selects the EVIL contract too, and the signed row carries our
// generated_source_hash for OUR template while foundry_result is produced by attacker
// Solidity. The --match-path pin + anchored filters (foundry-runner) make forge select
// exactly the generated file; THIS function binds the EXECUTED rows to the generated
// identity as a second, result-side line: EVERY executed test must map to
// <writtenPath>:<contract_name>::<function_name>, and the set must be EXACTLY that one test.
//
// Returns { bound, reason }. bound:true means every executed row binds AND exactly one ran.
// bound:false means refuse (mismatch / empty / extra tests). When the result lacks real
// identity fields (the simplified harness shape `{ tests: [{ success: true }] }`), this is
// NOT a real forge envelope; bindForge returns { applicable:false } and the caller skips the
// strict bind (the production adapter always yields the rich shape, so the real path always
// binds). The strict bind is REQUIRED whenever identity fields exist (the production path).
function bindExecutedTestIdentity({ foundryResult, writtenPath, harnessPath, contractName, functionName }) {
  if (!isPlainObject(foundryResult) || !Array.isArray(foundryResult.tests)) {
    return { applicable: false };
  }
  const tests = foundryResult.tests;
  // A REAL forge envelope's rows carry string `suite` (path:Contract) AND `test` (fn-sig)
  // fields (summarizeForgeJson). The simplified test-harness shape carries neither — detect
  // it and skip the strict bind so existing fixtures stay green.
  const hasIdentityFields = tests.length > 0 && tests.every(
    (t) => t && typeof t.suite === "string" && typeof t.test === "string",
  );
  if (!hasIdentityFields) {
    return { applicable: false };
  }
  // Relativize the generated file against the resolved harness root, mirroring forge's
  // project-relative suite paths. Compare on the trailing path segment so an absolute or a
  // project-relative suite path both reconcile.
  let relWritten = null;
  try {
    const realHarness = fs.realpathSync(harnessPath);
    relWritten = path.relative(realHarness, writtenPath);
  } catch {
    relWritten = null;
  }
  const expectedSuffix = `test/bob-invariants/${contractName}.t.sol:${contractName}`;
  let bound = 0;
  for (const t of tests) {
    // suite = "<relative-or-absolute-path>:<ContractName>". Split on the LAST ':' (a POSIX
    // path segment cannot contain ':' on the platforms in scope, and a Solidity contract
    // name cannot either), so the tail is the contract and the head is the path.
    const lastColon = t.suite.lastIndexOf(":");
    if (lastColon < 0) {
      return { bound: false, reason: `executed-test identity: suite '${t.suite}' has no path:Contract shape (cannot bind to the generated test)` };
    }
    const suitePath = t.suite.slice(0, lastColon);
    const suiteContract = t.suite.slice(lastColon + 1);
    if (suiteContract !== contractName) {
      return { bound: false, reason: `executed-test identity: forge ran contract '${suiteContract}', not the generated '${contractName}' (a shadow contract matched) — refusing the row` };
    }
    // The suite path must be (or resolve to) the generated file. Accept an exact suffix
    // match against the canonical project-relative path, OR a realpath reconciliation to
    // writtenPath (forge emits project-relative; the runner holds the absolute writtenPath).
    const suitePathMatches = t.suite.endsWith(`/${expectedSuffix}`)
      || t.suite === expectedSuffix
      || (relWritten != null && (suitePath === relWritten || suitePath.endsWith(`/${relWritten}`)))
      || suitePath === writtenPath;
    if (!suitePathMatches) {
      return { bound: false, reason: `executed-test identity: forge ran a test at '${suitePath}', not the generated file '${expectedSuffix}' — refusing the row` };
    }
    // test = "<fn-sig>()". Strip the argument list and compare to the generated function.
    const fn = t.test.replace(/\(.*$/, "");
    if (fn !== functionName) {
      return { bound: false, reason: `executed-test identity: forge ran function '${fn}', not the generated '${functionName}' — refusing the row` };
    }
    bound += 1;
  }
  // EXACTLY the generated test must have run — not zero (a silently-empty match) and not
  // more than one (a shadow function/contract that also matched).
  if (bound !== 1) {
    return { bound: false, reason: `executed-test identity: expected EXACTLY the generated test to run, but ${bound} bound test rows executed — refusing the row` };
  }
  return { bound: true };
}

function invariantFoundryResultHash(foundryResult) {
  if (foundryResult == null) return hashCanonicalJson(null);
  // container_isolated is a containerization MARKER (was this forge run isolated in
  // a filesystem namespace, or a degrade-host spawn as the signer?), NOT a part of
  // the Foundry EXECUTION result. It must be EXCLUDED from foundry_result_hash so
  // run_hash stays byte-stable whether the run was containerized or not — a control
  // run on a different box, or a re-derivation, must produce the identical hash, and
  // every pre-existing invariant-runs fixture (which carries no container_isolated)
  // must hash identically before and after this change. The marker's integrity is
  // instead carried by the row_mac (it covers the whole record minus row_mac) and is
  // consulted by the verdict gate, never by the content hash.
  // target_binding/target_binding_error are EXCLUDED for the same reason: they are a
  // cross-stack target attestation (the executed target's address + runtime-bytecode sha256,
  // parsed from the pinned template's emitted log), carried OUTSIDE run_hash so run_hash stays
  // byte-stable and every pre-existing fixture hashes identically. Their integrity rides in the
  // row_mac via the target_* record siblings, and the cross-stack verifier consults those.
  if (typeof foundryResult === "object" && !Array.isArray(foundryResult)
    && (Object.prototype.hasOwnProperty.call(foundryResult, "container_isolated")
      || Object.prototype.hasOwnProperty.call(foundryResult, "target_binding")
      || Object.prototype.hasOwnProperty.call(foundryResult, "target_binding_error"))) {
    const { container_isolated, target_binding, target_binding_error, ...withoutMarker } = foundryResult;
    return hashCanonicalJson(withoutMarker);
  }
  return hashCanonicalJson(foundryResult);
}

function computeInvariantRunHash({
  finding_id,
  finding_hash,
  template_id,
  slot_values,
  contract_name,
  function_name,
  execution_context_hash,
  outcome,
  foundry_result,
  dry_run,
  tree_ref,
  checkout_kind,
  generated_source_hash,
  consumed_artifact_hash,
}) {
  return hashCanonicalJson({
    finding_id: parseFindingId(finding_id, "finding_id"),
    finding_hash: finding_hash || null,
    template_id,
    slot_values: slot_values || null,
    contract_name,
    function_name,
    execution_context_hash,
    outcome: outcome || null,
    foundry_result_hash: invariantFoundryResultHash(foundry_result),
    dry_run: dry_run === true,
    // tree_ref/checkout_kind identify WHICH tree the SAME generated test ran
    // against. They are bound into run_hash (so a control row cannot be re-pointed
    // at a different tree without changing its hash) but DELIBERATELY excluded
    // from execution_context_hash — the verifier requires the positive and control
    // to share execution_context_hash (same test) and differ only here (the tree).
    tree_ref: tree_ref || null,
    checkout_kind: checkout_kind || null,
    // consumed_artifact_hash names WHICH bytes (the real cause / a random decoy / none)
    // this run injected as BOB_CONSUMED_ARTIFACT. It is bound into run_hash (so the cross-
    // stack control and decoy arms — both HELD with identical foundry_result — are DISTINCT
    // persistable rows that the dedup-by-run_hash ledger keeps separate) but, like tree_ref,
    // EXCLUDED from execution_context_hash so the arms stay the SAME test. A single-surface
    // run leaves it null (the runner only sets it for a cross-stack cause), so single-surface
    // run_hashes are unchanged.
    consumed_artifact_hash: consumed_artifact_hash || null,
    // generated_source_hash PINS the exact emitted test bytes (buildTestSource's
    // full output, including the renamed function body) into the content hash, so
    // the test SOURCE is signed via the row_mac that covers run_hash. An agent who
    // shadows/overrides the test body in the harness directory, or who injects
    // through a slot, changes the emitted source -> changes this hash -> changes
    // run_hash -> the row no longer matches the membership the agent claimed, and
    // the read-time re-derivation refuses on mismatch. Nullable so a row predating
    // the field (which carries no generated_source_hash) hashes as before; a NEW
    // row always carries it.
    generated_source_hash: generated_source_hash || null,
  });
}

async function runInvariantForFinding({
  target_domain,
  finding,
  template_id,
  slot_values,
  harness_path,
  foundry_run,
  match_contract,
  match_test,
  chain_id,
  fork_block,
  fork_urls,
  extra_args,
  timeout_ms,
  run_id,
  dry_run,
  tree_ref,
  checkout_kind,
  cause_run_id,
}) {
  const domain = assertSafeDomain(target_domain);
  if (!isPlainObject(finding)) {
    throw new Error("finding must be an object");
  }
  if (typeof harness_path !== "string" || harness_path.length === 0) {
    throw new Error("harness_path must be a non-empty string");
  }
  if (typeof foundry_run !== "function" && dry_run !== true) {
    throw new Error("foundry_run must be a function (or pass dry_run: true)");
  }
  const findingId = normalizeRequiredFindingId(finding);
  const suggestion = suggestInvariantsForFinding(finding, { slot_values });
  if (suggestion.suggestions.length === 0) {
    return {
      target_domain: domain,
      vulnerability_class: suggestion.vulnerability_class,
      missing_class: suggestion.missing_class === true,
      template_id: null,
      outcome: "no_template",
    };
  }
  const chosen = template_id
    ? suggestion.suggestions.find((s) => s.template_id === template_id)
    : suggestion.suggestions[0];
  if (!chosen) {
    throw new Error(`No matching template for class ${suggestion.vulnerability_class} (template_id=${template_id})`);
  }
  const invariantRunsPath = dry_run === true
    ? null
    : resolveInvariantRunsFilePath(invariantRunsJsonlPath(domain), { createDir: true });
  const { contract_name, function_name } = deriveTestNamesFromTemplate(chosen, finding, slot_values || null);
  if (match_contract && match_contract !== contract_name) {
    throw new Error(`match_contract overrides are unsupported for generated invariants; expected ${contract_name}`);
  }
  if (match_test && match_test !== function_name) {
    throw new Error(`match_test overrides are unsupported for generated invariants; expected ${function_name}`);
  }
  const renamedBody = renameTestFunction(chosen.foundry_test, function_name);
  const source = buildTestSource({ contractName: contract_name, functionBody: renamedBody });
  // PIN the exact emitted test bytes into the run identity. generated_source_hash is
  // bound into computeInvariantRunHash (and so into the row_mac via run_hash), so the
  // signed row commits to the precise source the runner emitted. An agent who later
  // shadows/overrides the test body in the harness cannot match this hash.
  const generatedSourceHash = crypto.createHash("sha256").update(source, "utf8").digest("hex");
  const executionContext = {
    chain_id: chain_id || null,
    fork_block: fork_block == null ? null : fork_block,
    fork_urls: Array.isArray(fork_urls) ? fork_urls : null,
    extra_args: Array.isArray(extra_args) ? extra_args : null,
    match_contract: match_contract || null,
    match_test: match_test || null,
  };
  const executionContextHash = hashCanonicalJson(executionContext);
  // tree_ref/checkout_kind name WHICH tree this run executed against (the real
  // target by default; a control tree for the refuting arm). They are bound into
  // run_hash but NOT execution_context_hash, so a positive/control pair shares the
  // same test identity and differs only in the tree.
  const treeRef = typeof tree_ref === "string" && tree_ref.trim() ? tree_ref.trim() : null;
  const checkoutKind = typeof checkout_kind === "string" && checkout_kind.trim() ? checkout_kind.trim() : null;
  const causeRunId = typeof cause_run_id === "string" && cause_run_id.trim() ? cause_run_id.trim() : null;
  // CROSS-STACK CONSUME: when a violated arm names a cause_run_id, FETCH that offensive
  // run's captured consumable bytes and INJECT them into the foundry subprocess as
  // BOB_CONSUMED_ARTIFACT. The control arm names no cause -> empty env (the controlled
  // variable). The fetch is non-forgeable: the named offensive row's row_mac is STRICTLY
  // verified (assertRowMac — an unsigned/forged row is refused, NOT waved through as
  // legacy) and the on-disk bytes are re-hashed and asserted EQUAL to that row's
  // MAC-covered consumed_artifact_hash (the dedicated .consumed leaf). A missing/
  // mismatched/forged capture for a run_id the agent did not execute fails closed: the
  // arm runs cause-free (no injection), which the O-B verifier refuses.
  // consumedArtifactHash records sha256 of the bytes ACTUALLY injected — the binding the
  // invariant row carries as a MAC-covered sibling.
  //
  // CANONICAL .consumed LEAF (fail-closed): the .consumed leaf is the SOLE canonical
  // consumable. There is NO stdout_hash fallback — a cause that captured no dedicated
  // consumable (consumed_artifact_hash null) does NOT have its raw HTTP stdout body
  // injected as a free consumable; the cross-stack consume path is simply UNAVAILABLE and
  // the arm runs cause-free. This keeps the runner and the O-B adjudicator (which binds
  // only the .consumed leaf via causeLeg.consumedArtifactHash) in agreement about what a
  // "consumable" is, and forecloses the stdout-as-free-consumable path.
  let consumedArtifactBytes = null;
  let consumedArtifactHash = null;
  if (dry_run !== true && causeRunId != null) {
    // The consume-bind path (feeding a web-captured artifact into the gated call as
    // the on-chain authorization argument) is reachable ONLY for the audited cross-
    // stack consuming template, whose body is fixed corpus text. An arbitrary corpus
    // template (whose body is agent-influenced via slots) may never bind a cause —
    // forbid it so an agent cannot point a slot-controlled template at a captured
    // cause to manufacture a flip.
    if (chosen.template_id !== CROSS_STACK_CONSUME_TEMPLATE_ID) {
      throw new Error(
        `cross-stack consume (cause_run_id binding) is only permitted for template ${CROSS_STACK_CONSUME_TEMPLATE_ID}; got ${chosen.template_id}`,
      );
    }
    const causeRows = readOffensiveRunRecords(domain);
    const causeRow = causeRows.find((r) => r && r.run_id === causeRunId) || null;
    if (causeRow != null) {
      // STRICT MAC: a cross-stack consume must bind to a REAL signature, never an
      // unsigned legacy row (which a same-uid actor could have appended). A present-but-
      // invalid MAC throws; we treat any throw as "no verified cause" and run cause-free.
      let rowVerified = false;
      try {
        assertRowMac(OFFENSIVE_ROW_MAC_CONTEXT, causeRow, resolveRowVerifierSafely(domain));
        rowVerified = true;
      } catch {
        rowVerified = false;
      }
      if (rowVerified) {
        // The dedicated .consumed leaf is the SOLE canonical consumable (fail-closed): a
        // cause with consumed_artifact_hash null captured NO consumable, so the consume
        // path is unavailable and the arm runs cause-free. A raw HTTP stdout body is NOT a
        // free consumable — there is no stdout_hash fallback.
        const boundConsumedHash = typeof causeRow.consumed_artifact_hash === "string"
          && /^[0-9a-f]{64}$/.test(causeRow.consumed_artifact_hash)
          ? causeRow.consumed_artifact_hash
          : null;
        if (boundConsumedHash != null) {
          const fetched = readOffensiveCaptureBytesSecure(domain, causeRunId, "consumed");
          // Bind the fetched bytes to the MAC-covered hash on the row: only inject when the
          // on-disk bytes re-hash to EXACTLY what the signed row pins. This is what makes a
          // forged stored-bytes for a non-executed run_id rejected — the bytes would not
          // match the (signed, non-forgeable) hash, so they are never injected.
          if (fetched != null && fetched.sha256 === boundConsumedHash) {
            consumedArtifactBytes = fetched.bytes;
            consumedArtifactHash = fetched.sha256;
          }
        }
      }
    }
  }
  let writtenPath = null;
  let foundryRawResult = null;
  let outcome = "dry_run";
  let runHash = null;
  let invariantRunsRetention = null;
  // Cross-stack target binding (siblings, outside run_hash, inside row_mac). Null on
  // single-surface / dry runs; set on a cross-stack run that emitted the pinned binding.
  let targetAddress = null;
  let targetCodeSha256 = null;
  let targetOnchainCodeSha256 = null;
  if (dry_run !== true) {
    const bobDir = ensureHarnessTestDir(harness_path);
    writtenPath = writeInvariantSourceFile(bobDir, `${contract_name}.t.sol`, source);
    foundryRawResult = await foundry_run({
      target_domain: domain,
      harness_path,
      match_test: match_test || function_name,
      match_contract: match_contract || contract_name,
      // HIGH-1: pin forge to the EXACT generated file + anchor the match filters to the full
      // identifier. A shadow .t.sol whose contract/test name CONTAINS the generated name is
      // never selected, so a dishonest agent cannot have foundry run attacker-authored
      // Solidity under the signed row's generated_source_hash. match_path is the absolute
      // written path; anchor_match wraps match_test/match_contract in ^...$.
      match_path: writtenPath,
      anchor_match: true,
      chain_id,
      fork_block,
      fork_urls,
      extra_args,
      timeout_ms,
      // The cross-stack consumable bytes injected into the foundry subprocess as
      // BOB_CONSUMED_ARTIFACT. null/absent on the control arm -> empty env (the corpus
      // template's vm.envOr default), so the artifact PRESENCE is the controlled variable.
      consumed_artifact: consumedArtifactBytes,
    });
    if (typeof foundryRawResult === "string") {
      try {
        foundryRawResult = JSON.parse(foundryRawResult);
      } catch (_err) {
        // leave as string for downstream inspection.
      }
    }
    outcome = classifyFoundryOutcome(foundryRawResult);
    // EXECUTED-TEST IDENTITY BINDING (HIGH-1). Bind the EXECUTED foundry rows to the
    // generated contract::function@path. The --match-path pin + anchored filters already
    // make forge select the generated file; this is the result-side line that REFUSES a row
    // whose executed identity is not the generated one (a shadow contract/test that slipped
    // through, or a silently-empty/extra-test run). On a non-binding REAL envelope the run is
    // marked outcome:"identity_unbound" (classifyFoundryViolation -> "degraded", which can
    // never satisfy INVARIANT_POSITIVE_DISPOSITION="violated", so it can never back a
    // verified_pass) and the cross-stack consumed-artifact injection is nulled (an unbound
    // run never carries a usable cause binding). The simplified test-harness shape (no
    // identity fields) is skipped — the production adapter always yields the rich shape.
    const identityBind = bindExecutedTestIdentity({
      foundryResult: foundryRawResult,
      writtenPath,
      harnessPath: harness_path,
      contractName: contract_name,
      functionName: function_name,
    });
    if (identityBind.applicable !== false && identityBind.bound !== true) {
      outcome = "identity_unbound";
      consumedArtifactHash = null;
      consumedArtifactBytes = null;
    }
    // CROSS-STACK TARGET BINDING. The pinned template emits exactly one
    // "BOB_TARGET_BIND:<address>:<sha256(target.code)>" line (foundry-runner parses it into
    // foundry_result.target_binding; a setUp-injected second line sets target_binding_error
    // → refused). Cross-check the executed runtime-bytecode sha256 against the REAL on-chain
    // bytecode at the SAME address+fork_block via eth_getCode on the trusted fork endpoints.
    // The agent controls the executed target but NOT the runner's eth_getCode against the
    // real chain, so a fake-deployed or vm.etch'd target yields a mismatch the cross-stack
    // verifier refuses. Single-surface runs emit no binding (these stay null). The lookup uses
    // ethGetCodeAgreed (quorum across endpoints, "0x" non-archival misses ignored), so a single
    // bad endpoint cannot mint a WRONG on-chain hash that would falsely refuse a genuine target;
    // when the lookup is unavailable (all endpoints failed/timed-out, or real-code responders
    // disagree) target_onchain_code_sha256 stays null. The verifier distinguishes that null
    // (on-chain lookup UNAVAILABLE → a re-runnable, NOT a forgery) from a present-but-mismatched
    // hash (the fake/etch case). A re-run reuses the same run_hash (the target siblings are
    // outside run_hash), so a resolved row supersedes an unavailable one in the dedup ledger.
    const tbResult = isPlainObject(foundryRawResult) ? foundryRawResult.target_binding : null;
    const tbError = isPlainObject(foundryRawResult) ? foundryRawResult.target_binding_error : null;
    if (!tbError && tbResult && typeof tbResult.address === "string" && typeof tbResult.code_sha256 === "string") {
      targetAddress = tbResult.address.toLowerCase();
      targetCodeSha256 = tbResult.code_sha256.toLowerCase();
      if (chain_id != null && fork_block != null && Array.isArray(fork_urls) && fork_urls.length > 0) {
        try {
          const { ethGetCodeAgreed } = require("./evm-client.js");
          const resp = await ethGetCodeAgreed({ chainId: chain_id, address: targetAddress, block: fork_block, endpoints: fork_urls });
          if (resp && resp.status === "resolved" && typeof resp.code === "string" && resp.code.length > 0) {
            targetOnchainCodeSha256 = `0x${crypto.createHash("sha256").update(Buffer.from(resp.code, "hex")).digest("hex")}`;
          }
        } catch {
          targetOnchainCodeSha256 = null;
        }
      }
    }
    runHash = computeInvariantRunHash({
      finding_id: findingId,
      finding_hash: finding.finding_hash,
      template_id: chosen.template_id,
      slot_values: slot_values || null,
      contract_name,
      function_name,
      execution_context_hash: executionContextHash,
      outcome,
      foundry_result: foundryRawResult,
      dry_run: false,
      tree_ref: treeRef,
      checkout_kind: checkoutKind,
      generated_source_hash: generatedSourceHash,
      consumed_artifact_hash: consumedArtifactHash,
    });
  } else {
    runHash = computeInvariantRunHash({
      finding_id: findingId,
      finding_hash: finding.finding_hash,
      template_id: chosen.template_id,
      slot_values: slot_values || null,
      contract_name,
      function_name,
      execution_context_hash: executionContextHash,
      outcome,
      foundry_result: null,
      dry_run: true,
      tree_ref: treeRef,
      checkout_kind: checkoutKind,
      generated_source_hash: generatedSourceHash,
      consumed_artifact_hash: consumedArtifactHash,
    });
  }
  const record = {
    run_hash: runHash,
    target_domain: domain,
    finding_id: findingId,
    finding_hash: finding.finding_hash || null,
    finding_title: finding.title || null,
    vulnerability_class: suggestion.vulnerability_class,
    template_id: chosen.template_id,
    slot_values: slot_values || null,
    unfilled_slots: chosen.unfilled_slots,
    contract_name,
    function_name,
    execution_context_hash: executionContextHash,
    tree_ref: treeRef,
    checkout_kind: checkoutKind,
    // The pinned source hash — part of the run identity (computeInvariantRunHash
    // binds it, the row_mac covers run_hash). readInvariantRunRowForVerification
    // re-derives computeInvariantRunHash from this stored value, so a row whose
    // generated_source_hash was stripped or altered fails the content-hash re-check.
    generated_source_hash: generatedSourceHash,
    chain_id: chain_id || null,
    fork_block: fork_block == null ? null : fork_block,
    fork_url_count: Array.isArray(fork_urls) ? fork_urls.length : 0,
    extra_args_count: Array.isArray(extra_args) ? extra_args.length : 0,
    match_contract: match_contract || null,
    match_test: match_test || null,
    test_path: writtenPath,
    outcome,
    foundry_result_hash: invariantFoundryResultHash(foundryRawResult),
    foundry_result: foundryRawResult,
    dry_run: dry_run === true,
    run_id: typeof run_id === "string" && run_id.length > 0 ? run_id : null,
    recorded_at: new Date().toISOString(),
    // Did THIS invariant run execute inside a filesystem-namespace container, or
    // degrade to a host spawn AS THE SIGNER? Lifted from the foundry result's
    // top-level marker (foundry-runner finalizeRun). A host-as-signer (degrade) run
    // resolves false, because agent-authored Solidity in the foundry test/build runs
    // as the signer and CAN read the 0400 key to forge a MAC-valid row. This is a
    // SIBLING top-level field (like recorded_at/run_id) OUTSIDE computeInvariantRunHash
    // (so run_hash stays byte-stable) but INSIDE the row_mac (signRowViaIsolatedSignerOrLocal
    // covers the whole record minus row_mac), so an agent cannot strip/flip it without
    // invalidating the MAC. The verdict gate refuses to trust an SC reportable whose
    // backing positive row is not container_isolated:true. A legacy row predating this
    // field carries null/absent and is fail-closed un-isolated at the gate under enforce.
    container_isolated: foundryRawResult && typeof foundryRawResult === "object"
      && !Array.isArray(foundryRawResult) && foundryRawResult.container_isolated === true
      ? true
      : false,
    // The CROSS-STACK CAUSAL LINK. A violated (positive) arm whose effect was
    // produced by a stack-A offensive run names that run's run_id here; a held
    // (control) arm runs on the cause-free tree and legitimately omits it (null).
    // Like container_isolated this is a top-level SIBLING OUTSIDE computeInvariantRunHash
    // (so the positive and control stay the SAME test — execution_context_hash and
    // run_hash binding are undisturbed) but INSIDE the row_mac (the signer covers the
    // whole record minus row_mac), so an agent cannot re-point a violated arm at a
    // different cause without invalidating its MAC. The cross-stack adjudicator refuses
    // any flip whose violated arm does not name the bound cause run.
    cause_run_id: causeRunId,
    // The CONSUMED-ARTIFACT BINDING. sha256 of the bytes this invariant run ACTUALLY
    // consumed (injected as BOB_CONSUMED_ARTIFACT). On a violated arm with a verified
    // cause this is the bound bytes' hash; on the control arm (no cause, empty env) it is
    // null. UNLIKE cause_run_id/container_isolated/target_* (true top-level siblings OUTSIDE
    // the content hash), consumed_artifact_hash IS bound INTO run_hash alongside tree_ref —
    // so the cross-stack control and decoy arms, both HELD with an identical foundry_result,
    // are DISTINCT persistable rows the dedup-by-run_hash ledger keeps separate. It is
    // EXCLUDED only from execution_context_hash, so the positive/control/decoy arms stay the
    // SAME test (the artifact PRESENCE is the controlled variable, like tree_ref). run_hash is
    // in turn covered by the row_mac (the signer covers the whole record minus row_mac), so an
    // agent cannot forge which bytes a violated arm consumed. The O-B verifier binds this to
    // sha256 of the named cause's stored bytes.
    consumed_artifact_hash: consumedArtifactHash,
    // CROSS-STACK TARGET BINDING siblings — top-level, OUTSIDE run_hash (so run_hash stays
    // byte-stable and pre-binding rows hash identically) but INSIDE the row_mac. The
    // cross-stack verifier requires all three and refuses unless target_code_sha256 (the
    // executed runtime-bytecode hash the pinned template emitted) equals
    // target_onchain_code_sha256 (eth_getCode at the same address+fork_block). The agent
    // controls target_code_sha256 via its target but NOT target_onchain_code_sha256.
    target_address: targetAddress,
    target_code_sha256: targetCodeSha256,
    target_onchain_code_sha256: targetOnchainCodeSha256,
  };
  if (dry_run !== true) {
    await withInvariantSessionWriteLock(domain, () => {
      // KEY the executed row INSIDE the producer's existing write lock (C4) through
      // the single signing seam. run_hash is already computed and EXCLUDES row_mac
      // (computeInvariantRunHash binds only the 12 listed fields), so signing here
      // leaves run_hash byte-stable and the row recomputes identically at read;
      // writeJsonlRuns serializes row_mac verbatim and dedup-by-run_hash preserves it.
      // NOT a re-hash — a keyed signature over the whole record minus row_mac under the
      // invariant-run context. The seam isolates the secret when the server runs under a
      // dedicated signer uid (agent uid then gets EACCES); on the same-uid box it
      // degrades to a local sign and the verdict-level attestation gate enforces trust.
      signRowViaIsolatedSignerOrLocal(domain, INVARIANT_RUN_MAC_CONTEXT, record);
      const existing = readJsonlRuns(invariantRunsPath, { symlinkAsEmpty: true });
      const byHash = new Map();
      for (const run of existing) {
        if (run && typeof run.run_hash === "string") byHash.set(run.run_hash, run);
      }
      byHash.set(runHash, record);
      invariantRunsRetention = writeJsonlRuns(invariantRunsPath, Array.from(byHash.values()));
    });
  }
  return {
    target_domain: domain,
    vulnerability_class: suggestion.vulnerability_class,
    template_id: chosen.template_id,
    contract_name,
    function_name,
    test_path: writtenPath,
    outcome,
    finding_id: findingId,
    unfilled_slots: chosen.unfilled_slots,
    run_hash: runHash,
    execution_context_hash: executionContextHash,
    invariant_runs_retention: invariantRunsRetention,
    dry_run: dry_run === true,
    foundry_result: foundryRawResult,
  };
}

function readInvariantRuns({ target_domain, outcome_filter, template_id_filter, limit }) {
  const domain = assertSafeDomain(target_domain);
  const filePath = resolveInvariantRunsFilePath(invariantRunsJsonlPath(domain), { createDir: false });
  const records = readJsonlRuns(filePath);
  if (records.length === 0) {
    return { runs: [], total_in_corpus: 0, total_matched: 0 };
  }
  const matched = [];
  for (const run of records) {
    if (!isPlainObject(run)) continue;
    if (outcome_filter && run.outcome !== outcome_filter) continue;
    if (template_id_filter && run.template_id !== template_id_filter) continue;
    matched.push(run);
  }
  const cap = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 200) : 50;
  return {
    runs: matched.slice(0, cap),
    total_in_corpus: records.length,
    total_matched: matched.length,
  };
}

function readInvariantRunCorpus({ target_domain }) {
  const domain = assertSafeDomain(target_domain);
  const filePath = resolveInvariantRunsFilePath(invariantRunsJsonlPath(domain), { createDir: false });
  const records = readJsonlRuns(filePath);
  return {
    runs: records.filter((run) => isPlainObject(run)),
    total_in_corpus: records.length,
  };
}

// classifyFoundryViolation maps a per-run PRIMITIVE to the INVARIANT direction.
// The corpus templates (invariant-template-corpus.js) are authored as the
// invariant HOLDING (they vm.expectRevert / assert the SAFE behavior and PASS
// when the contract is safe). So "the invariant is VIOLATED" is OBSERVED as the
// safe-assertion test FAILING. fork_blocked/forge_missing/unknown/no_template
// carry no signal about the invariant -> "degraded".
function classifyFoundryViolation(rawResult) {
  const outcome = classifyFoundryOutcome(rawResult);
  if (outcome === "test_failed") return "violated";
  if (outcome === "test_passed") return "held";
  return "degraded";
}

// classifyHalmosViolation — the halmos analogue. A halmos run is a primitive:
// summary.failed>0 (a counterexample / [FAIL]) = "violated"; ok with total>0
// (no counterexample) = "held"; not-in-path/empty/unparseable/timed_out/
// zero-test = "degraded". `ok` is a SINGLE-RUN PRIMITIVE, NOT a verified verdict
// (it only mints "held"); a verified verdict requires the differential flip.
function classifyHalmosViolation(halmosRun) {
  if (!isPlainObject(halmosRun)) return "degraded";
  if (halmosRun.timed_out === true) return "degraded";
  if (typeof halmosRun.reason === "string"
    && (halmosRun.reason === "halmos_not_in_path"
      || halmosRun.reason === "halmos_spawn_failed"
      || halmosRun.reason === "empty_stdout"
      || halmosRun.reason === "unparseable_output")) {
    return "degraded";
  }
  if (typeof halmosRun.parse_warning === "string" && halmosRun.parse_warning) return "degraded";
  const summary = isPlainObject(halmosRun.summary) ? halmosRun.summary : null;
  if (!summary || !Number.isFinite(Number(summary.total)) || Number(summary.total) <= 0) {
    return "degraded";
  }
  if (Number(summary.failed) > 0) return "violated";
  return "held";
}

// adjudicateInvariantDifferential — a thin wrapper REUSING the exact branch order
// of repro-replay-verifier.js::adjudicateDifferential, retargeted to violation
// semantics. positiveRun is the run on the REAL target (the invariant must FAIL /
// a counterexample must exist there); controlRun is the SAME generated test on a
// control tree where the invariant SHOULD hold (it must NOT fail). Each is given
// as { violation: "violated"|"held"|"degraded" }. The flip is: violated-here AND
// holds-there. A non-flipping pair (control also violated) is a harness/template
// artifact and is REFUSED — the forgery defense.
function adjudicateInvariantDifferential({ positiveRun, controlRun }) {
  const positiveViolation = positiveRun && typeof positiveRun.violation === "string"
    ? positiveRun.violation : "degraded";
  const controlViolation = controlRun && typeof controlRun.violation === "string"
    ? controlRun.violation : "degraded";

  let result;
  let reason;
  if (positiveViolation === "degraded" || controlViolation === "degraded") {
    result = RESULT_INCONCLUSIVE;
    reason = `degraded re-execution (positive:${positiveViolation}, control:${controlViolation})`;
  } else if (positiveViolation !== "violated") {
    // The claimed violation does not reproduce on the real target.
    result = RESULT_REFUTED;
    reason = "claimed invariant violation did not reproduce on the real target";
  } else if (controlViolation === "violated") {
    // No flip: the invariant ALSO fails on the control tree where it should hold.
    // A tautology-false / mis-authored assertion fails on the known-safe baseline
    // too; the failure is a harness/template artifact, not an attributable bug.
    result = RESULT_REFUTED;
    reason = "no differential flip: the invariant also fails on the control tree where it should hold — harness/template artifact, not an attributable bug";
  } else {
    // Real, attributable flip: the invariant FAILS on the target and HOLDS on the
    // control tree.
    result = RESULT_VERIFIED_PASS;
    reason = "differential invariant violation: fails on the real target, holds on the control tree";
  }
  return { result, reason, positive_violation: positiveViolation, control_violation: controlViolation };
}

// Resolve the per-call shared verifier for the invariant-run MAC check WITHOUT throwing.
// Cycle B rows are always ed25519 (v2), so the ed25519 PUBLIC key is the only material
// these contexts need; resolveRowVerifierSafely yields a public-key-only verifier
// (hmacKey:null) for a non-offensive ed25519-only session and null for a pre-keypair
// session. A legacy (unsigned) row carries no row_mac so assertRowMacOrLegacy returns
// {legacy} and never consults the verifier, while a SIGNED row with a null verifier fails
// closed. Resolve ONCE per call (it reads keys from disk) and thread it into the per-row
// validator, never per row (CONSTRAINT 1: no per-row disk re-read).
function resolveInvariantRowVerifierSafely(domain) {
  return resolveRowVerifierSafely(domain);
}

// Re-validate a single invariant-runs.jsonl row exactly as proof-bundle.js's
// readInvariantRunRow does (the row binds the outcome to the Foundry result and
// the run identity), then return the row. A forged row is rejected here just as
// it is at the proof-bundle gate.
//
// Cycle B: AFTER the content-hash re-derivation (computeInvariantRunHash === run_hash)
// passes, ALSO assert the keyed row_mac via assertRowMacOrLegacy. A NEW row carries a
// valid bob.invariant-run.v1 signature; a row whose covered field was mutated with a
// stale MAC hard-fails (throw → reverify catch → ok:false; proof-bundle rejects the
// bundle); an OLD unsigned row is accepted-with-warning (still fully re-derived). The
// MAC is an ADDED O(1) keyed layer, never a replacement for the content-hash check.
function readInvariantRunRowForVerification(rows, runHash, fieldName, expectedFindingId, verifier = null) {
  if (typeof runHash !== "string" || !/^[0-9a-f]{64}$/i.test(runHash)) {
    throw new Error(`${fieldName} must be a 64-hex invariant run_hash`);
  }
  const normalizedRunHash = runHash.toLowerCase();
  const matching = rows.filter((entry) => isPlainObject(entry) && entry.run_hash === normalizedRunHash);
  if (matching.length === 0) {
    throw new Error(`${fieldName} does not match an invariant-runs.jsonl row`);
  }
  if (matching.length > 1) {
    const hashes = new Set(matching.map((row) => hashCanonicalJson(row)));
    if (hashes.size > 1) {
      throw new Error(`${fieldName} has ambiguous duplicate entries in invariant-runs.jsonl`);
    }
  }
  const row = matching[0];
  if (row.dry_run !== false) {
    throw new Error(`${fieldName} must reference an executed invariant run, not a dry-run plan`);
  }
  if (row.finding_id == null || parseFindingId(row.finding_id, `${fieldName}.finding_id`) !== expectedFindingId) {
    throw new Error(`${fieldName} finding_id does not match ${expectedFindingId}`);
  }
  const expectedFoundryResultHash = invariantFoundryResultHash(row.foundry_result);
  if (row.foundry_result_hash != null && row.foundry_result_hash !== expectedFoundryResultHash) {
    throw new Error(`${fieldName} foundry_result_hash does not match invariant run result payload`);
  }
  if (computeInvariantRunHash(row) !== normalizedRunHash) {
    throw new Error(`${fieldName} does not bind the invariant run outcome and Foundry result`);
  }
  if (classifyFoundryOutcome(row.foundry_result) !== row.outcome) {
    throw new Error(`${fieldName} outcome does not match invariant run Foundry result`);
  }
  // Cycle B keyed layer: a present-but-invalid row_mac (forged/tampered/cross-context)
  // throws here; an absent row_mac is accepted-with-warning (legacy in-flight row, still
  // re-derived above). Throws propagate to the caller's catch (reverify → ok:false) or
  // to the proof-bundle gate (bundle rejected), mirroring the content-hash failure path.
  assertRowMacOrLegacy(INVARIANT_RUN_MAC_CONTEXT, row, verifier);
  return row;
}

// verifyInvariantDifferential — load BOTH the positive (real-target) and control
// rows from the MCP-owned invariant-runs.jsonl, assert they are the SAME test
// (template_id, contract_name, function_name, slot_values, execution_context)
// differing ONLY in tree/checkout identity, recompute each row's hashes, then
// adjudicate the flip and mint a record to the NEW write-only, agent-Write-blocked
// invariant-verified.jsonl ledger keyed by finding_id (LEDGER-BY-ID). A bare
// single-run pass (no control_run_hash) is INCONCLUSIVE by construction: the gate
// has nothing to flip against, so NO verified_pass is ever written.
function verifyInvariantDifferential({ target_domain, finding_id, positive_run_hash, control_run_hash }) {
  const domain = assertSafeDomain(target_domain);
  const findingId = parseFindingId(finding_id, "finding_id");
  if (typeof positive_run_hash !== "string" || !positive_run_hash.trim()) {
    throw new Error("positive_run_hash is required (the run on the real target where the invariant must fail)");
  }
  const corpusPath = resolveInvariantRunsFilePath(invariantRunsJsonlPath(domain), { createDir: false });
  const rows = readJsonlRuns(corpusPath);
  // Cycle B: resolve the keyed-MAC verifier ONCE for this call (not per row).
  const verifier = resolveInvariantRowVerifierSafely(domain);
  const positiveRow = readInvariantRunRowForVerification(rows, positive_run_hash, "positive_run_hash", findingId, verifier);

  // REFUTING-ARM (universal): a confirm needs a refuting control. No control arm
  // => INCONCLUSIVE by construction; the ledger receives no verified_pass.
  if (control_run_hash == null || (typeof control_run_hash === "string" && !control_run_hash.trim())) {
    return mintInvariantVerifiedRecord({
      targetDomain: domain,
      findingId,
      positiveRunHash: positiveRow.run_hash,
      controlRunHash: null,
      result: RESULT_INCONCLUSIVE,
      reason: "no refuting control arm supplied; a single-run pass cannot confirm a violation",
      positiveViolation: classifyFoundryViolation(positiveRow.foundry_result),
      controlViolation: null,
      templateId: positiveRow.template_id || null,
    });
  }

  const controlRow = readInvariantRunRowForVerification(rows, control_run_hash, "control_run_hash", findingId, verifier);

  // The control MUST be the SAME test on a DIFFERENT tree. It binds finding_id,
  // template_id, contract_name, function_name, slot_values and the
  // execution_context_hash; it differs ONLY in the tree/checkout identity. A
  // control that differs on any of these provably implicates the harness, so it
  // is rejected (it is not the same discriminator).
  for (const field of ["template_id", "contract_name", "function_name", "execution_context_hash"]) {
    if ((positiveRow[field] || null) !== (controlRow[field] || null)) {
      throw new Error(`control_run_hash ${field} must match the positive run (control must be the SAME test on a different tree)`);
    }
  }
  if (hashCanonicalJson(positiveRow.slot_values || null) !== hashCanonicalJson(controlRow.slot_values || null)) {
    throw new Error("control_run_hash slot_values must match the positive run (control must be the SAME test on a different tree)");
  }
  const positiveTree = positiveRow.tree_ref || null;
  const controlTree = controlRow.tree_ref || null;
  if (positiveRow.run_hash === controlRow.run_hash) {
    throw new Error("control_run_hash must differ from positive_run_hash (a control hash-identical to the positive cannot discriminate)");
  }
  if (positiveTree === controlTree && positiveRow.checkout_kind === controlRow.checkout_kind) {
    throw new Error("control_run_hash must reference a DIFFERENT tree/checkout than the positive run (set tree_ref/checkout_kind so the control is distinguishable)");
  }

  const { result, reason, positive_violation, control_violation } = adjudicateInvariantDifferential({
    positiveRun: { violation: classifyFoundryViolation(positiveRow.foundry_result) },
    controlRun: { violation: classifyFoundryViolation(controlRow.foundry_result) },
  });

  return mintInvariantVerifiedRecord({
    targetDomain: domain,
    findingId,
    positiveRunHash: positiveRow.run_hash,
    controlRunHash: controlRow.run_hash,
    result,
    reason,
    positiveViolation: positive_violation,
    controlViolation: control_violation,
    templateId: positiveRow.template_id || null,
  });
}

// Mint the adjudicated verdict to the MCP-write-only, agent-Write-blocked
// invariant-verified.jsonl, keyed by finding_id and hash-bound to BOTH run
// hashes. Mirrors repro-replay-verifier.js::mintDifferentialRecord.
function mintInvariantVerifiedRecord({
  targetDomain, findingId, positiveRunHash, controlRunHash, result, reason,
  positiveViolation, controlViolation, templateId,
}) {
  const body = {
    version: INVARIANT_VERIFIED_VERSION,
    target_domain: targetDomain,
    ts: new Date().toISOString(),
    finding_id: findingId,
    result,
    reason,
    template_id: templateId,
    positive_run_hash: positiveRunHash,
    control_run_hash: controlRunHash || null,
    positive_violation: positiveViolation,
    control_violation: controlViolation || null,
  };
  const record = { ...body, results_hash: hashCanonicalJson(body) };
  withSessionLock(targetDomain, () => {
    appendJsonlLine(invariantVerifiedJsonlPath(targetDomain), record, {
      maxRecords: INVARIANT_VERIFIED_MAX_RECORDS,
    });
  });
  return {
    target_domain: targetDomain,
    finding_id: findingId,
    result,
    reason,
    positive_run_hash: positiveRunHash,
    control_run_hash: controlRunHash || null,
    results_hash: record.results_hash,
  };
}

// reverifyInvariantVerifiedRecord — READ-TIME INTEGRITY. Do NOT trust the verdict
// row's stored positive_run_hash/control_run_hash/template_id (results_hash is an
// UNKEYED self-hash, so a runtime-indirection write can append a bare forged
// verified_pass line whose run hashes point at nothing). RE-RESOLVE both run
// hashes against the content-hashed invariant-runs.jsonl rows and RE-ADJUDICATE
// the flip exactly as verifyInvariantDifferential does. A forged verdict whose
// run hashes don't resolve to a consistent flipping pair fails here (any throw →
// ok:false).
//
// FAIL-CLOSED on a rotated/truncated ledger: a verdict whose invariant-runs rows
// were legitimately minted then later removed reads as unverified. The source
// run rows ARE the asset — if they are gone, the verdict is no longer provable.
//
// Runs under NO lock (read-only, like the summary reader). Returns
// { ok, positive_run_hash, control_run_hash } — the run hashes are taken from the
// RE-RESOLVED rows (the signed-source values), never the verdict record's stored
// fields.
function reverifyInvariantVerifiedRecord(domain, record) {
  const targetDomain = assertSafeDomain(domain);
  if (record == null || typeof record !== "object") {
    return { ok: false, positive_run_hash: null, control_run_hash: null };
  }
  try {
    const findingId = parseFindingId(record.finding_id, "finding_id");
    const corpusPath = resolveInvariantRunsFilePath(invariantRunsJsonlPath(targetDomain), { createDir: false });
    const rows = readJsonlRuns(corpusPath);
    // Cycle B: resolve the keyed-MAC verifier ONCE for this re-derivation (not per row).
    // A present-but-invalid row_mac throws inside readInvariantRunRowForVerification →
    // caught below → ok:false, fail-closed exactly like a content-inconsistent row.
    const verifier = resolveInvariantRowVerifierSafely(targetDomain);
    const positiveRow = readInvariantRunRowForVerification(rows, record.positive_run_hash, "positive_run_hash", findingId, verifier);

    // A confirm needs a refuting control. No control arm → not a flip → not ok
    // (a single-run pass never confirms; mirrors verifyInvariantDifferential).
    if (record.control_run_hash == null
      || (typeof record.control_run_hash === "string" && !record.control_run_hash.trim())) {
      return { ok: false, positive_run_hash: null, control_run_hash: null };
    }
    const controlRow = readInvariantRunRowForVerification(rows, record.control_run_hash, "control_run_hash", findingId, verifier);

    // The control MUST be the SAME test on a DIFFERENT tree — identical binding to
    // verifyInvariantDifferential. A control that differs on the test identity
    // provably implicates the harness, so it is rejected.
    for (const field of ["template_id", "contract_name", "function_name", "execution_context_hash"]) {
      if ((positiveRow[field] || null) !== (controlRow[field] || null)) {
        throw new Error(`control_run_hash ${field} must match the positive run`);
      }
    }
    if (hashCanonicalJson(positiveRow.slot_values || null) !== hashCanonicalJson(controlRow.slot_values || null)) {
      throw new Error("control_run_hash slot_values must match the positive run");
    }
    if (positiveRow.run_hash === controlRow.run_hash) {
      throw new Error("control_run_hash must differ from positive_run_hash");
    }
    if ((positiveRow.tree_ref || null) === (controlRow.tree_ref || null)
      && positiveRow.checkout_kind === controlRow.checkout_kind) {
      throw new Error("control_run_hash must reference a DIFFERENT tree/checkout than the positive run");
    }

    const { result } = adjudicateInvariantDifferential({
      positiveRun: { violation: classifyFoundryViolation(positiveRow.foundry_result) },
      controlRun: { violation: classifyFoundryViolation(controlRow.foundry_result) },
    });
    return {
      ok: result === RESULT_VERIFIED_PASS,
      positive_run_hash: positiveRow.run_hash,
      control_run_hash: controlRow.run_hash,
      // Surface whether the POSITIVE run row (the row that demonstrates the
      // violation, i.e. the forgery vector if it ran host-as-signer) was executed
      // in a filesystem-namespace container. The verdict gate consults this so a
      // degrade-host SC run can never back a TRUSTED SC reportable. An absent/legacy
      // value reads false (fail-closed un-isolated at the gate).
      container_isolated: positiveRow.container_isolated === true,
    };
  } catch {
    // Missing / content-inconsistent / non-flipping / single-run / rotated row →
    // the flip is not re-derivable from the run rows. Fail closed.
    return { ok: false, positive_run_hash: null, control_run_hash: null, container_isolated: false };
  }
}

// readInvariantVerifiedSummary — the AUTHORITATIVE FV-confirm signal, mirroring
// readReproVerifiedSummary / readFindingDifferentialVerifiedSummary. Reads the
// MCP-write-only invariant-verified.jsonl, then RE-ADJUDICATES each verified_pass
// from the invariant-runs rows it cites rather than trusting the verdict's
// self-hashed fields.
//
// invariant-runs integrity is content-hash (computeInvariantRunHash binds
// outcome<->foundry_result) + agent-Write-block; a verified_pass is
// RE-ADJUDICATED here from the run rows it cites, not trusted from the verdict's
// self-hashed fields. This raises the forgery bar to a CONSISTENT flipping run
// pair, not a bare verdict line. NOTE: unlike the finding-differential ledger
// (whose source offensive-runs rows carry a keyed MAC), this is NOT MAC-level —
// signing invariant-runs rows + verifying the MAC at the proof-bundle gate is the
// deeper follow-up. The proof-bundle gate requires a VERIFIED_PASS whose
// positive/control run hashes match the bundle's invariant artifact (LEDGER-BY-ID).
function readInvariantVerifiedSummary(domain) {
  const targetDomain = assertSafeDomain(domain);
  let records = [];
  try {
    const raw = fs.readFileSync(invariantVerifiedJsonlPath(targetDomain), "utf8");
    records = raw
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch {
    records = [];
  }
  const verified = records.filter((r) => r.result === RESULT_VERIFIED_PASS);
  const verifiedByFinding = {};
  for (const r of verified) {
    const rederived = reverifyInvariantVerifiedRecord(targetDomain, r);
    if (!rederived.ok) continue;
    verifiedByFinding[r.finding_id] = {
      // RE-RESOLVED run hashes from the run rows the verdict cites, NOT the
      // verdict record's stored fields.
      positive_run_hash: rederived.positive_run_hash,
      control_run_hash: rederived.control_run_hash,
      template_id: r.template_id,
      // Whether the RE-RESOLVED positive run row was containerized. The verdict gate
      // treats an SC-backed reportable whose backing positive run was NOT
      // containerized (a degrade-host-as-signer run) as un-isolated, regardless of
      // the live signer-key probe. False on a legacy row predating the field.
      container_isolated: rederived.container_isolated === true,
    };
  }
  return {
    total_runs: records.length,
    verified_pass_count: verified.length,
    refuted_count: records.filter((r) => r.result === RESULT_REFUTED).length,
    inconclusive_count: records.filter((r) => r.result === RESULT_INCONCLUSIVE).length,
    // finding_id -> the RE-DERIVED bound run hashes, for the proof-bundle gate to
    // require a verified_pass whose positive/control run hashes match the bundle's
    // invariant artifact.
    verified_by_finding: verifiedByFinding,
  };
}

module.exports = {
  runInvariantForFinding,
  readInvariantRuns,
  readInvariantRunCorpus,
  buildTestSource,
  deriveTestNamesFromTemplate,
  renameTestFunction,
  classifyFoundryOutcome,
  classifyFoundryViolation,
  classifyHalmosViolation,
  adjudicateInvariantDifferential,
  // Exposed for the cross-stack differential bind path (cross-stack-differential-verifier.js):
  // it resolves an invariant-runs row by run_hash, re-derives computeInvariantRunHash, and
  // asserts the keyed INVARIANT_RUN_MAC_CONTEXT MAC — the SAME read-time integrity boundary
  // verifyInvariantDifferential uses, so an SC/EVM executed row is bindable as a MAC-verified
  // executed row the same way an offensive-runs row is (no new key, no new MAC).
  readInvariantRunRowForVerification,
  verifyInvariantDifferential,
  reverifyInvariantVerifiedRecord,
  readInvariantVerifiedSummary,
  computeInvariantRunHash,
  invariantFoundryResultHash,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
};
