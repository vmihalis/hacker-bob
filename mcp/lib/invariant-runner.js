"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const {
  assertSafeDomain,
  invariantRunsJsonlPath,
  sessionsRoot,
} = require("./paths.js");
const {
  parseFindingId,
} = require("./validation.js");
const {
  suggestInvariantsForFinding,
} = require("./invariant-template-corpus.js");
const {
  DEFAULT_ARTIFACT_READ_MAX_BYTES,
  withSessionLock,
} = require("./storage.js");
const { ERROR_CODES } = require("./envelope.js");
const { hashCanonicalJson } = require("./verification-contracts.js");

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

function invariantFoundryResultHash(foundryResult) {
  return hashCanonicalJson(foundryResult == null ? null : foundryResult);
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
  const executionContext = {
    chain_id: chain_id || null,
    fork_block: fork_block == null ? null : fork_block,
    fork_urls: Array.isArray(fork_urls) ? fork_urls : null,
    extra_args: Array.isArray(extra_args) ? extra_args : null,
    match_contract: match_contract || null,
    match_test: match_test || null,
  };
  const executionContextHash = hashCanonicalJson(executionContext);
  let writtenPath = null;
  let foundryRawResult = null;
  let outcome = "dry_run";
  let runHash = null;
  let invariantRunsRetention = null;
  if (dry_run !== true) {
    const bobDir = ensureHarnessTestDir(harness_path);
    writtenPath = writeInvariantSourceFile(bobDir, `${contract_name}.t.sol`, source);
    foundryRawResult = await foundry_run({
      target_domain: domain,
      harness_path,
      match_test: match_test || function_name,
      match_contract: match_contract || contract_name,
      chain_id,
      fork_block,
      fork_urls,
      extra_args,
      timeout_ms,
    });
    if (typeof foundryRawResult === "string") {
      try {
        foundryRawResult = JSON.parse(foundryRawResult);
      } catch (_err) {
        // leave as string for downstream inspection.
      }
    }
    outcome = classifyFoundryOutcome(foundryRawResult);
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
  };
  if (dry_run !== true) {
    await withInvariantSessionWriteLock(domain, () => {
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

module.exports = {
  runInvariantForFinding,
  readInvariantRuns,
  readInvariantRunCorpus,
  buildTestSource,
  deriveTestNamesFromTemplate,
  renameTestFunction,
  classifyFoundryOutcome,
  computeInvariantRunHash,
  invariantFoundryResultHash,
};
