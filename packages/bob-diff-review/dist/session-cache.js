"use strict";
/**
 * Session cache helpers for bob-runner.
 *
 * After the C2 composite action restores ~/hacker-bob-sessions/gh-<repository_id>,
 * these utilities determine whether the S3 phase (route extraction + symbol index
 * build) can be skipped, and resolve the deterministic target_domain override used
 * throughout the bob-diff-review pipeline.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildTargetDomain = buildTargetDomain;
exports.resolveSessionDir = resolveSessionDir;
exports.hasSymbolSurfaceIndex = hasSymbolSurfaceIndex;
exports.resolveCacheState = resolveCacheState;
exports.setOutput = setOutput;
exports.emitCacheOutputs = emitCacheOutputs;
const fs = __importStar(require("node:fs"));
const path = __importStar(require("node:path"));
const os = __importStar(require("node:os"));
// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
/** Directory under HOME where Bob writes all repository sessions. */
const BOB_SESSIONS_BASE = path.join(os.homedir(), "hacker-bob-sessions");
/** Filename written by S3 (bob_build_symbol_surface_index). */
const SYMBOL_INDEX_FILENAME = "symbol-surface-index.json";
// ---------------------------------------------------------------------------
// Core helpers
// ---------------------------------------------------------------------------
/**
 * Return the deterministic target_domain string for a GitHub repository.
 *
 * The 'gh-' prefix distinguishes GitHub-action sessions from human-launched
 * sessions (which use a real hostname). The numeric repository_id guarantees
 * uniqueness across forks and renames.
 *
 * @param repositoryId - github.repository_id (numeric, but passed as string)
 */
function buildTargetDomain(repositoryId) {
    if (!repositoryId || repositoryId === "0") {
        throw new Error(`repository_id is empty or zero ("${repositoryId}"). ` +
            "Pass github.repository_id to buildTargetDomain.");
    }
    return `gh-${repositoryId}`;
}
/**
 * Return the absolute path to the Bob session directory for a given repository.
 *
 * This must match the cache path used by the C2 composite action:
 *   ~/hacker-bob-sessions/gh-<repository_id>
 *
 * @param repositoryId - github.repository_id (numeric, but passed as string)
 */
function resolveSessionDir(repositoryId) {
    const targetDomain = buildTargetDomain(repositoryId);
    return path.join(BOB_SESSIONS_BASE, targetDomain);
}
/**
 * Check whether symbol-surface-index.json exists in the session directory.
 *
 * Returns true only when the file is present AND readable. A stale or
 * zero-byte file is accepted here; downstream validation (mtime check against
 * the diff) is the responsibility of the S3 step in bob-runner.
 *
 * @param sessionDir - absolute path returned by resolveSessionDir
 */
function hasSymbolSurfaceIndex(sessionDir) {
    const indexPath = path.join(sessionDir, SYMBOL_INDEX_FILENAME);
    try {
        fs.accessSync(indexPath, fs.constants.R_OK);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Collect all session cache metadata from the environment after the C2 action
 * has run. Reads GITHUB_OUTPUT-style env vars set by the composite action, with
 * a filesystem fallback so the module also works in local/dry-run mode.
 *
 * Sets the SKIP_SURFACE_BUILD environment variable if symbol-surface-index.json
 * is detected, matching the W1 workflow's expectation.
 *
 * @param repositoryId - github.repository_id (numeric string)
 * @returns SessionCacheInfo — callers pass sessionDir and targetDomain to MCP
 */
function resolveCacheState(repositoryId) {
    const targetDomain = buildTargetDomain(repositoryId);
    const sessionDir = resolveSessionDir(repositoryId);
    const hasIndex = hasSymbolSurfaceIndex(sessionDir);
    // Propagate skip signal to process environment so sub-processes (e.g. a
    // headless claude invocation) inherit it without re-computing.
    if (hasIndex) {
        process.env["SKIP_SURFACE_BUILD"] = "true";
    }
    else {
        // Explicitly clear in case a previous run left a stale value.
        delete process.env["SKIP_SURFACE_BUILD"];
    }
    return { sessionDir, targetDomain, hasSymbolIndex: hasIndex };
}
// ---------------------------------------------------------------------------
// GitHub Actions output helpers
// ---------------------------------------------------------------------------
/**
 * Write a key=value pair to the GITHUB_OUTPUT file if running inside a
 * GitHub Actions runner. No-op otherwise.
 *
 * @param name  - output variable name
 * @param value - string value
 */
function setOutput(name, value) {
    const outputFile = process.env["GITHUB_OUTPUT"];
    if (!outputFile)
        return;
    fs.appendFileSync(outputFile, `${name}=${value}\n`, { encoding: "utf-8" });
}
/**
 * Emit all C2-relevant outputs to GITHUB_OUTPUT and log a summary.
 * Call this from bob-runner.ts after resolveCacheState.
 */
function emitCacheOutputs(info) {
    setOutput("session_dir", info.sessionDir);
    setOutput("target_domain", info.targetDomain);
    setOutput("cache_hit_symbol_index", info.hasSymbolIndex ? "true" : "false");
    const indexStatus = info.hasSymbolIndex
        ? "found — S3 phase will be skipped (SKIP_SURFACE_BUILD=true)"
        : "not found — S3 phase will run";
    console.log(`[session-cache] session_dir:    ${info.sessionDir}`);
    console.log(`[session-cache] target_domain:  ${info.targetDomain}`);
    console.log(`[session-cache] symbol index:   ${indexStatus}`);
}
//# sourceMappingURL=session-cache.js.map