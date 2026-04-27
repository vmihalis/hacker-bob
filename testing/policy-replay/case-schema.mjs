import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const REPO_ROOT = path.resolve(__dirname, "..", "..");
export const FAILURE_TYPES = new Set([
  "refusal",
  "policy_stall",
  "tool_policy_loop",
  "unsafe_compliance",
]);
export const EXPECTED_RESULTS = new Set([
  "should_continue_safely",
  "should_refuse",
  "should_ask_clarification",
]);

export function expandHome(value) {
  if (!value) return value;
  if (value === "~") return os.homedir();
  if (value.startsWith("~/")) return path.join(os.homedir(), value.slice(2));
  return value;
}

export function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      args[key] = true;
    } else {
      args[key] = next;
      i++;
    }
  }
  return args;
}

export function stripFrontmatter(raw) {
  if (!raw.startsWith("---")) return raw;
  const end = raw.indexOf("\n---", 3);
  if (end === -1) return raw;
  return raw.slice(end + 4).trimStart();
}

export function loadSystemPrompt(filePath) {
  return stripFrontmatter(fs.readFileSync(expandHome(filePath), "utf8"));
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateStringArray(value, pathName, errors) {
  if (!Array.isArray(value)) {
    errors.push(`${pathName} must be an array`);
    return;
  }
  value.forEach((item, index) => {
    if (typeof item !== "string" || item.trim() === "") {
      errors.push(`${pathName}[${index}] must be a non-empty string`);
    }
  });
}

function validateTranscriptSource(value, errors) {
  if (typeof value === "string") {
    if (value.trim() === "") errors.push("transcript_source must not be empty");
    return;
  }
  if (!isObject(value)) {
    errors.push("transcript_source must be a path string or object");
    return;
  }
  if (typeof value.path !== "string" || value.path.trim() === "") {
    errors.push("transcript_source.path is required");
  }
  if (
    value.sha256 !== undefined &&
    (typeof value.sha256 !== "string" || !/^[a-f0-9]{64}$/i.test(value.sha256))
  ) {
    errors.push("transcript_source.sha256 must be a 64-character hex digest");
  }
  if (value.redacted !== undefined && typeof value.redacted !== "boolean") {
    errors.push("transcript_source.redacted must be boolean when present");
  }
}

function validateRedaction(value, errors) {
  if (!isObject(value)) {
    errors.push("redaction must be an object");
    return;
  }
  if (
    value.status !== undefined &&
    !["raw", "redacted", "synthetic"].includes(value.status)
  ) {
    errors.push("redaction.status must be raw, redacted, or synthetic");
  }
  if (value.notes !== undefined) {
    validateStringArray(value.notes, "redaction.notes", errors);
  }
  if (value.replacements !== undefined) {
    if (!Array.isArray(value.replacements)) {
      errors.push("redaction.replacements must be an array");
    } else {
      value.replacements.forEach((replacement, index) => {
        if (!isObject(replacement)) {
          errors.push(`redaction.replacements[${index}] must be an object`);
          return;
        }
        if (
          typeof replacement.placeholder !== "string" ||
          replacement.placeholder.trim() === ""
        ) {
          errors.push(
            `redaction.replacements[${index}].placeholder is required`,
          );
        }
        if (
          replacement.description !== undefined &&
          typeof replacement.description !== "string"
        ) {
          errors.push(
            `redaction.replacements[${index}].description must be a string`,
          );
        }
      });
    }
  }
}

function validateReplay(value, errors) {
  if (!isObject(value)) {
    errors.push("replay must be an object");
    return;
  }
  for (const key of ["failure_event_index", "next_user_index"]) {
    if (
      value[key] !== undefined &&
      (!Number.isInteger(value[key]) || value[key] < 0)
    ) {
      errors.push(`replay.${key} must be a non-negative integer`);
    }
  }
}

export function validateCase(raw) {
  const errors = [];
  if (!isObject(raw)) {
    return { ok: false, errors: ["case must be a JSON object"] };
  }

  if (raw.id !== undefined && (typeof raw.id !== "string" || raw.id.trim() === "")) {
    errors.push("id must be a non-empty string when present");
  }
  if (typeof raw.agent_type !== "string" || raw.agent_type.trim() === "") {
    errors.push("agent_type is required");
  }
  if (typeof raw.prompt_path !== "string" || raw.prompt_path.trim() === "") {
    errors.push("prompt_path is required");
  }
  if (!FAILURE_TYPES.has(raw.failure_type)) {
    errors.push(
      `failure_type must be one of ${Array.from(FAILURE_TYPES).join(", ")}`,
    );
  }
  if (!EXPECTED_RESULTS.has(raw.expected)) {
    errors.push(
      `expected must be one of ${Array.from(EXPECTED_RESULTS).join(", ")}`,
    );
  }

  const hasTranscriptSource = raw.transcript_source !== undefined;
  const hasTranscript = raw.transcript !== undefined;
  if (!hasTranscriptSource && !hasTranscript) {
    errors.push("case must include transcript_source or transcript");
  }
  if (hasTranscriptSource) validateTranscriptSource(raw.transcript_source, errors);
  if (hasTranscript) {
    if (!Array.isArray(raw.transcript) || raw.transcript.length === 0) {
      errors.push("transcript must be a non-empty array");
    } else {
      raw.transcript.forEach((event, index) => {
        if (!isObject(event)) errors.push(`transcript[${index}] must be an object`);
      });
    }
  }

  if (raw.notes !== undefined && typeof raw.notes !== "string") {
    errors.push("notes must be a string when present");
  }
  if (raw.redaction !== undefined) validateRedaction(raw.redaction, errors);
  if (raw.replay !== undefined) validateReplay(raw.replay, errors);
  if (raw.unsafe_compliance_patterns !== undefined) {
    validateStringArray(
      raw.unsafe_compliance_patterns,
      "unsafe_compliance_patterns",
      errors,
    );
  }

  return { ok: errors.length === 0, errors };
}

export function loadCase(casePath) {
  const absoluteCasePath = path.resolve(expandHome(casePath));
  const raw = JSON.parse(fs.readFileSync(absoluteCasePath, "utf8"));
  const validation = validateCase(raw);
  if (!validation.ok) {
    throw new Error(
      `invalid policy replay case ${absoluteCasePath}: ${validation.errors.join("; ")}`,
    );
  }
  return {
    casePath: absoluteCasePath,
    caseDir: path.dirname(absoluteCasePath),
    caseData: {
      ...raw,
      id: raw.id || path.basename(absoluteCasePath, ".json"),
    },
  };
}

export function resolveCasePath(casePath, relativeOrAbsolute) {
  const expanded = expandHome(relativeOrAbsolute);
  if (path.isAbsolute(expanded)) return expanded;
  return path.resolve(path.dirname(casePath), expanded);
}

export function resolvePromptPath(caseData, casePath, overridePath) {
  const promptPath = overridePath || caseData.prompt_path;
  const expanded = expandHome(promptPath);
  if (path.isAbsolute(expanded)) return expanded;
  const repoRelative = path.resolve(REPO_ROOT, expanded);
  if (fs.existsSync(repoRelative)) return repoRelative;
  return path.resolve(path.dirname(casePath), expanded);
}

export function transcriptEventsForCase(caseData, casePath) {
  if (Array.isArray(caseData.transcript)) {
    return caseData.transcript;
  }
  const source =
    typeof caseData.transcript_source === "string"
      ? caseData.transcript_source
      : caseData.transcript_source.path;
  const transcriptPath = resolveCasePath(casePath, source);
  return fs
    .readFileSync(transcriptPath, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(
          `${transcriptPath}:${index + 1} is not valid JSON: ${error.message}`,
        );
      }
    });
}
