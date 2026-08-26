"use strict";

const FILE_HEADER = /^\+\+\+\s+(?:b\/)?(.+?)(?:\s+|$)/;
const FILE_DELETED_HEADER = /^---\s+(?:a\/)?(.+?)(?:\s+|$)/;
const HUNK_HEADER = /^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/;
const WHOLE_FILE_RANGE_END = Number.MAX_SAFE_INTEGER;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function mergeRanges(ranges) {
  if (!Array.isArray(ranges) || ranges.length === 0) return [];
  const sorted = ranges.slice().sort((a, b) => a.start - b.start);
  const merged = [sorted[0]];
  for (let i = 1; i < sorted.length; i++) {
    const last = merged[merged.length - 1];
    const next = sorted[i];
    if (next.start <= last.end + 1) {
      last.end = Math.max(last.end, next.end);
    } else {
      merged.push({ ...next });
    }
  }
  return merged;
}

function diffLineRanges(entry) {
  const addedRanges = mergeRanges(entry.added_ranges);
  if (addedRanges.length === 0 && entry.removed_lines > 0) {
    return [{ start: 1, end: WHOLE_FILE_RANGE_END }];
  }
  return addedRanges;
}

function parseUnifiedDiff(rawDiff) {
  if (typeof rawDiff !== "string") {
    throw new TypeError("rawDiff must be a string");
  }
  const lines = rawDiff.split(/\r?\n/);
  const fileMap = new Map();
  let currentFile = null;
  let currentLine = null;
  let currentDeletedFile = null;
  for (const line of lines) {
    if (line.startsWith("--- ")) {
      const m = line.match(FILE_DELETED_HEADER);
      currentDeletedFile = m ? m[1] : null;
      continue;
    }
    if (line.startsWith("+++ ")) {
      const m = line.match(FILE_HEADER);
      if (!m) continue;
      currentFile = m[1] === "/dev/null" ? currentDeletedFile : m[1];
      currentLine = null;
      if (currentFile && !fileMap.has(currentFile)) {
        fileMap.set(currentFile, { added_ranges: [], removed_lines: 0, added_lines: 0 });
      }
      continue;
    }
    if (line.startsWith("@@")) {
      const m = line.match(HUNK_HEADER);
      if (!m || currentFile == null) continue;
      currentLine = parseInt(m[3], 10);
      continue;
    }
    if (currentFile == null || currentLine == null) continue;
    const fileEntry = fileMap.get(currentFile);
    if (line.startsWith("+") && !line.startsWith("+++")) {
      fileEntry.added_ranges.push({ start: currentLine, end: currentLine });
      fileEntry.added_lines += 1;
      currentLine += 1;
      continue;
    }
    if (line.startsWith("-") && !line.startsWith("---")) {
      fileEntry.removed_lines += 1;
      continue;
    }
    if (line.startsWith(" ")) {
      currentLine += 1;
      continue;
    }
    if (line.startsWith("\\")) continue;
  }
  const diffFiles = [];
  for (const [file, entry] of fileMap) {
    diffFiles.push({
      file,
      line_ranges: diffLineRanges(entry),
      added_lines: entry.added_lines,
      removed_lines: entry.removed_lines,
    });
  }
  diffFiles.sort((a, b) => a.file.localeCompare(b.file));
  return {
    schema_version: 1,
    diff_files: diffFiles,
    total_added_lines: diffFiles.reduce((acc, f) => acc + f.added_lines, 0),
    total_removed_lines: diffFiles.reduce((acc, f) => acc + f.removed_lines, 0),
    file_count: diffFiles.length,
  };
}

module.exports = {
  parseUnifiedDiff,
};
