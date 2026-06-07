export {
  buildTargetDomain,
  resolveSessionDir,
  hasSymbolSurfaceIndex,
  resolveCacheState,
  setOutput,
  emitCacheOutputs,
} from "./session-cache.js";
export type { SessionCacheInfo } from "./session-cache.js";

export {
  validateRepoPath,
  sessionDirExists,
  buildInitParams,
  normaliseInitResult,
  normaliseInventoryResult,
  prepareS2,
  formatStepFailureJson,
} from "./session-init.js";
export type {
  InitRepoSessionParams,
  S2InitResult,
  S2InitError,
  S2InventoryResult,
  InventoryEntry,
  S2StepArgs,
  S2StepResult,
} from "./session-init.js";

export { fetchPRDiff, buildDiffPositionMap } from "./diff.js";
export type { OctokitLike } from "./diff.js";
export type { DiffPositionMap, DiffHunk, PositionEntry } from "./types.js";

export {
  deriveCheckRunStatus,
  startCheckRun,
  completeCheckRun,
  createCheckRun,
} from "./check-run.js";
export type {
  CheckRunStatus,
  ChecksOctokitLike,
  Conclusion,
  Severity,
  SeverityBreakdown,
} from "./check-run.js";

export { submitPRReview } from "./reviews-api.js";
export type {
  ResolvedComment,
  ReviewSummary,
  ReviewsOctokitLike,
} from "./reviews-api.js";

export {
  SYMBOL_INDEX_FILENAME,
  isSkipEnvSet,
  indexFileExists,
  decideS3,
  normaliseRoutesResult,
  normaliseIndexResult,
  formatS3FailureJson,
} from "./surface-index.js";
export type {
  SymbolSurfaceEntry,
  ExtractedRoute,
  S3RoutesResult,
  S3IndexResult,
  S3StepDecision,
} from "./surface-index.js";

export {
  runPathB,
  buildHeuristicImpactedEntries,
  parseDiffFiles,
  MAX_HEURISTIC_SURFACES,
  MAX_UNKNOWN_DISPATCHES,
} from "./heuristic-dispatch.js";
export type {
  ImpactedEntry,
  DiffFileEntry,
  PathBResult,
} from "./heuristic-dispatch.js";

export {
  normaliseDiffImpactResult,
  formatS4FailureJson,
  logPathAActivation,
  logPathASuccess,
  logNoImpactedSurfaces,
  buildDiffImpactArtifact,
} from "./diff-impact.js";
export type {
  RawDiffImpactResponse,
  S4PathAResult,
  DiffImpactParams,
  DiffImpactArtifact,
} from "./diff-impact.js";

export {
  MAX_EVALUATOR_AGENTS,
  AGENT_TIMEOUT_MS,
  deduplicateAndPrioritize,
  buildDiffHunksForSurface,
  buildAgentContexts,
  buildS5SpawnPlan,
  initSpawnedAgent,
  markAgentCompleted,
  markAgentTimedOut,
  allAgentsExited,
  findTimedOutAgents,
  findCoverageGaps,
  formatS5FailureJson,
} from "./evaluator-dispatch.js";
export type {
  EvalDiffHunk,
  EvaluatorAgentContext,
  SpawnedAgent,
  DeduplicationResult,
  AgentContextsResult,
  S5SpawnPlan,
} from "./evaluator-dispatch.js";

export {
  BOB_RUNNER_TIMEOUT_MS,
  BobRunnerError,
  validateDiffReviewFindings,
  resolveOutputDir,
  runBobDiffReview,
} from "./bob-runner.js";
export type { BobRunnerParams } from "./bob-runner.js";

export {
  resolveFindings,
  resolvePosition,
  formatCommentBody,
  formatPRLevelBody,
} from "./resolver.js";
export type { ResolvedComment as ResolvedFindingComment } from "./resolver.js";

export {
  EVIDENCE_MAX_CHARS,
  VALID_SEVERITIES,
  normaliseSeverity,
  truncate,
  sanitiseEvidence,
  normaliseCandidateClaim,
  rangesOverlap,
  findMatchingEntry,
  serializeFindings,
  writeFindings,
  validateJsonFile,
  formatS6FailureJson,
} from "./findings-serializer.js";
export type {
  FindingSeverity,
  RawCandidateClaim,
  FindingEntry,
  DiffReviewFindings,
  SerializeParams,
  SerializeResult,
} from "./findings-serializer.js";
