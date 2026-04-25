const {
  ERROR_CODES,
  classifyDataError,
  classifyException,
  errorEnvelope,
  okEnvelope,
  parseHandlerResult,
} = require("./envelope.js");
const {
  TOOL_HANDLERS,
  getRegisteredTool,
} = require("./tool-registry.js");
const {
  validateToolArguments,
} = require("./tool-validation.js");
const {
  safeRecordToolTelemetry,
} = require("./tool-telemetry.js");

async function executeTool(name, args) {
  const startedAt = Date.now();
  const safeArgs = args || {};
  const tool = getRegisteredTool(name);
  const finish = (envelope) => {
    safeRecordToolTelemetry({
      toolName: name,
      tool,
      args: safeArgs,
      envelope,
      elapsedMs: Date.now() - startedAt,
    });
    return envelope;
  };

  if (!tool) {
    return finish(errorEnvelope(name, ERROR_CODES.UNKNOWN_TOOL, `Unknown tool: ${name}`));
  }

  try {
    validateToolArguments(name, safeArgs);
  } catch (error) {
    return finish(errorEnvelope(name, ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error)));
  }

  try {
    const data = parseHandlerResult(await tool.handler(safeArgs));
    const dataErrorCode = classifyDataError(data);
    if (dataErrorCode) {
      return finish(errorEnvelope(name, dataErrorCode, data.error, data));
    }
    return finish(okEnvelope(name, data));
  } catch (error) {
    return finish(errorEnvelope(name, classifyException(error), error.message || String(error), error.details));
  }
}

module.exports = {
  TOOL_HANDLERS,
  executeTool,
};
