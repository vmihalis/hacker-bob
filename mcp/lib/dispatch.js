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

async function executeTool(name, args) {
  const tool = getRegisteredTool(name);
  if (!tool) {
    return errorEnvelope(name, ERROR_CODES.UNKNOWN_TOOL, `Unknown tool: ${name}`);
  }

  try {
    validateToolArguments(name, args || {});
  } catch (error) {
    return errorEnvelope(name, ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }

  try {
    const data = parseHandlerResult(await tool.handler(args || {}));
    const dataErrorCode = classifyDataError(data);
    if (dataErrorCode) {
      return errorEnvelope(name, dataErrorCode, data.error, data);
    }
    return okEnvelope(name, data);
  } catch (error) {
    return errorEnvelope(name, classifyException(error), error.message || String(error), error.details);
  }
}

module.exports = {
  TOOL_HANDLERS,
  executeTool,
};
