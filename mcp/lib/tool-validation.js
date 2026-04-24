"use strict";

const { TOOLS } = require("./tool-definitions.js");

const TOOL_BY_NAME = new Map(TOOLS.map((tool) => [tool.name, tool]));

function getToolDefinition(name) {
  return TOOL_BY_NAME.get(name) || null;
}

function schemaTypeMatches(value, schemaType) {
  const types = Array.isArray(schemaType) ? schemaType : [schemaType];
  return types.some((type) => {
    if (type === "null") return value === null;
    if (type === "array") return Array.isArray(value);
    if (type === "object") return value != null && typeof value === "object" && !Array.isArray(value);
    if (type === "number") return typeof value === "number" && Number.isFinite(value);
    if (type === "integer") return Number.isInteger(value);
    return typeof value === type;
  });
}

function validateTopLevelType(value, propertySchema, fieldName) {
  if (!propertySchema || value == null || propertySchema.oneOf) {
    return;
  }
  if (propertySchema.type && !schemaTypeMatches(value, propertySchema.type)) {
    const expected = Array.isArray(propertySchema.type)
      ? propertySchema.type.join(" or ")
      : propertySchema.type;
    throw new Error(`${fieldName} must be ${expected}`);
  }
  if (propertySchema.enum && !propertySchema.enum.includes(value)) {
    throw new Error(`${fieldName} must be one of ${propertySchema.enum.join(", ")}`);
  }
}

function validateToolArguments(name, args) {
  const tool = getToolDefinition(name);
  if (!tool) {
    return;
  }

  const schema = tool.inputSchema || {};
  if (schema.type === "object" && (args == null || typeof args !== "object" || Array.isArray(args))) {
    throw new Error(`${name} arguments must be an object`);
  }

  const properties = schema.properties || {};
  const required = Array.isArray(schema.required) ? schema.required : [];
  const allowedKeys = new Set(Object.keys(properties));

  for (const key of Object.keys(args || {})) {
    if (!allowedKeys.has(key)) {
      throw new Error(`Unknown argument for ${name}: ${key}`);
    }
  }

  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(args || {}, key) || args[key] == null) {
      throw new Error(`Missing required argument for ${name}: ${key}`);
    }
  }

  for (const [key, value] of Object.entries(args || {})) {
    validateTopLevelType(value, properties[key], key);
  }
}

module.exports = {
  getToolDefinition,
  validateToolArguments,
};
