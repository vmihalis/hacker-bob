"use strict";

const { getRegisteredTool } = require("./tool-registry.js");

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

function expectedTypeLabel(schemaType) {
  return Array.isArray(schemaType) ? schemaType.join(" or ") : schemaType;
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function formatPath(pathParts) {
  if (!pathParts.length) return "value";
  return pathParts.map((part, index) => {
    if (typeof part === "number") return `[${part}]`;
    return index === 0 ? part : `.${part}`;
  }).join("");
}

function validateEnum(value, schema, pathParts) {
  if (!schema.enum) return;
  if (!schema.enum.some((item) => Object.is(item, value))) {
    throw new Error(`${formatPath(pathParts)} must be one of ${schema.enum.map((item) => String(item)).join(", ")}`);
  }
}

function validateStringConstraints(value, schema, pathParts) {
  if (typeof value !== "string") return;
  if (schema.minLength != null && value.length < schema.minLength) {
    throw new Error(`${formatPath(pathParts)} must be at least ${schema.minLength} characters`);
  }
  if (schema.maxLength != null && value.length > schema.maxLength) {
    throw new Error(`${formatPath(pathParts)} must be at most ${schema.maxLength} characters`);
  }
  if (schema.pattern != null) {
    const pattern = new RegExp(schema.pattern);
    if (!pattern.test(value)) {
      throw new Error(`${formatPath(pathParts)} must match pattern ${schema.pattern}`);
    }
  }
}

function validateNumberConstraints(value, schema, pathParts) {
  if (typeof value !== "number") return;
  if (schema.minimum != null && value < schema.minimum) {
    throw new Error(`${formatPath(pathParts)} must be >= ${schema.minimum}`);
  }
  if (schema.maximum != null && value > schema.maximum) {
    throw new Error(`${formatPath(pathParts)} must be <= ${schema.maximum}`);
  }
  if (schema.min != null && value < schema.min) {
    throw new Error(`${formatPath(pathParts)} must be >= ${schema.min}`);
  }
  if (schema.max != null && value > schema.max) {
    throw new Error(`${formatPath(pathParts)} must be <= ${schema.max}`);
  }
}

function validateArrayConstraints(value, schema, pathParts) {
  if (!Array.isArray(value)) return;
  if (schema.minItems != null && value.length < schema.minItems) {
    throw new Error(`${formatPath(pathParts)} must contain at least ${schema.minItems} items`);
  }
  if (schema.maxItems != null && value.length > schema.maxItems) {
    throw new Error(`${formatPath(pathParts)} must contain at most ${schema.maxItems} items`);
  }
}

function validateOneOf(value, schema, pathParts) {
  if (!Array.isArray(schema.oneOf)) {
    return;
  }

  let matches = 0;
  const errors = [];
  for (const option of schema.oneOf) {
    try {
      validateAgainstSchema(value, option, pathParts);
      matches += 1;
    } catch (error) {
      errors.push(error.message || String(error));
    }
  }

  if (matches !== 1) {
    if (matches > 1) {
      throw new Error(`${formatPath(pathParts)} must match exactly one allowed schema`);
    }
    throw new Error(`${formatPath(pathParts)} must match one allowed schema: ${errors.join("; ")}`);
  }
}

function validateObject(value, schema, pathParts) {
  const properties = schema.properties || {};
  const required = Array.isArray(schema.required) ? schema.required : [];
  const additionalProperties = hasOwn(schema, "additionalProperties")
    ? schema.additionalProperties
    : false;

  for (const key of required) {
    if (!hasOwn(value, key) || value[key] == null) {
      throw new Error(`${formatPath([...pathParts, key])} is required`);
    }
  }

  for (const [key, childValue] of Object.entries(value)) {
    if (hasOwn(properties, key)) {
      validateAgainstSchema(childValue, properties[key], [...pathParts, key]);
      continue;
    }

    if (additionalProperties === true) {
      continue;
    }
    if (additionalProperties && typeof additionalProperties === "object") {
      validateAgainstSchema(childValue, additionalProperties, [...pathParts, key]);
      continue;
    }

    throw new Error(`${formatPath([...pathParts, key])} is not allowed`);
  }
}

function validateAgainstSchema(value, schema, pathParts = []) {
  if (!schema || typeof schema !== "object") {
    return;
  }

  if (Array.isArray(schema.oneOf)) {
    validateOneOf(value, schema, pathParts);
    return;
  }

  if (schema.type && !schemaTypeMatches(value, schema.type)) {
    throw new Error(`${formatPath(pathParts)} must be ${expectedTypeLabel(schema.type)}`);
  }

  validateEnum(value, schema, pathParts);
  validateStringConstraints(value, schema, pathParts);
  validateNumberConstraints(value, schema, pathParts);
  validateArrayConstraints(value, schema, pathParts);

  if (value == null) {
    return;
  }

  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  if (types.includes("object") || (!schema.type && (schema.properties || schema.additionalProperties))) {
    if (typeof value === "object" && !Array.isArray(value)) {
      validateObject(value, schema, pathParts);
    }
  }

  if ((types.includes("array") || (!schema.type && schema.items)) && Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      validateAgainstSchema(value[index], schema.items || {}, [...pathParts, index]);
    }
  }
}

function validateToolArguments(name, args) {
  const tool = getRegisteredTool(name);
  if (!tool) {
    return;
  }

  const schema = tool.inputSchema || {};
  validateAgainstSchema(args, schema, []);
}

module.exports = {
  validateToolArguments,
  validateAgainstSchema,
};
