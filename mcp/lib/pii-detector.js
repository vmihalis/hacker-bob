"use strict";

const MAX_SCAN_BYTES = 1024 * 1024;
const MAX_MATCHES = 200;

function normalizeEmailForComparison(email) {
  if (typeof email !== "string") return null;
  const normalized = email.trim().toLowerCase();
  if (!normalized) return null;

  const atIndex = normalized.lastIndexOf("@");
  if (atIndex === -1) return normalized;

  let local = normalized.slice(0, atIndex);
  let domain = normalized.slice(atIndex + 1);

  const plusIndex = local.indexOf("+");
  if (plusIndex !== -1) {
    local = local.slice(0, plusIndex);
  }

  if (domain === "gmail.com" || domain === "googlemail.com") {
    local = local.replace(/\./g, "");
    domain = "gmail.com";
  }

  return `${local}@${domain}`;
}

function luhnCheck(digits) {
  if (!/^\d{13,19}$/.test(digits)) return false;
  if (/^(\d)\1+$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let value = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      value *= 2;
      if (value > 9) value -= 9;
    }
    sum += value;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

function isLikelyPhone(candidate) {
  if (/[A-Za-z]/.test(candidate)) return false;
  if (/^\d{4}-\d{2}-\d{2}/.test(candidate)) return false;

  const digits = candidate.replace(/\D/g, "");
  if (digits.length < 10 || digits.length > 15) return false;

  if (candidate.startsWith("+")) return true;
  if (!/[\s().-]/.test(candidate)) return false;
  if (digits.length === 10) return true;
  return digits.length === 11 && digits.startsWith("1");
}

function detectPiiShapes(text) {
  const scan = typeof text === "string" ? text.slice(0, MAX_SCAN_BYTES) : "";
  if (!scan) return [];

  const matches = [];
  const seen = new Set();
  const addMatch = (type, value) => {
    if (!value || matches.length >= MAX_MATCHES) return false;
    const key = `${type}\0${value}`;
    if (seen.has(key)) return true;
    seen.add(key);
    matches.push({ type, value });
    return matches.length < MAX_MATCHES;
  };

  const emailPattern = /(^|[^A-Z0-9._%+-])([A-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+)(?![A-Z0-9._%+-])/gi;
  for (const match of scan.matchAll(emailPattern)) {
    if (!addMatch("email", match[2])) return matches;
  }

  const phonePattern = /(^|[^A-Z0-9+])(\+?\d[\d\s().-]{7,}\d)(?![A-Z0-9])/g;
  for (const match of scan.matchAll(phonePattern)) {
    const candidate = match[2].trim();
    if (isLikelyPhone(candidate) && !addMatch("phone", candidate)) return matches;
  }

  const ssnPattern = /(^|\D)(\d{3}-\d{2}-\d{4})(?!\d)/g;
  for (const match of scan.matchAll(ssnPattern)) {
    if (!addMatch("ssn", match[2])) return matches;
  }

  const cardPattern = /(^|\D)(\d{13,19})(?!\d)/g;
  for (const match of scan.matchAll(cardPattern)) {
    const digits = match[2];
    if (luhnCheck(digits) && !addMatch("credit_card", digits)) return matches;
  }

  return matches;
}

function emailMatchesOperatorDenylist(email, operatorIdentifiers) {
  if (!Array.isArray(operatorIdentifiers) || operatorIdentifiers.length === 0) return false;

  const normalizedEmail = normalizeEmailForComparison(email);
  if (!normalizedEmail) return false;

  return operatorIdentifiers.some((identifier) => (
    normalizeEmailForComparison(identifier) === normalizedEmail
  ));
}

module.exports = {
  normalizeEmailForComparison,
  detectPiiShapes,
  emailMatchesOperatorDenylist,
};
