const sanitizeHtml = require("sanitize-html");

function cleanString(s) {
  if (typeof s !== "string") return s;
  return sanitizeHtml(s, { allowedTags: [], allowedAttributes: {} }).trim();
}

function deepSanitize(obj) {
  if (!obj || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(deepSanitize);

  const out = {};
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    out[k] = typeof v === "string" ? cleanString(v) : deepSanitize(v);
  }
  return out;
}

module.exports = { cleanString, deepSanitize };
