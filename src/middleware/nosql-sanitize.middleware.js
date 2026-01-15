function sanitizeObjectInPlace(obj) {
  if (!obj || typeof obj !== "object") return;

  if (Array.isArray(obj)) {
    for (const item of obj) sanitizeObjectInPlace(item);
    return;
  }

  for (const key of Object.keys(obj)) {
    if (key.startsWith("$") || key.includes(".")) {
      delete obj[key];
      continue;
    }

    sanitizeObjectInPlace(obj[key]);
  }
}

function noSqlSanitize() {
  return (req, _res, next) => {
    try {
      sanitizeObjectInPlace(req.body);
      const q = req.query;
      sanitizeObjectInPlace(q);
    } catch (_) {
    }
    next();
  };
}

module.exports = { noSqlSanitize };
