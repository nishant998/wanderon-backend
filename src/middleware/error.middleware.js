function errorHandler(err, req, res, next) {
  console.error(err);

  if (err.name === "ZodError") {
    return res.status(400).json({
      message: "Validation error",
      errors: err.errors.map((x) => ({ path: x.path.join("."), message: x.message })),
    });
  }

  return res.status(err.statusCode || 500).json({
    message: err.message || "Internal Server Error",
  });
}

module.exports = { errorHandler };
