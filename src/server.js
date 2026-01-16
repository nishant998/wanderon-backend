require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
// const rateLimit = require("express-rate-limit");
const morgan = require("morgan");

const { connectDB } = require("./config/db");
const { noSqlSanitize } = require("./middleware/nosql-sanitize.middleware");
const { errorHandler } = require("./middleware/error.middleware");

const swaggerUi = require("swagger-ui-express");
const { swaggerSpec } = require("./docs/swagger");

const authRoutes = require("./routes/auth.routes");

const app = express();

app.set("trust proxy", 1);

app.use(morgan("dev"));
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

const allowedOrigins = (process.env.CLIENT_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin: function (origin, cb) {
    if (!origin) return cb(null, true);

    if (allowedOrigins.includes(origin)) return cb(null, true);

    return cb(new Error(`CORS blocked for origin: ${origin}`), false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  exposedHeaders: ["Set-Cookie"],
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

// app.use(
//   rateLimit({
//     windowMs: 10 * 60 * 1000,
//     max: 200,
//     standardHeaders: true,
//     legacyHeaders: false,
//   })
// );

app.get("/", (req, res) =>
  res.json({ ok: true, name: "WanderOn Auth API" })
);

app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.use("/auth", noSqlSanitize());
app.use("/auth", authRoutes);

app.use(errorHandler);

(async () => {
  try {
    await connectDB();

    const port = process.env.PORT || 4000;
    app.listen(port, () => {
      console.log(`API running on http://localhost:${port}`);
      console.log(`Allowed origins: ${allowedOrigins.join(", ") || "(none)"}`);
    });
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
})();
