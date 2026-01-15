const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const { noSqlSanitize } = require("./middleware/nosql-sanitize.middleware");

const swaggerUi = require("swagger-ui-express");
const { swaggerSpec } = require("./docs/swagger");

const authRoutes = require("./routes/auth.routes");
const { errorHandler } = require("./middleware/error.middleware");

const app = express();

app.set("trust proxy", 1);
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN,
    credentials: true,
  })
);

app.use(
  rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.get("/", (req, res) => res.json({ ok: true, name: "WanderOn Auth API" }));
app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.use("/auth", noSqlSanitize());

app.use("/auth", authRoutes);

app.use(errorHandler);

module.exports = { app };
