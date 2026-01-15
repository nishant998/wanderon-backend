/**
 * @swagger
 * tags:
 *   - name: Auth
 *     description: Authentication endpoints
 */

const express = require("express");
const bcrypt = require("bcrypt");
const User = require("../models/User");
const { registerSchema, loginSchema } = require("../validators/auth.validators");
const { deepSanitize } = require("../utils/sanitize");
const { signAccessToken, signRefreshToken, verifyRefresh } = require("../utils/tokens");
const { requireAuth } = require("../middleware/auth.middleware");

const router = express.Router();
const SALT_ROUNDS = 12;

function cookieOptions() {
  const secure = String(process.env.COOKIE_SECURE) === "true";
  return {
    httpOnly: true,
    secure,
    sameSite: process.env.COOKIE_SAMESITE || "lax",
    path: "/",
  };
}
/**
 * @swagger
 * /auth/register:
 *   post:
 *     tags: [Auth]
 *     summary: Register a new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: "#/components/schemas/RegisterRequest"
 *     responses:
 *       201:
 *         description: Registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   $ref: "#/components/schemas/UserResponse"
 *                 message:
 *                   type: string
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/ValidationError"
 *       409:
 *         description: Email already registered
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/ApiError"
 */
router.post("/register", async (req, res, next) => {
  try {
    const cleanBody = deepSanitize(req.body);
    const data = registerSchema.parse(cleanBody);

    const email = data.email.toLowerCase().trim();

    const exists = await User.findOne({ email }).lean();
    if (exists) return res.status(409).json({ message: "Email already registered" });

    const passwordHash = await bcrypt.hash(data.password, SALT_ROUNDS);
    const user = await User.create({ email, username: data.username.trim(), passwordHash });

    return res.status(201).json({
      user: { id: user._id.toString(), email: user.email, username: user.username },
      message: "Registered successfully",
    });
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /auth/login:
 *   post:
 *     tags: [Auth]
 *     summary: Login user and set HttpOnly cookies (access_token, refresh_token)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: "#/components/schemas/LoginRequest"
 *     responses:
 *       200:
 *         description: Login successful (cookies set)
 *         headers:
 *           Set-Cookie:
 *             description: Sets access_token and refresh_token HttpOnly cookies
 *             schema:
 *               type: string
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   $ref: "#/components/schemas/UserResponse"
 *                 message:
 *                   type: string
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/ValidationError"
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/ApiError"
 */
router.post("/login", async (req, res, next) => {
  try {
    const cleanBody = deepSanitize(req.body);
    const data = loginSchema.parse(cleanBody);

    const email = data.email.toLowerCase().trim();

    const user = await User.findOne({ email }).select("+passwordHash +refreshTokenHash");
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(data.password, user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const safeUser = { id: user._id.toString(), email: user.email, username: user.username };

    const accessToken = signAccessToken(safeUser);
    const refreshToken = signRefreshToken({ id: safeUser.id, email: safeUser.email });

    user.refreshTokenHash = await bcrypt.hash(refreshToken, SALT_ROUNDS);
    await user.save();

    res.cookie("access_token", accessToken, { ...cookieOptions(), maxAge: 15 * 60 * 1000 });
    res.cookie("refresh_token", refreshToken, { ...cookieOptions(), maxAge: 7 * 24 * 60 * 60 * 1000 });

    return res.json({ user: safeUser, message: "Login successful" });
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /auth/me:
 *   get:
 *     tags: [Auth]
 *     summary: Get current logged-in user (protected)
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User payload from access token cookie
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   type: object
 *                   properties:
 *                     sub:
 *                       type: string
 *                       example: "65b123abc123abc123abc123"
 *                     email:
 *                       type: string
 *                       example: "user@example.com"
 *                     username:
 *                       type: string
 *                       example: "nishant"
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/ApiError"
 */
router.get("/me", requireAuth, async (req, res) => {
    console.log("Fetching current user:", req.user);
  return res.json({ user: req.user });
});

/**
 * @swagger
 * /auth/refresh:
 *   post:
 *     tags: [Auth]
 *     summary: Refresh tokens using refresh_token cookie (rotates refresh token)
 *     responses:
 *       200:
 *         description: Tokens refreshed (cookies set)
 *         headers:
 *           Set-Cookie:
 *             description: Sets new access_token and refresh_token HttpOnly cookies
 *             schema:
 *               type: string
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   $ref: "#/components/schemas/UserResponse"
 *                 message:
 *                   type: string
 *       401:
 *         description: Session expired
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/ApiError"
 */
router.post("/refresh", async (req, res, next) => {
  try {
    const token = req.cookies?.refresh_token;
    if (!token) return res.status(401).json({ message: "Session expired" });

    let payload;
    try {
      payload = verifyRefresh(token);
    } catch {
      return res.status(401).json({ message: "Session expired" });
    }

    const userId = payload.sub;

    const user = await User.findById(userId).select("+refreshTokenHash");
    if (!user || !user.refreshTokenHash) return res.status(401).json({ message: "Session expired" });

    const ok = await bcrypt.compare(token, user.refreshTokenHash);
    if (!ok) return res.status(401).json({ message: "Session expired" });

    const safeUser = { id: user._id.toString(), email: user.email, username: user.username };

    const newAccess = signAccessToken(safeUser);
    const newRefresh = signRefreshToken({ id: safeUser.id, email: safeUser.email });

    user.refreshTokenHash = await bcrypt.hash(newRefresh, SALT_ROUNDS);
    await user.save();

    res.cookie("access_token", newAccess, { ...cookieOptions(), maxAge: 15 * 60 * 1000 });
    res.cookie("refresh_token", newRefresh, { ...cookieOptions(), maxAge: 7 * 24 * 60 * 60 * 1000 });

    return res.json({ user: safeUser, message: "Refreshed" });
  } catch (err) {
    next(err);
  }
});

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     tags: [Auth]
 *     summary: Logout user (clears cookies and invalidates refresh token)
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Logged out
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *       401:
 *         description: Unauthorized
 *         content:
 *           application/json:
 *             schema:
 *               $ref: "#/components/schemas/ApiError"
 */
router.post("/logout", requireAuth, async (req, res, next) => {
  try {
    const userId = req.user.sub;
    await User.findByIdAndUpdate(userId, { refreshTokenHash: null });

    res.clearCookie("access_token", { path: "/" });
    res.clearCookie("refresh_token", { path: "/" });

    return res.json({ message: "Logged out" });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
