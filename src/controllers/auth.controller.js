const { registerSchema, loginSchema } = require("../validators/auth.validators");
const { deepSanitize } = require("../utils/sanitize");
const authService = require("../services/auth.service");

function cookieOptions() {
  const secure = String(process.env.COOKIE_SECURE) === "true";
  return {
    httpOnly: true,
    secure,
    sameSite: process.env.COOKIE_SAMESITE || "lax",
    path: "/",
  };
}

function setAuthCookies(res, accessToken, refreshToken) {
  res.cookie("access_token", accessToken, { ...cookieOptions(), maxAge: 15 * 60 * 1000 });
  res.cookie("refresh_token", refreshToken, { ...cookieOptions(), maxAge: 7 * 24 * 60 * 60 * 1000 });
}

async function register(req, res, next) {
  try {
    const cleanBody = deepSanitize(req.body);
    const data = registerSchema.parse(cleanBody);

    const user = await authService.register(data);

    return res.status(201).json({
      user,
      message: "Registered successfully",
    });
  } catch (err) {
    next(err);
  }
}

async function login(req, res, next) {
  try {
    const cleanBody = deepSanitize(req.body);
    const data = loginSchema.parse(cleanBody);

    const { safeUser, accessToken, refreshToken } = await authService.login(data);

    setAuthCookies(res, accessToken, refreshToken);

    return res.json({ user: safeUser, message: "Login successful" });
  } catch (err) {
    next(err);
  }
}

async function me(req, res) {
  return res.json({ user: req.user });
}

async function refresh(req, res, next) {
  try {
    const token = req.cookies?.refresh_token;
    if (!token) return res.status(401).json({ message: "Session expired" });

    const { safeUser, accessToken, refreshToken } = await authService.refresh({ refreshToken: token });

    setAuthCookies(res, accessToken, refreshToken);

    return res.json({ user: safeUser, message: "Refreshed" });
  } catch (err) {
    next(err);
  }
}

async function logout(req, res, next) {
  try {
    const userId = req.user.sub;

    await authService.logout({ userId });

    res.clearCookie("access_token", { path: "/" });
    res.clearCookie("refresh_token", { path: "/" });

    return res.json({ message: "Logged out" });
  } catch (err) {
    next(err);
  }
}

module.exports = { register, login, me, refresh, logout };
