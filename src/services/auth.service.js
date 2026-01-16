const bcrypt = require("bcrypt");
const User = require("../models/User");
const {
  signAccessToken,
  signRefreshToken,
  verifyRefresh,
} = require("../utils/tokens");

const SALT_ROUNDS = 12;

async function register({ email, username, password }) {
  const normalizedEmail = email.toLowerCase().trim();

  const exists = await User.findOne({ email: normalizedEmail }).lean();
  if (exists) {
    const err = new Error("Email already registered");
    err.statusCode = 409;
    throw err;
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  const user = await User.create({
    email: normalizedEmail,
    username: username.trim(),
    passwordHash,
  });

  return {
    id: user._id.toString(),
    email: user.email,
    username: user.username,
  };
}

async function login({ email, password }) {
  const normalizedEmail = email.toLowerCase().trim();

  const user = await User.findOne({ email: normalizedEmail }).select(
    "+passwordHash +refreshTokenHash"
  );

  if (!user) {
    const err = new Error("Invalid credentials");
    err.statusCode = 401;
    throw err;
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    const err = new Error("Invalid credentials");
    err.statusCode = 401;
    throw err;
  }

  const safeUser = {
    id: user._id.toString(),
    email: user.email,
    username: user.username,
  };

  const accessToken = signAccessToken(safeUser);
  const refreshToken = signRefreshToken({ id: safeUser.id, email: safeUser.email });

  user.refreshTokenHash = await bcrypt.hash(refreshToken, SALT_ROUNDS);
  await user.save();

  return { safeUser, accessToken, refreshToken };
}

async function refresh({ refreshToken }) {
  let payload;
  try {
    payload = verifyRefresh(refreshToken);
  } catch {
    const err = new Error("Session expired");
    err.statusCode = 401;
    throw err;
  }

  const userId = payload.sub;

  const user = await User.findById(userId).select("+refreshTokenHash");
  if (!user || !user.refreshTokenHash) {
    const err = new Error("Session expired");
    err.statusCode = 401;
    throw err;
  }

  const ok = await bcrypt.compare(refreshToken, user.refreshTokenHash);
  if (!ok) {
    const err = new Error("Session expired");
    err.statusCode = 401;
    throw err;
  }

  const safeUser = {
    id: user._id.toString(),
    email: user.email,
    username: user.username,
  };

  const newAccessToken = signAccessToken(safeUser);
  const newRefreshToken = signRefreshToken({ id: safeUser.id, email: safeUser.email });

  user.refreshTokenHash = await bcrypt.hash(newRefreshToken, SALT_ROUNDS);
  await user.save();

  return { safeUser, accessToken: newAccessToken, refreshToken: newRefreshToken };
}

async function logout({ userId }) {
  await User.findByIdAndUpdate(userId, { refreshTokenHash: null });
}

module.exports = { register, login, refresh, logout };
