const bcrypt = require('bcryptjs');
const User = require('../models/User');
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  hashToken,
} = require('../utils/jwt');

const ACCESS_COOKIE = 'sd_access_token';
const REFRESH_COOKIE = 'sd_refresh_token';

function cookieOptions(maxAge) {
  const isProduction = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax',
    path: '/api',
    maxAge,
  };
}

function setAccessCookie(res, token) {
  const maxAge = 15 * 60 * 1000;
  res.cookie(ACCESS_COOKIE, token, cookieOptions(maxAge));
}

function clearAccessCookie(res) {
  res.clearCookie(ACCESS_COOKIE, cookieOptions(0));
}

function setRefreshCookie(res, token) {
  const isProduction = process.env.NODE_ENV === 'production';
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax',
    path: '/api/auth',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function clearRefreshCookie(res) {
  const isProduction = process.env.NODE_ENV === 'production';
  res.clearCookie(REFRESH_COOKIE, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax',
    path: '/api/auth',
  });
}

async function signup(req, res, next) {
  try {
    const { name, email, password } = req.body;

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const user = await User.create({ name, email: email.toLowerCase(), passwordHash });

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    user.refreshTokenHash = hashToken(refreshToken);
    await user.save();
    setAccessCookie(res, accessToken);
    setRefreshCookie(res, refreshToken);

    return res.status(201).json({
      user: user.toSafeJSON(),
    });
  } catch (err) {
    return next(err);
  }
}

async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() }).select('+passwordHash');
    // Deliberately generic error message — don't reveal whether the email exists.
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const valid = await user.comparePassword(password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    user.refreshTokenHash = hashToken(refreshToken);
    await user.save();
    setAccessCookie(res, accessToken);
    setRefreshCookie(res, refreshToken);

    return res.json({
      user: user.toSafeJSON(),
    });
  } catch (err) {
    return next(err);
  }
}

async function refresh(req, res, next) {
  try {
    const refreshToken = req.cookies[REFRESH_COOKIE] || req.body?.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token is required' });
    }

    let payload;
    try {
      payload = verifyRefreshToken(refreshToken);
    } catch (err) {
      clearAccessCookie(res);
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const user = await User.findById(payload.sub).select('+refreshTokenHash');
    if (!user || user.refreshTokenHash !== hashToken(refreshToken)) {
      clearAccessCookie(res);
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Refresh token no longer valid' });
    }

    const newAccessToken = signAccessToken(user);
    const newRefreshToken = signRefreshToken(user);
    user.refreshTokenHash = hashToken(newRefreshToken);
    await user.save();
    setAccessCookie(res, newAccessToken);
    setRefreshCookie(res, newRefreshToken);

    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
}

async function logout(req, res, next) {
  try {
    const user = await User.findById(req.userId);
    if (user) {
      user.refreshTokenHash = null;
      await user.save();
    }
    clearAccessCookie(res);
    clearRefreshCookie(res);
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
}

async function me(req, res, next) {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    return res.json({ user: user.toSafeJSON() });
  } catch (err) {
    return next(err);
  }
}

module.exports = { signup, login, refresh, logout, me };