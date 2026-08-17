const { verifyAccessToken } = require('../utils/jwt');
const User = require('../models/User');

/**
 * Requires a valid Bearer access token. Attaches req.userId on success.
 * Does not touch the database by default (cheap check) — controllers that
 * need the full user document load it themselves.
 */
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  try {
    const payload = verifyAccessToken(token);
    req.userId = payload.sub;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired access token' });
  }
}

/**
 * Loads the full user document and ensures it still exists (e.g. wasn't
 * deleted after the token was issued). Use on routes that need user data.
 */
async function loadUser(req, res, next) {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(401).json({ error: 'User no longer exists' });
    req.user = user;
    return next();
  } catch (err) {
    return next(err);
  }
}

module.exports = { requireAuth, loadUser };
