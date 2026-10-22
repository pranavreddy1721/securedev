const { verifyAccessToken } = require('../utils/jwt');
const User = require('../models/User');

const ACCESS_COOKIE = 'sd_access_token';

/**
 * Requires a valid access token. The preferred transport is an HttpOnly
 * cookie; the Authorization header remains supported for compatibility with
 * older clients during rollout.
 */
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, headerToken] = header.split(' ');
  const token = req.cookies?.[ACCESS_COOKIE] || (scheme === 'Bearer' ? headerToken : null);

  if (!token) {
    return res.status(401).json({ error: 'Missing or malformed access token' });
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
