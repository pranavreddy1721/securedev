const axios = require('axios');
const crypto = require('crypto');
const User = require('../models/User');
const { encrypt, decrypt } = require('../utils/crypto');

// In-memory state store for CSRF protection on the OAuth flow.
// SecureDev v1 is deployed as a single backend instance. If the service is
// scaled horizontally, move this state store to Redis/MongoDB.
const pendingStates = new Map(); // state -> { userId, expiresAt }

const STATE_TTL_MS = 10 * 60 * 1000;
const GITHUB_API_VERSION = '2022-11-28';

function githubHeaders(accessToken) {
  return {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
    Authorization: `Bearer ${accessToken}`,
  };
}

function getRequiredOAuthConfig() {
  const required = ['GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'GITHUB_CALLBACK_URL', 'GITHUB_TOKEN_ENC_KEY', 'CLIENT_ORIGIN'];
  const missing = required.filter((key) => !process.env[key]);
  return missing;
}

function getClientOrigin() {
  return (process.env.CLIENT_ORIGIN || '').split(',')[0].trim().replace(/\/+$/, '');
}

// Remove expired states opportunistically so a long-running process does not
// retain abandoned OAuth attempts forever.
function pruneExpiredStates() {
  const now = Date.now();
  for (const [state, pending] of pendingStates) {
    if (pending.expiresAt <= now) pendingStates.delete(state);
  }
}

/**
 * Step 1: Redirects the already-authenticated user to GitHub's OAuth consent screen.
 * Scope is intentionally limited to public_repo.
 */
function connectStart(req, res) {
  pruneExpiredStates();
  const missing = getRequiredOAuthConfig();
  if (missing.length) {
    return res.status(503).json({
      error: 'GitHub connection is not configured on the server',
      missing,
    });
  }

  const state = crypto.randomBytes(24).toString('hex');
  pendingStates.set(state, { userId: req.userId, expiresAt: Date.now() + STATE_TTL_MS });

  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: process.env.GITHUB_CALLBACK_URL,
    scope: 'public_repo',
    state,
    allow_signup: 'false',
  });

  return res.json({ redirectUrl: `https://github.com/login/oauth/authorize?${params.toString()}` });
}

/**
 * Step 2: GitHub redirects here with a code + our state param.
 * The state maps the OAuth callback back to the authenticated SecureDev user.
 */
async function connectCallback(req, res, next) {
  try {
    const { code, state, error: oauthError } = req.query;
    const missing = getRequiredOAuthConfig();
    if (missing.length) return res.status(503).send('GitHub connection is not configured on the server.');
    if (oauthError) return res.redirect(`${getClientOrigin()}/dashboard?github=error`);
    if (!code || !state) return res.status(400).send('Missing GitHub OAuth code or state.');

    const pending = pendingStates.get(state);
    if (!pending || pending.expiresAt < Date.now()) {
      pendingStates.delete(state);
      return res.status(400).send('OAuth state invalid or expired. Please try connecting again.');
    }
    pendingStates.delete(state);

    const tokenResp = await axios.post(
      'https://github.com/login/oauth/access_token',
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: process.env.GITHUB_CALLBACK_URL,
      },
      { headers: { Accept: 'application/json' }, timeout: 15000 }
    );

    const { access_token: accessToken, scope } = tokenResp.data;
    if (!accessToken) return res.status(400).send('GitHub did not return an access token.');

    // Defensive check: refuse to store a token with the broad repo scope.
    if (scope && scope.split(',').some((s) => s.trim() === 'repo')) {
      return res.status(400).send('Received broader OAuth scope than requested (public_repo). Connection rejected.');
    }

    const ghUser = await axios.get('https://api.github.com/user', {
      headers: githubHeaders(accessToken),
      timeout: 15000,
    });

    const user = await User.findById(pending.userId);
    if (!user) return res.status(404).send('User not found.');

    user.github = {
      id: String(ghUser.data.id),
      username: ghUser.data.login,
      accessTokenEncrypted: encrypt(accessToken),
      scope: scope || 'public_repo',
      connectedAt: new Date(),
    };
    await user.save();

    return res.redirect(`${getClientOrigin()}/dashboard?github=connected`);
  } catch (err) {
    return next(err);
  }
}

async function status(req, res, next) {
  try {
    const user = await User.findById(req.userId).select('+github.accessTokenEncrypted');
    if (!user) return res.status(404).json({ error: 'User not found' });

    return res.json({
      connected: Boolean(user.github?.accessTokenEncrypted),
      username: user.github?.username || null,
      connectedAt: user.github?.connectedAt || null,
      scope: user.github?.scope || null,
    });
  } catch (err) {
    return next(err);
  }
}

async function disconnect(req, res, next) {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.github = { id: null, username: null, accessTokenEncrypted: null, scope: null, connectedAt: null };
    await user.save();
    return res.status(204).send();
  } catch (err) {
    return next(err);
  }
}

/**
 * Lists the connected user's public repos (paginated) so they can pick one to scan.
 */
async function listRepos(req, res, next) {
  try {
    const user = await User.findById(req.userId).select('+github.accessTokenEncrypted');
    if (!user?.github?.accessTokenEncrypted) {
      return res.status(400).json({ error: 'GitHub is not connected for this account' });
    }

    const accessToken = decrypt(user.github.accessTokenEncrypted);
    const requestedPage = Number.parseInt(req.query.page || '1', 10);
    const page = Number.isInteger(requestedPage) && requestedPage > 0 ? Math.min(requestedPage, 100) : 1;

    const resp = await axios.get('https://api.github.com/user/repos', {
      headers: githubHeaders(accessToken),
      params: { visibility: 'public', per_page: 30, page, sort: 'updated' },
      timeout: 15000,
    });

    const repos = resp.data.map((r) => ({
      fullName: r.full_name,
      url: r.html_url,
      cloneUrl: r.clone_url,
      defaultBranch: r.default_branch,
      private: r.private,
      updatedAt: r.updated_at,
      language: r.language,
    }));

    return res.json({ repos, page, hasNextPage: repos.length === 30 });
  } catch (err) {
    return next(err);
  }
}

module.exports = { connectStart, connectCallback, status, disconnect, listRepos };
