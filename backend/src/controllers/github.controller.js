const axios = require('axios');
const crypto = require('crypto');
const User = require('../models/User');
const { encrypt, decrypt } = require('../utils/crypto');

// In-memory state store for CSRF protection on the OAuth flow.
// Fine for a single-instance deploy; move to Redis/Mongo if scaling out.
const pendingStates = new Map(); // state -> { userId, expiresAt }

const STATE_TTL_MS = 10 * 60 * 1000;

/**
 * Step 1: Redirects the (already-logged-in) user to GitHub's OAuth consent screen.
 * Scope is public_repo ONLY — per the confirmed decision, do not widen this
 * without an explicit product decision, since it's part of the security story.
 */
function connectStart(req, res) {
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
 * Exchanges the code for an access token, encrypts it, stores it on the user.
 */
async function connectCallback(req, res, next) {
  try {
    const { code, state } = req.query;

    const pending = pendingStates.get(state);
    if (!pending || pending.expiresAt < Date.now()) {
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
      { headers: { Accept: 'application/json' } }
    );

    const { access_token: accessToken, scope } = tokenResp.data;
    if (!accessToken) {
      return res.status(400).send('GitHub did not return an access token.');
    }

    // Defensive check: refuse to store a token with a broader scope than requested.
    if (scope && scope.split(',').some((s) => s.trim() === 'repo')) {
      return res
        .status(400)
        .send('Received broader OAuth scope than requested (public_repo). Connection rejected.');
    }

    const ghUser = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `token ${accessToken}` },
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

    const redirectTarget = `${process.env.CLIENT_ORIGIN}/dashboard?github=connected`;
    return res.redirect(redirectTarget);
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
    const page = parseInt(req.query.page || '1', 10);

    const resp = await axios.get('https://api.github.com/user/repos', {
      headers: { Authorization: `token ${accessToken}` },
      params: { visibility: 'public', per_page: 30, page, sort: 'updated' },
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

    return res.json({ repos, page });
  } catch (err) {
    return next(err);
  }
}

module.exports = { connectStart, connectCallback, disconnect, listRepos };
