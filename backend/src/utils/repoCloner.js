const simpleGit = require('simple-git');

/**
 * Shallow-clones a repo (depth 1) into destDir using the user's GitHub token
 * for auth. Depth 1 keeps this fast and avoids pulling full history into the
 * ephemeral temp dir unnecessarily.
 */
async function cloneRepo({ cloneUrl, accessToken, branch, destDir }) {
  const authedUrl = cloneUrl.replace('https://', `https://x-access-token:${accessToken}@`);
  const git = simpleGit();
  await git.clone(authedUrl, destDir, ['--depth', '1', ...(branch ? ['--branch', branch] : [])]);
  return destDir;
}

module.exports = { cloneRepo };
