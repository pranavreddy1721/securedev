const fs = require('fs/promises');
const path = require('path');
const simpleGit = require('simple-git');

/**
 * Shallow-clones a GitHub repo with an ephemeral HTTP Authorization header.
 * The token is not embedded in the remote URL, and the .git directory is
 * removed immediately after cloning because SecureDev only needs source files.
 */
async function cloneRepo({ cloneUrl, accessToken, branch, destDir }) {
  if (!/^https:\/\/github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+(?:\.git)?$/.test(cloneUrl)) {
    throw new Error('Only GitHub HTTPS repository URLs are allowed');
  }
  if (!accessToken) throw new Error('GitHub access token is required');
  if (branch && (!/^[A-Za-z0-9._/-]{1,200}$/.test(branch) || branch.includes('..'))) {
    throw new Error('Invalid GitHub branch');
  }

  const git = simpleGit();
  const authHeader = `Authorization: Bearer ${accessToken}`;
  const cloneArgs = [
    '-c',
    `http.extraheader=${authHeader}`,
    '--depth',
    '1',
    ...(branch ? ['--branch', branch] : []),
  ];

  await git.clone(cloneUrl, destDir, cloneArgs);

  // Git metadata is not needed for scanning and may contain repository
  // remotes/configuration. Remove it before any scanner sees the source.
  await fs.rm(path.join(destDir, '.git'), { recursive: true, force: true });
  return destDir;
}

module.exports = { cloneRepo };
