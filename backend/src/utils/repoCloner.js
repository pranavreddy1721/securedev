const fs = require('fs/promises');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

/**
 * Shallow-clones a GitHub repo using the OAuth token through Git's
 * environment-based configuration. The token is never embedded in the
 * repository URL or command-line arguments, and the .git directory is
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

  // GitHub OAuth tokens authenticate Git-over-HTTPS as the HTTP username.
  // Keep the credential out of argv and supply it only through Git's
  // environment-based config so it cannot appear in process listings.
  const basicAuth = Buffer.from(`${accessToken}:x-oauth-basic`, 'utf8').toString('base64');
  const gitEnv = {
    ...process.env,
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'http.extraheader',
    GIT_CONFIG_VALUE_0: `Authorization: Basic ${basicAuth}`,
  };

  const cloneArgs = [
    'clone',
    '--depth',
    '1',
    ...(branch ? ['--branch', branch, '--single-branch'] : []),
    cloneUrl,
    destDir,
  ];

  try {
    await execFileAsync('git', cloneArgs, {
      env: gitEnv,
      maxBuffer: 1024 * 1024,
    });
  } catch (err) {
    // Do not expose credentials in API responses/logs. Git's stderr is useful
    // for diagnosis and does not contain the Authorization header.
    const detail = String(err.stderr || err.message || 'Git clone failed')
      .replace(/gho_[A-Za-z0-9_]+/g, '***')
      .replace(/ghu_[A-Za-z0-9_]+/g, '***');
    throw new Error(`GitHub repository clone failed: ${detail.trim()}`);
  }

  // Git metadata is not needed for scanning and may contain repository
  // remotes/configuration. Remove it before any scanner sees the source.
  await fs.rm(path.join(destDir, '.git'), { recursive: true, force: true });
  return destDir;
}

module.exports = { cloneRepo };
