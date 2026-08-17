const os = require('os');
const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');

/**
 * Creates a fresh, uniquely-named directory under the OS temp dir for a
 * single scan's working files (extracted zip or cloned repo).
 * Per the confirmed decision: no S3/cloud storage in v1 — everything here
 * is deleted after the scan completes (or fails), see cleanupTempDir().
 */
async function createTempDir(prefix = 'securedev-scan-') {
  const dirName = `${prefix}${crypto.randomBytes(8).toString('hex')}`;
  const fullPath = path.join(os.tmpdir(), dirName);
  await fs.mkdir(fullPath, { recursive: true });
  return fullPath;
}

async function cleanupTempDir(dirPath) {
  if (!dirPath || !dirPath.startsWith(os.tmpdir())) {
    // Guard rail: never rm -rf something outside the OS temp dir.
    throw new Error(`Refusing to clean up path outside temp dir: ${dirPath}`);
  }
  await fs.rm(dirPath, { recursive: true, force: true });
}

module.exports = { createTempDir, cleanupTempDir };
