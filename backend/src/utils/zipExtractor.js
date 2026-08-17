const path = require('path');
const AdmZip = require('adm-zip');

/**
 * Extracts an uploaded zip into destDir, guarding against zip-slip
 * (entries whose path escapes destDir via "../"). This is the same class
 * of bug SecureDev itself flags under Insecure File Uploads, so it needs
 * to be airtight here.
 */
function safeExtract(zipFilePath, destDir) {
  const zip = new AdmZip(zipFilePath);
  const entries = zip.getEntries();

  for (const entry of entries) {
    const resolvedPath = path.resolve(destDir, entry.entryName);
    if (!resolvedPath.startsWith(path.resolve(destDir) + path.sep) && resolvedPath !== path.resolve(destDir)) {
      throw new Error(`Rejected unsafe zip entry (path traversal attempt): ${entry.entryName}`);
    }
  }

  // Skip common noise directories the UI already tells users to exclude,
  // and skip them defensively even if they're present anyway.
  const SKIP_DIRS = ['node_modules/', '.git/'];
  for (const entry of entries) {
    if (SKIP_DIRS.some((skip) => entry.entryName.includes(skip))) continue;
    zip.extractEntryTo(entry, destDir, true, true);
  }

  return destDir;
}

module.exports = { safeExtract };
