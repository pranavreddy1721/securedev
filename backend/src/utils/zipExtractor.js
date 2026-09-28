const path = require('path');
const AdmZip = require('adm-zip');

// Uploads are already capped in Multer, but a small compressed archive can
// expand to a huge amount of data (zip bomb). Keep extraction bounded even
// when the archive is syntactically valid.
const MAX_ENTRIES = 5000;
const MAX_ENTRY_UNCOMPRESSED_BYTES = 25 * 1024 * 1024;
const MAX_TOTAL_UNCOMPRESSED_BYTES = 250 * 1024 * 1024;

/**
 * Extracts an uploaded zip into destDir, guarding against zip-slip and
 * resource-exhaustion attacks. SecureDev scans untrusted repositories, so
 * extraction must never be able to escape the destination or expand without
 * a practical upper bound.
 */
function safeExtract(zipFilePath, destDir) {
  const zip = new AdmZip(zipFilePath);
  const entries = zip.getEntries();

  if (entries.length > MAX_ENTRIES) {
    throw new Error(`Rejected archive: too many entries (maximum ${MAX_ENTRIES})`);
  }

  const resolvedDest = path.resolve(destDir);
  let totalUncompressedBytes = 0;

  for (const entry of entries) {
    const resolvedPath = path.resolve(resolvedDest, entry.entryName);
    if (!resolvedPath.startsWith(resolvedDest + path.sep) && resolvedPath !== resolvedDest) {
      throw new Error(`Rejected unsafe zip entry (path traversal attempt): ${entry.entryName}`);
    }

    // Directories have no meaningful payload size. For files, AdmZip exposes
    // the uncompressed size in header.size, which is sufficient to reject
    // oversized members before extraction starts.
    if (!entry.isDirectory) {
      const entrySize = Number(entry.header?.size || 0);
      if (!Number.isSafeInteger(entrySize) || entrySize < 0) {
        throw new Error(`Rejected archive: invalid entry size for ${entry.entryName}`);
      }
      if (entrySize > MAX_ENTRY_UNCOMPRESSED_BYTES) {
        throw new Error(
          `Rejected archive: entry ${entry.entryName} exceeds the ${MAX_ENTRY_UNCOMPRESSED_BYTES / (1024 * 1024)} MB per-file limit`
        );
      }
      totalUncompressedBytes += entrySize;
      if (totalUncompressedBytes > MAX_TOTAL_UNCOMPRESSED_BYTES) {
        throw new Error(
          `Rejected archive: total uncompressed size exceeds the ${MAX_TOTAL_UNCOMPRESSED_BYTES / (1024 * 1024)} MB limit`
        );
      }
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

module.exports = {
  safeExtract,
  MAX_ENTRIES,
  MAX_ENTRY_UNCOMPRESSED_BYTES,
  MAX_TOTAL_UNCOMPRESSED_BYTES,
};
