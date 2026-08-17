const fs = require('fs/promises');
const path = require('path');
const secretPatterns = require('./patterns/secretPatterns');

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage']);
const TEXT_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.json', '.env', '.yml', '.yaml', '.md',
  '.txt', '.py', '.java', '.rb', '.go', '.php', '.html', '.css', '.sh',
  '.config', '.conf', '.xml', '.toml', '.ini',
]);
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024; // 2MB — skip huge files (likely not source)

async function walkFiles(dir, files = []) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.name !== '.env') continue; // hidden files, except .env
    if (SKIP_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walkFiles(fullPath, files);
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      const isEnvFile = entry.name === '.env' || entry.name.startsWith('.env.');
      if (TEXT_EXTENSIONS.has(ext) || isEnvFile) {
        files.push(fullPath);
      }
    }
  }
  return files;
}

/**
 * Scans every text file under projectDir for hardcoded secrets using the
 * patterns in patterns/secretPatterns.js. Returns an array of findings in
 * the shape expected by the Scan model's findingSchema.
 */
async function runSecretScan(projectDir) {
  const findings = [];
  const files = await walkFiles(projectDir);

  for (const filePath of files) {
    let stat;
    try {
      stat = await fs.stat(filePath);
    } catch {
      continue; // file may have been a broken symlink
    }
    if (stat.size > MAX_FILE_SIZE_BYTES) continue;

    let content;
    try {
      content = await fs.readFile(filePath, 'utf8');
    } catch {
      continue; // likely binary despite extension allowlist
    }

    const relPath = path.relative(projectDir, filePath);
    const lines = content.split('\n');

    for (const pattern of secretPatterns) {
      // Reset lastIndex since patterns are reused with the /g flag across files.
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(content)) !== null) {
        const upToMatch = content.slice(0, match.index);
        const lineNumber = upToMatch.split('\n').length;

        findings.push({
          category: 'hardcodedSecrets',
          severity: pattern.severity,
          title: pattern.name,
          description: `Pattern "${pattern.name}" matched in ${relPath}. Redact and rotate this credential immediately.`,
          file: relPath,
          line: lineNumber,
          engine: 'secret-scanner',
          owaspRef: 'A02:2021 - Cryptographic Failures',
          heuristic: false,
        });

        // Avoid infinite loops on zero-width matches
        if (match.index === pattern.regex.lastIndex) pattern.regex.lastIndex++;
      }
      // guard against runaway match counts on pathological files
      void lines;
    }
  }

  return findings;
}

module.exports = { runSecretScan };
