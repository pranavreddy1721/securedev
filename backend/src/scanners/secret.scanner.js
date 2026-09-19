const fs = require('fs/promises');
const path = require('path');
const secretPatterns = require('./patterns/secretPatterns');

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage']);
const TEXT_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.json', '.env', '.yml', '.yaml', '.md',
  '.txt', '.py', '.java', '.rb', '.go', '.php', '.html', '.css', '.sh',
  '.config', '.conf', '.xml', '.toml', '.ini',
]);
const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;

async function walkFiles(dir, files = []) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    // Environment files are security-relevant and must be scanned, including
    // .env.local, .env.production, etc. Other hidden files/directories remain excluded.
    const isEnvFile = entry.name === '.env' || entry.name.startsWith('.env.');
    if (entry.name.startsWith('.') && !isEnvFile) continue;
    if (SKIP_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walkFiles(fullPath, files);
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      if (TEXT_EXTENSIONS.has(ext) || isEnvFile) files.push(fullPath);
    }
  }
  return files;
}

async function runSecretScan(projectDir) {
  const findings = [];
  const files = await walkFiles(projectDir);

  for (const filePath of files) {
    let stat;
    try {
      stat = await fs.stat(filePath);
    } catch {
      continue;
    }
    if (stat.size > MAX_FILE_SIZE_BYTES) continue;

    let content;
    try {
      content = await fs.readFile(filePath, 'utf8');
    } catch {
      continue;
    }

    const relPath = path.relative(projectDir, filePath);

    for (const pattern of secretPatterns) {
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(content)) !== null) {
        findings.push({
          category: 'hardcodedSecrets',
          severity: pattern.severity,
          title: pattern.name,
          description: `Pattern "${pattern.name}" matched in ${relPath}. Redact and rotate this credential immediately.`,
          file: relPath,
          line: content.slice(0, match.index).split('\n').length,
          engine: 'secret-scanner',
          owaspRef: 'A02:2021 - Cryptographic Failures',
          heuristic: false,
        });

        if (match.index === pattern.regex.lastIndex) pattern.regex.lastIndex++;
      }
    }
  }

  return findings;
}

module.exports = { runSecretScan };
