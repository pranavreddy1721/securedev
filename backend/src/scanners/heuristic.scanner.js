const fs = require('fs/promises');
const path = require('path');

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build']);

async function walkJsFiles(dir, files = []) {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return files;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walkJsFiles(fullPath, files);
    } else if (/\.(js|jsx|ts|tsx)$/.test(entry.name)) {
      files.push(fullPath);
    }
  }
  return files;
}

function lineOf(content, index) {
  return content.slice(0, index).split('\n').length;
}

/**
 * Explicitly heuristic, pattern-based checks for:
 *  - Insecure File Uploads (path traversal / unrestricted multer config)
 *  - Broken Access Control (routes missing auth middleware)
 *  - Sensitive Data Exposure (logging of sensitive fields, kept DISTINCT
 *    from Secrets Detection — this is about runtime data, not embedded keys)
 * Plus static config checks feeding Broken Authentication and
 * Security Misconfiguration sub-scores.
 *
 * These are NOT exhaustive static/dataflow analysis — they're regex/AST-lite
 * pattern matches. Findings from this engine are marked heuristic: true and
 * the UI/report must surface that distinction, not present them as
 * equivalent-confidence to Semgrep/npm-audit findings.
 */
async function runHeuristicScan(projectDir) {
  const findings = [];
  const files = await walkJsFiles(projectDir);

  for (const filePath of files) {
    let content;
    try {
      content = await fs.readFile(filePath, 'utf8');
    } catch {
      continue;
    }
    const relPath = path.relative(projectDir, filePath);

    // --- Insecure File Uploads ---
    if (/multer\s*\(\s*\)/.test(content) || /multer\.diskStorage\(/.test(content)) {
      if (!/fileFilter\s*:/.test(content)) {
        findings.push(makeFinding('insecureFileUploads', 'medium',
          'Multer configured without a fileFilter',
          'File uploads should restrict accepted MIME types/extensions to prevent malicious file execution.',
          relPath, lineOf(content, content.indexOf('multer')), 'A04:2021 - Insecure Design'));
      }
      if (!/limits\s*:/.test(content)) {
        findings.push(makeFinding('insecureFileUploads', 'low',
          'Multer configured without upload size limits',
          'Missing limits.fileSize allows unbounded uploads (DoS risk).',
          relPath, lineOf(content, content.indexOf('multer')), 'A04:2021 - Insecure Design'));
      }
    }
    if (/path\.join\([^)]*req\.(body|params|query)/.test(content)) {
      findings.push(makeFinding('insecureFileUploads', 'high',
        'Possible path traversal via user-controlled path segment',
        'User input flows into path.join() for a filesystem path — validate/sanitize against traversal (../).',
        relPath, lineOf(content, content.search(/path\.join\([^)]*req\.(body|params|query)/)), 'A01:2021 - Broken Access Control'));
    }

    // --- Broken Access Control (heuristic: route defined without nearby auth middleware) ---
    const routeMatches = [...content.matchAll(/router\.(get|post|put|patch|delete)\(\s*['"`][^'"`]+['"`]\s*,/g)];
    for (const m of routeMatches) {
      const windowStart = Math.max(0, m.index - 20);
      const windowEnd = Math.min(content.length, m.index + 200);
      const nearby = content.slice(windowStart, windowEnd);
      const looksProtected = /requireAuth|authMiddleware|isAuthenticated|verifyToken|passport\.authenticate/.test(nearby);
      const looksSensitive = /\/(admin|users?|account|profile|settings|delete|update)/i.test(nearby);
      if (looksSensitive && !looksProtected) {
        findings.push(makeFinding('brokenAccessControl', 'medium',
          'Route may be missing an authorization check',
          'A route matching a sensitive path pattern was found with no recognizable auth middleware nearby. Verify manually — this is a heuristic, not a guarantee.',
          relPath, lineOf(content, m.index), 'A01:2021 - Broken Access Control'));
      }
    }

    // --- Sensitive Data Exposure (distinct from hardcoded secrets: this is about
    // logging/handling of sensitive runtime values, not embedded credentials) ---
    if (/console\.(log|info|debug)\([^)]*\b(password|token|secret|ssn|creditCard|card_number)\b/i.test(content)) {
      findings.push(makeFinding('sensitiveDataExposure', 'high',
        'Sensitive field logged to console',
        'A variable named like a sensitive field (password/token/etc.) is passed to console.log. Sensitive data should never be logged in plaintext.',
        relPath, lineOf(content, content.search(/console\.(log|info|debug)\([^)]*\b(password|token|secret|ssn|creditCard|card_number)\b/i)),
        'A02:2021 - Cryptographic Failures'));
    }
    if (/schema\s*=\s*new\s+mongoose\.Schema\(\{[^}]*password[^}]*type\s*:\s*String/is.test(content) &&
        !/select\s*:\s*false/i.test(content)) {
      findings.push(makeFinding('sensitiveDataExposure', 'medium',
        'Password field may not be excluded from query results',
        'A Mongoose schema has a String field named password without select:false — it may be returned in API responses by default.',
        relPath, null, 'A02:2021 - Cryptographic Failures'));
    }

    // --- Broken Authentication (static config checks) ---
    if (/bcrypt\.(hash|genSalt)\([^)]*,\s*([1-9]|10)\s*[,)]/.test(content)) {
      findings.push(makeFinding('brokenAuthentication', 'medium',
        'bcrypt salt rounds below recommended minimum',
        'Salt rounds under 11 are weaker than current best practice (10+ is often cited, 12 is a safer default for 2025+ hardware).',
        relPath, lineOf(content, content.search(/bcrypt\.(hash|genSalt)/)), 'A07:2021 - Identification and Authentication Failures'));
    }
    if (/jwt\.sign\(\s*[^,]+,\s*[^,]+\)/.test(content) && !/expiresIn/.test(content)) {
      findings.push(makeFinding('brokenAuthentication', 'high',
        'JWT signed without an expiry',
        'jwt.sign() called without an expiresIn option produces a token that never expires.',
        relPath, lineOf(content, content.search(/jwt\.sign\(/)), 'A07:2021 - Identification and Authentication Failures'));
    }

    // --- Security Misconfiguration ---
    if (/cors\(\s*\)/.test(content) || /origin\s*:\s*['"`]\*['"`]/.test(content)) {
      findings.push(makeFinding('securityMisconfiguration', 'medium',
        'Permissive CORS configuration',
        'CORS is enabled with no origin restriction (or wildcard "*"), allowing any site to make credentialed requests.',
        relPath, lineOf(content, content.search(/cors\(|origin\s*:\s*['"`]\*['"`]/)), 'A05:2021 - Security Misconfiguration'));
    }
  }

  // Project-wide check: is Helmet used anywhere at all?
  const anyHelmet = files.length > 0 && (await Promise.all(files.map(async (f) => {
    try {
      const c = await fs.readFile(f, 'utf8');
      return /require\(['"]helmet['"]\)|from ['"]helmet['"]/.test(c);
    } catch { return false; }
  }))).some(Boolean);

  if (!anyHelmet) {
    findings.push(makeFinding('securityMisconfiguration', 'medium',
      'Helmet.js not detected',
      'No usage of the helmet package was found. Helmet sets a range of protective HTTP headers by default.',
      null, null, 'A05:2021 - Security Misconfiguration'));
  }

  return findings;
}

function makeFinding(category, severity, title, description, file, line, owaspRef) {
  return {
    category,
    severity,
    title,
    description,
    file: file || null,
    line: line || null,
    engine: 'heuristic',
    owaspRef: owaspRef || null,
    heuristic: true,
  };
}

module.exports = { runHeuristicScan };
