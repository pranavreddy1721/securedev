const fs = require('fs/promises');
const path = require('path');

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build']);
const AUTH_MIDDLEWARE = /\b(?:requireAuth|authMiddleware|isAuthenticated|verifyToken|authenticate|passport\.authenticate|protect|requireLogin|ensureAuthenticated)\b/;
const AUTHZ_MIDDLEWARE = /\b(?:authorize|requireRole|requirePermission|checkRole|checkPermission|isAdmin|adminOnly|rbac|acl|canAccess)\b/i;
const SENSITIVE_ROUTE = /\/(?:admin|users?|accounts?|profiles?|settings|payments?|orders?|delete|update|manage|private|dashboard)(?:\/|$)/i;

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
  return content.slice(0, Math.max(0, index)).split('\n').length;
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

/**
 * Pattern-based security checks. This is intentionally heuristic rather than
 * full AST/data-flow analysis; findings must be presented as such.
 */
async function runHeuristicScan(projectDir) {
  const findings = [];
  const files = await walkJsFiles(projectDir);

  for (const filePath of files) {
    let content;
    try { content = await fs.readFile(filePath, 'utf8'); } catch { continue; }
    const relPath = path.relative(projectDir, filePath);

    // Insecure file uploads
    const multerIndex = content.search(/multer\s*\(|multer\.diskStorage\(/);
    if (multerIndex >= 0) {
      if (!/fileFilter\s*:/.test(content)) {
        findings.push(makeFinding('insecureFileUploads', 'medium',
          'Multer configured without a fileFilter',
          'File uploads should restrict accepted MIME types/extensions to reduce malicious-file risk.',
          relPath, lineOf(content, multerIndex), 'A04:2021 - Insecure Design'));
      }
      if (!/limits\s*:/.test(content)) {
        findings.push(makeFinding('insecureFileUploads', 'low',
          'Multer configured without upload size limits',
          'Missing limits.fileSize allows unbounded uploads and can increase denial-of-service risk.',
          relPath, lineOf(content, multerIndex), 'A04:2021 - Insecure Design'));
      }
    }

    const traversal = /path\.join\([^)]*req\.(body|params|query)/.exec(content);
    if (traversal) {
      findings.push(makeFinding('insecureFileUploads', 'high',
        'Possible path traversal via user-controlled path segment',
        'User input appears to flow into path.join() for a filesystem path. Validate and constrain the resolved path before filesystem access.',
        relPath, lineOf(content, traversal.index), 'A01:2021 - Broken Access Control'));
    }

    // Authentication / authorization checks. Parse the route middleware list
    // itself instead of looking at an arbitrary nearby text window. This
    // greatly reduces false positives from unrelated auth code nearby.
    const routeRegex = /(?:router|app)\.(get|post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]\s*,([^\n;]*)(?:\);|\n)/g;
    for (const match of content.matchAll(routeRegex)) {
      const route = match[2];
      const middlewareAndHandler = match[3] || '';
      const routeText = `${route} ${middlewareAndHandler}`;
      const sensitive = SENSITIVE_ROUTE.test(route);
      const hasAuth = AUTH_MIDDLEWARE.test(middlewareAndHandler);
      const hasAuthz = AUTHZ_MIDDLEWARE.test(middlewareAndHandler);
      const index = match.index || 0;

      if (sensitive && !hasAuth) {
        findings.push(makeFinding('brokenAuthentication', 'medium',
          'Sensitive route may be missing authentication middleware',
          `Route ${route} matches a sensitive-path pattern but no recognizable authentication middleware is present in its middleware list. Verify manually; this is heuristic.`,
          relPath, lineOf(content, index), 'A07:2021 - Identification and Authentication Failures'));
      }

      // Only flag likely administrative/management routes. Ordinary user
      // routes often need authentication but not necessarily role checks.
      if (/\/(?:admin|manage|management)(?:\/|$)/i.test(route) && hasAuth && !hasAuthz) {
        findings.push(makeFinding('brokenAccessControl', 'high',
          'Administrative route may lack an authorization/role check',
          `Route ${route} has recognizable authentication but no recognizable authorization middleware. Authentication alone does not establish that the caller has the required role.`,
          relPath, lineOf(content, index), 'A01:2021 - Broken Access Control'));
      }

      // Avoid an unused variable warning while keeping routeText useful for
      // future parser expansion.
      void routeText;
    }

    // Sensitive runtime data logging
    const sensitiveLog = /console\.(log|info|debug)\([^)]*\b(password|token|secret|ssn|creditCard|card_number)\b/i.exec(content);
    if (sensitiveLog) {
      findings.push(makeFinding('sensitiveDataExposure', 'high',
        'Sensitive field logged to console',
        'A variable named like a sensitive field is passed to console logging. Sensitive data should not be logged in plaintext.',
        relPath, lineOf(content, sensitiveLog.index), 'A02:2021 - Cryptographic Failures'));
    }

    if (/schema\s*=\s*new\s+mongoose\.Schema\(\{[^}]*password[^}]*type\s*:\s*String/is.test(content) &&
        !/select\s*:\s*false/i.test(content)) {
      findings.push(makeFinding('sensitiveDataExposure', 'medium',
        'Password field may not be excluded from query results',
        'A Mongoose schema has a String password field without select:false. Review API serialization and query behavior to ensure passwords cannot be returned.',
        relPath, null, 'A02:2021 - Cryptographic Failures'));
    }

    // Authentication configuration
    const weakBcrypt = /bcrypt\.(hash|genSalt)\([^)]*,\s*(?:[1-9]|10)\s*[,)]/.exec(content);
    if (weakBcrypt) {
      findings.push(makeFinding('brokenAuthentication', 'medium',
        'bcrypt salt rounds below recommended minimum',
        'A low bcrypt work factor may provide less resistance to password cracking. Review the chosen cost factor for the deployment environment.',
        relPath, lineOf(content, weakBcrypt.index), 'A07:2021 - Identification and Authentication Failures'));
    }

    const jwtNoExpiry = /jwt\.sign\(\s*[^,]+,\s*[^,]+\s*\)/.exec(content);
    if (jwtNoExpiry && !/expiresIn/.test(content)) {
      findings.push(makeFinding('brokenAuthentication', 'high',
        'JWT may be signed without an expiry',
        'jwt.sign() appears to omit an expiresIn option. Verify that issued tokens have an appropriate lifetime.',
        relPath, lineOf(content, jwtNoExpiry.index), 'A07:2021 - Identification and Authentication Failures'));
    }

    // Security misconfiguration
    const permissiveCors = /cors\(\s*\)/.exec(content) || /origin\s*:\s*['"`]\*['"`]/.exec(content);
    if (permissiveCors) {
      findings.push(makeFinding('securityMisconfiguration', 'medium',
        'Permissive CORS configuration',
        'CORS appears to allow requests without an origin restriction. Review whether this is appropriate for credentialed or sensitive endpoints.',
        relPath, lineOf(content, permissiveCors.index), 'A05:2021 - Security Misconfiguration'));
    }
  }

  const anyHelmet = files.length > 0 && (await Promise.all(files.map(async (file) => {
    try { return /require\(['"]helmet['"]\)|from ['"]helmet['"]/.test(await fs.readFile(file, 'utf8')); }
    catch { return false; }
  }))).some(Boolean);

  if (!anyHelmet) {
    findings.push(makeFinding('securityMisconfiguration', 'medium',
      'Helmet.js not detected',
      'No usage of the helmet package was found. Review HTTP security headers and determine whether Helmet or an equivalent configuration is appropriate.',
      null, null, 'A05:2021 - Security Misconfiguration'));
  }

  return findings;
}

module.exports = { runHeuristicScan };
