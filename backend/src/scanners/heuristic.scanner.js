const fs = require('fs/promises');
const path = require('path');

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build']);
const AUTH_MIDDLEWARE = /\b(?:requireAuth|authMiddleware|isAuthenticated|verifyToken|authenticate|passport\.authenticate|protect|requireLogin|ensureAuthenticated)\b/;
const AUTHZ_MIDDLEWARE = /\b(?:authorize|requireRole|requirePermission|checkRole|checkPermission|isAdmin|adminOnly|rbac|acl|canAccess)\b/i;
const SENSITIVE_ROUTE = /\/(?:admin|users?|accounts?|profiles?|settings|payments?|orders?|delete|update|manage|private|dashboard)(?:\/|$)/i;

async function walkJsFiles(dir, files = []) {
  let entries;
  try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return files; }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) await walkJsFiles(fullPath, files);
    else if (/\.(js|jsx|ts|tsx)$/.test(entry.name)) files.push(fullPath);
  }
  return files;
}

function lineOf(content, index) { return content.slice(0, Math.max(0, index)).split('\n').length; }
function makeFinding(category, severity, title, description, file, line, owaspRef) {
  return { category, severity, title, description, file: file || null, line: line || null, engine: 'heuristic', owaspRef: owaspRef || null, heuristic: true };
}

/** Pattern-based security checks. Intentionally heuristic, not AST/data-flow analysis. */
async function runHeuristicScan(projectDir) {
  const findings = [];
  const files = await walkJsFiles(projectDir);

  for (const filePath of files) {
    let content;
    try { content = await fs.readFile(filePath, 'utf8'); } catch { continue; }
    const relPath = path.relative(projectDir, filePath);

    // File-upload security
    const multerIndex = content.search(/multer\s*\(|multer\.diskStorage\(/);
    if (multerIndex >= 0) {
      const hasFilter = /fileFilter\s*:/.test(content);
      const hasLimits = /limits\s*:/.test(content);
      const hasSizeLimit = /limits\s*:\s*\{[^}]*fileSize\s*:/is.test(content);
      const hasMimeCheck = /mimetype|file\.mimetype|allowedMime|allowedTypes|contentType/i.test(content);
      const hasExtensionCheck = /path\.extname|\.originalname.*\.(?:endsWith|test)|allowedExtensions?/i.test(content);
      const hasFilenameControl = /filename\s*:\s*(?:\(|function|[^,}]*=>)/.test(content);
      if (!hasFilter) findings.push(makeFinding('insecureFileUploads', 'medium', 'Multer configured without a fileFilter', 'File uploads should restrict accepted file types using server-side validation.', relPath, lineOf(content, multerIndex), 'A04:2021 - Insecure Design'));
      else if (!hasMimeCheck && !hasExtensionCheck) findings.push(makeFinding('insecureFileUploads', 'medium', 'Upload filter may not validate file type', 'A fileFilter exists, but no recognizable MIME-type or extension validation was detected. Verify that untrusted file types are rejected server-side.', relPath, lineOf(content, multerIndex), 'A04:2021 - Insecure Design'));
      if (!hasLimits) findings.push(makeFinding('insecureFileUploads', 'low', 'Multer configured without upload limits', 'Missing limits configuration can permit unnecessarily large uploads and increase resource-exhaustion risk.', relPath, lineOf(content, multerIndex), 'A04:2021 - Insecure Design'));
      else if (!hasSizeLimit) findings.push(makeFinding('insecureFileUploads', 'low', 'Multer limits do not define fileSize', 'Review limits.fileSize so upload size is explicitly bounded.', relPath, lineOf(content, multerIndex), 'A04:2021 - Insecure Design'));
      if (/diskStorage\s*\(/.test(content) && !hasFilenameControl) findings.push(makeFinding('insecureFileUploads', 'medium', 'Disk upload storage may use uncontrolled filenames', 'diskStorage() is used without a recognizable custom filename function. Avoid trusting user-supplied original filenames and generate server-side names.', relPath, lineOf(content, multerIndex), 'A04:2021 - Insecure Design'));
    }

    // User-controlled filesystem paths
    const traversal = /path\.(?:join|resolve)\([^)]*req\.(body|params|query)/.exec(content);
    if (traversal) findings.push(makeFinding('insecureFileUploads', 'high', 'Possible path traversal via user-controlled path segment', 'User input appears to flow into a filesystem path. Validate the input and constrain the resolved path to an intended directory before filesystem access.', relPath, lineOf(content, traversal.index), 'A01:2021 - Broken Access Control'));

    // Authentication / authorization. Support route middleware and inline ownership/role checks.
    const routeRegex = /(?:router|app)\.(get|post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]\s*,([^\n;]*)(?:\);|\n)/g;
    for (const match of content.matchAll(routeRegex)) {
      const route = match[2];
      const middlewareAndHandler = match[3] || '';
      const sensitive = SENSITIVE_ROUTE.test(route);
      const hasAuth = AUTH_MIDDLEWARE.test(middlewareAndHandler) || /req\.user\b|req\.auth\b|req\.session\b/.test(middlewareAndHandler);
      const hasAuthz = AUTHZ_MIDDLEWARE.test(middlewareAndHandler) || /(?:req\.user\.(?:role|isAdmin|permissions?)|req\.auth\.(?:role|permissions?)|req\.user\.id\s*===|req\.params\.id\s*===\s*req\.user\.id|403|forbidden)/i.test(middlewareAndHandler);
      const index = match.index || 0;
      if (sensitive && !hasAuth) findings.push(makeFinding('brokenAuthentication', 'medium', 'Sensitive route may be missing authentication middleware', `Route ${route} matches a sensitive-path pattern but no recognizable authentication middleware or inline authenticated-user reference is present. Verify manually; this is heuristic.`, relPath, lineOf(content, index), 'A07:2021 - Identification and Authentication Failures'));
      if (/\/(?:admin|manage|management)(?:\/|$)/i.test(route) && hasAuth && !hasAuthz) findings.push(makeFinding('brokenAccessControl', 'high', 'Administrative route may lack an authorization/role check', `Route ${route} has recognizable authentication but no recognizable authorization middleware, role/permission check, or ownership check.`, relPath, lineOf(content, index), 'A01:2021 - Broken Access Control'));
    }

    // Authorization patterns outside the route declaration.
    const roleCheck = /(?:req\.(?:user|auth)\.(?:role|isAdmin|permissions?)|user\.(?:role|isAdmin|permissions?))\s*(?:===|!==|==|!=|\.includes\(|\.has\()/i.exec(content);
    const ownershipCheck = /(?:req\.(?:params|body|query)\.[A-Za-z_$][\w$]*\s*(?:===|==)\s*req\.(?:user|auth)\.id|req\.(?:user|auth)\.id\s*(?:===|==)\s*req\.(?:params|body|query)\.[A-Za-z_$][\w$]*)/i.exec(content);
    if (roleCheck || ownershipCheck) {
      // Presence of these checks is useful evidence and should not itself be reported as a vulnerability.
    }

    // Sensitive data exposure
    const sensitiveLog = /console\.(log|info|debug)\([^)]*\b(password|token|secret|ssn|creditCard|card_number|authorization)\b/i.exec(content);
    if (sensitiveLog) findings.push(makeFinding('sensitiveDataExposure', 'high', 'Sensitive field logged to console', 'A variable named like a sensitive field is passed to console logging. Sensitive data should not be logged in plaintext.', relPath, lineOf(content, sensitiveLog.index), 'A02:2021 - Cryptographic Failures'));
    if (/schema\s*=\s*new\s+mongoose\.Schema\(\{[^}]*password[^}]*type\s*:\s*String/is.test(content) && !/select\s*:\s*false/i.test(content)) findings.push(makeFinding('sensitiveDataExposure', 'medium', 'Password field may not be excluded from query results', 'A Mongoose schema has a String password field without select:false. Review API serialization and query behavior to ensure passwords cannot be returned.', relPath, null, 'A02:2021 - Cryptographic Failures'));
    const jsonSensitive = /res\.(json|send)\([^)]*\b(password|passwordHash|refreshToken|accessToken|secret|apiKey)\b/i.exec(content);
    if (jsonSensitive) findings.push(makeFinding('sensitiveDataExposure', 'high', 'Sensitive field may be returned in an API response', 'A response appears to include a sensitive field. Verify that secrets, password hashes and tokens are removed before serialization.', relPath, lineOf(content, jsonSensitive.index), 'A02:2021 - Cryptographic Failures'));

    // Authentication configuration
    const weakBcrypt = /bcrypt\.(hash|genSalt)\([^)]*,\s*(?:[1-9]|10)\s*[,)]/.exec(content);
    if (weakBcrypt) findings.push(makeFinding('brokenAuthentication', 'medium', 'bcrypt salt rounds below recommended minimum', 'A low bcrypt work factor may provide less resistance to password cracking. Review the chosen cost factor for the deployment environment.', relPath, lineOf(content, weakBcrypt.index), 'A07:2021 - Identification and Authentication Failures'));
    const jwtNoExpiry = /jwt\.sign\(\s*[^,]+,\s*[^,]+\s*\)/.exec(content);
    if (jwtNoExpiry && !/expiresIn/.test(content)) findings.push(makeFinding('brokenAuthentication', 'high', 'JWT may be signed without an expiry', 'jwt.sign() appears to omit an expiresIn option. Verify that issued tokens have an appropriate lifetime.', relPath, lineOf(content, jwtNoExpiry.index), 'A07:2021 - Identification and Authentication Failures'));

    // Security misconfiguration
    const permissiveCors = /cors\(\s*\)/.exec(content) || /origin\s*:\s*['"`]\*['"`]/.exec(content);
    if (permissiveCors) findings.push(makeFinding('securityMisconfiguration', 'medium', 'Permissive CORS configuration', 'CORS appears to allow requests without an origin restriction. Review whether this is appropriate for credentialed or sensitive endpoints.', relPath, lineOf(content, permissiveCors.index), 'A05:2021 - Security Misconfiguration'));
  }

  const anyHelmet = files.length > 0 && (await Promise.all(files.map(async (file) => {
    try { return /require\(['"]helmet['"]\)|from ['"]helmet['"]/.test(await fs.readFile(file, 'utf8')); } catch { return false; }
  }))).some(Boolean);
  if (!anyHelmet) findings.push(makeFinding('securityMisconfiguration', 'medium', 'Helmet.js not detected', 'No usage of the helmet package was found. Review HTTP security headers and determine whether Helmet or an equivalent configuration is appropriate.', null, null, 'A05:2021 - Security Misconfiguration'));

  return findings;
}

module.exports = { runHeuristicScan };
