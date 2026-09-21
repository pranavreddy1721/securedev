const { execFile } = require('child_process');
const fs = require('fs/promises');
const path = require('path');
const util = require('util');

const execFileAsync = util.promisify(execFile);

const NPM_SEVERITY_MAP = {
  critical: 'critical',
  high: 'high',
  moderate: 'medium',
  low: 'low',
  info: 'low',
};

const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.cache']);

async function findNpmProjects(projectDir, currentDir = projectDir, depth = 0, results = []) {
  if (depth > 4) return results;

  const entries = await fs.readdir(currentDir, { withFileTypes: true }).catch(() => []);
  const hasPackageJson = entries.some((entry) => entry.isFile() && entry.name === 'package.json');
  const hasLock = entries.some((entry) => entry.isFile() && entry.name === 'package-lock.json');

  if (hasPackageJson && hasLock) {
    results.push(currentDir);
    return results;
  }

  for (const entry of entries) {
    if (!entry.isDirectory() || IGNORED_DIRS.has(entry.name)) continue;
    await findNpmProjects(projectDir, path.join(currentDir, entry.name), depth + 1, results);
  }

  return results;
}

async function runAuditForDirectory(projectDir, auditDir) {
  const timeoutMs = parseInt(process.env.NPM_AUDIT_TIMEOUT_MS || '60000', 10);
  let stdout;

  try {
    const result = await execFileAsync('npm', ['audit', '--json', '--package-lock-only'], {
      cwd: auditDir,
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024 * 20,
    });
    stdout = result.stdout;
  } catch (err) {
    if (err.stdout) stdout = err.stdout;
    else throw new Error(`npm audit failed to produce output: ${err.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (err) {
    throw new Error(`Failed to parse npm audit JSON output: ${err.message}`);
  }

  const relativeDir = path.relative(projectDir, auditDir).replace(/\\/g, '/');
  return parseNpmAuditJson(parsed, relativeDir);
}

/**
 * MERN repositories often contain separate lockfiles in frontend/ and backend/.
 * Audit every deterministic package-lock.json instead of requiring one at the
 * repository root. No lockfile is generated during a scan.
 */
async function runNpmAuditScan(projectDir) {
  const packageDirs = await findNpmProjects(projectDir);

  if (packageDirs.length === 0) {
    return {
      findings: [],
      skipped: true,
      reason: 'No package.json + package-lock.json pair found in the project',
    };
  }

  const results = await Promise.allSettled(packageDirs.map((dir) => runAuditForDirectory(projectDir, dir)));
  const successful = results.filter((result) => result.status === 'fulfilled');
  const failed = results.filter((result) => result.status === 'rejected');

  if (successful.length === 0) {
    throw new Error(failed[0]?.reason?.message || 'npm audit failed for all detected Node projects');
  }

  if (failed.length > 0) {
    console.warn(`[npm-audit] ${failed.length} project audit(s) failed; using successful audit results.`);
  }

  return {
    findings: successful.flatMap((result) => result.value),
    skipped: false,
    projectsAudited: successful.length,
    projectsFailed: failed.length,
  };
}

function parseNpmAuditJson(parsed, projectRelativeDir = '') {
  const findings = [];
  const vulns = parsed.vulnerabilities || {};
  const lockFile = projectRelativeDir ? `${projectRelativeDir}/package-lock.json` : 'package-lock.json';

  for (const [pkgName, vuln] of Object.entries(vulns)) {
    const severity = NPM_SEVERITY_MAP[vuln.severity] || 'medium';
    const viaEntries = Array.isArray(vuln.via) ? vuln.via : [];
    const advisoryTitles = viaEntries
      .filter((v) => typeof v === 'object' && v.title)
      .map((v) => v.title);

    const title = advisoryTitles.length > 0
      ? `${pkgName}: ${advisoryTitles[0]}`
      : `${pkgName}: known vulnerability (${vuln.severity})`;

    findings.push({
      category: 'vulnerableDependencies',
      severity,
      title,
      description: `Affects versions: ${vuln.range || 'unknown'}. ${
        vuln.fixAvailable ? 'A fix is available via npm audit fix.' : 'No automatic fix currently available.'
      }`,
      file: lockFile,
      line: null,
      engine: 'npm-audit',
      owaspRef: 'A06:2021 - Vulnerable and Outdated Components',
      heuristic: false,
    });
  }

  return findings;
}

module.exports = { runNpmAuditScan, parseNpmAuditJson, findNpmProjects };
