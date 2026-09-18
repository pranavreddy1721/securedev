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

/**
 * Runs npm audit against an uploaded project.
 *
 * Determinism rule: do not generate a new lockfile during a scan. Generating
 * one can resolve today's dependency tree from the registry, meaning the
 * same ZIP can produce different results on different days. A project with
 * package.json but no package-lock.json is therefore reported as unavailable
 * for the npm audit engine instead of silently changing its dependency graph.
 */
async function runNpmAuditScan(projectDir) {
  const pkgJsonPath = path.join(projectDir, 'package.json');
  const lockPath = path.join(projectDir, 'package-lock.json');

  const hasPackageJson = await fs
    .access(pkgJsonPath)
    .then(() => true)
    .catch(() => false);

  if (!hasPackageJson) {
    return { findings: [], skipped: true, reason: 'No package.json found at project root' };
  }

  const hasLock = await fs
    .access(lockPath)
    .then(() => true)
    .catch(() => false);

  if (!hasLock) {
    throw new Error('package.json found, but package-lock.json is missing. npm audit was not run because generating a lockfile would make scan results non-deterministic.');
  }

  const timeoutMs = parseInt(process.env.NPM_AUDIT_TIMEOUT_MS || '60000', 10);

  let stdout;
  try {
    // npm audit exits non-zero when vulnerabilities are found — that is an
    // expected scan result, not a tool failure.
    const result = await execFileAsync('npm', ['audit', '--json'], {
      cwd: projectDir,
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024 * 20,
    });
    stdout = result.stdout;
  } catch (err) {
    if (err.stdout) {
      stdout = err.stdout;
    } else {
      throw new Error(`npm audit failed to produce output: ${err.message}`);
    }
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (err) {
    throw new Error(`Failed to parse npm audit JSON output: ${err.message}`);
  }

  return { findings: parseNpmAuditJson(parsed), skipped: false };
}

function parseNpmAuditJson(parsed) {
  const findings = [];
  const vulns = parsed.vulnerabilities || {};

  for (const [pkgName, vuln] of Object.entries(vulns)) {
    const severity = NPM_SEVERITY_MAP[vuln.severity] || 'medium';
    const viaEntries = Array.isArray(vuln.via) ? vuln.via : [];

    const advisoryTitles = viaEntries
      .filter((v) => typeof v === 'object' && v.title)
      .map((v) => v.title);

    const title =
      advisoryTitles.length > 0
        ? `${pkgName}: ${advisoryTitles[0]}`
        : `${pkgName}: known vulnerability (${vuln.severity})`;

    findings.push({
      category: 'vulnerableDependencies',
      severity,
      title,
      description: `Affects versions: ${vuln.range || 'unknown'}. ${
        vuln.fixAvailable ? 'A fix is available via npm audit fix.' : 'No automatic fix currently available.'
      }`,
      file: 'package-lock.json',
      line: null,
      engine: 'npm-audit',
      owaspRef: 'A06:2021 - Vulnerable and Outdated Components',
      heuristic: false,
    });
  }

  return findings;
}

module.exports = { runNpmAuditScan, parseNpmAuditJson };
