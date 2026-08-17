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
 * Runs `npm audit --json` against the project directory (which must have a
 * package.json). Wraps the tool rather than reimplementing vulnerability
 * data — per the spec's core framing, npm audit's CVE database does the
 * real work here.
 */
async function runNpmAuditScan(projectDir) {
  const pkgJsonPath = path.join(projectDir, 'package.json');
  try {
    await fs.access(pkgJsonPath);
  } catch {
    // No package.json — nothing for npm audit to check. Not a failure,
    // just an empty result (e.g. a frontend-only zip, or a monorepo where
    // package.json lives in a subfolder not yet supported in v1).
    return { findings: [], skipped: true, reason: 'No package.json found at project root' };
  }

  const timeoutMs = parseInt(process.env.NPM_AUDIT_TIMEOUT_MS || '60000', 10);

  // Install first (audit needs a lockfile / node_modules resolution info).
  // --package-lock-only avoids actually downloading node_modules, keeping
  // this fast and side-effect-free in the ephemeral temp dir.
  try {
    await execFileAsync('npm', ['install', '--package-lock-only', '--ignore-scripts'], {
      cwd: projectDir,
      timeout: timeoutMs,
    });
  } catch (installErr) {
    // Some projects won't resolve cleanly (private registries, etc). Try
    // audit anyway if a lockfile already exists in the uploaded project.
    const hasLock = await fs
      .access(path.join(projectDir, 'package-lock.json'))
      .then(() => true)
      .catch(() => false);
    if (!hasLock) {
      throw new Error(`npm install failed and no existing lockfile to fall back on: ${installErr.message}`);
    }
  }

  let stdout;
  try {
    // npm audit exits non-zero when vulnerabilities are found — that's
    // expected, not a real error, so we read stdout from the caught error too.
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

/**
 * npm audit's JSON shape differs between npm v6, v7-v8, and v9+.
 * This targets the v7+ `vulnerabilities` object format (npm >= 7),
 * which is what current Node LTS ships. v6's `advisories` array format
 * is intentionally not supported in v1 — flagged as a known limitation.
 */
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
      file: 'package.json',
      line: null,
      engine: 'npm-audit',
      owaspRef: 'A06:2021 - Vulnerable and Outdated Components',
      heuristic: false,
    });
  }

  return findings;
}

module.exports = { runNpmAuditScan, parseNpmAuditJson };
