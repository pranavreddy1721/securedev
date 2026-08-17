const { execFile } = require('child_process');
const util = require('util');

const execFileAsync = util.promisify(execFile);

const SEMGREP_SEVERITY_MAP = {
  ERROR: 'high',
  WARNING: 'medium',
  INFO: 'low',
};

// Maps common Semgrep rule-id substrings to our 9-category taxonomy.
// Semgrep's public rulesets don't use our category names, so this is a
// best-effort classifier — anything unmatched falls back to injectionFlaws
// as a safe default bucket for "code pattern" issues under OWASP Compliance.
function classifyRuleId(ruleId = '') {
  const id = ruleId.toLowerCase();
  if (id.includes('xss') || id.includes('dangerouslysetinnerhtml') || id.includes('innerhtml')) return 'xss';
  if (id.includes('sql') || id.includes('nosql') || id.includes('command-injection') || id.includes('injection')) {
    return 'injectionFlaws';
  }
  if (id.includes('jwt') || id.includes('auth') || id.includes('session')) return 'brokenAuthentication';
  if (id.includes('cors') || id.includes('helmet') || id.includes('header')) return 'securityMisconfiguration';
  if (id.includes('path-traversal') || id.includes('upload')) return 'insecureFileUploads';
  if (id.includes('access-control') || id.includes('authorization')) return 'brokenAccessControl';
  if (id.includes('hardcoded') || id.includes('secret')) return 'hardcodedSecrets';
  return 'injectionFlaws';
}

/**
 * Runs Semgrep against the project using public rulesets only (per the
 * confirmed decision — no custom rule-writing in v1). Covers Injection
 * Flaws and XSS at meaningful depth; other categories may get incidental
 * hits but shouldn't be relied on for those.
 */
async function runSemgrepScan(projectDir) {
  const rulesets = (process.env.SEMGREP_RULESETS || 'p/javascript,p/react,p/nodejsscan').split(',');
  const timeoutMs = parseInt(process.env.SEMGREP_TIMEOUT_MS || '120000', 10);

  const args = ['scan', '--json', '--no-git-ignore', '--metrics=off'];
  for (const rs of rulesets) args.push('--config', rs.trim());
  args.push(projectDir);

  let stdout;
  try {
    const result = await execFileAsync('semgrep', args, {
      cwd: projectDir,
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024 * 50,
    });
    stdout = result.stdout;
  } catch (err) {
    // Semgrep exits 1 when findings exist — not a real failure.
    if (err.stdout) {
      stdout = err.stdout;
    } else {
      throw new Error(`Semgrep execution failed: ${err.message}`);
    }
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (err) {
    throw new Error(`Failed to parse Semgrep JSON output: ${err.message}`);
  }

  return { findings: parseSemgrepJson(parsed, projectDir) };
}

function parseSemgrepJson(parsed, projectDir) {
  const findings = [];
  const results = parsed.results || [];

  for (const r of results) {
    const severity = SEMGREP_SEVERITY_MAP[r.extra?.severity] || 'medium';
    const relPath = r.path?.startsWith(projectDir) ? r.path.slice(projectDir.length + 1) : r.path;

    findings.push({
      category: classifyRuleId(r.check_id),
      severity,
      title: r.check_id?.split('.').pop() || 'Semgrep finding',
      description: r.extra?.message || 'Semgrep flagged a potentially insecure code pattern.',
      file: relPath,
      line: r.start?.line || null,
      engine: 'semgrep',
      owaspRef: r.extra?.metadata?.owasp?.[0] || null,
      heuristic: false,
    });
  }

  return findings;
}

module.exports = { runSemgrepScan, parseSemgrepJson, classifyRuleId };
