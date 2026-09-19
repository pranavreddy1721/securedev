const { execFile } = require('child_process');
const util = require('util');

const execFileAsync = util.promisify(execFile);

const SEMGREP_SEVERITY_MAP = {
  ERROR: 'high',
  WARNING: 'medium',
  INFO: 'low',
};

// Maps common Semgrep rule-id substrings to our 9-category taxonomy.
// This is a best-effort classifier because public rulesets use their own IDs.
function classifyRuleId(ruleId = '') {
  const id = ruleId.toLowerCase();
  if (id.includes('xss') || id.includes('dangerouslysetinnerhtml') || id.includes('innerhtml')) return 'xss';
  if (id.includes('sql') || id.includes('nosql') || id.includes('command-injection') || id.includes('injection')) return 'injectionFlaws';
  if (id.includes('jwt') || id.includes('auth') || id.includes('session')) return 'brokenAuthentication';
  if (id.includes('cors') || id.includes('helmet') || id.includes('header')) return 'securityMisconfiguration';
  if (id.includes('path-traversal') || id.includes('upload')) return 'insecureFileUploads';
  if (id.includes('access-control') || id.includes('authorization')) return 'brokenAccessControl';
  if (id.includes('hardcoded') || id.includes('secret')) return 'hardcodedSecrets';
  return 'injectionFlaws';
}

/**
 * Runs Semgrep against the project using the Express ruleset by default.
 * Express rules already build on the JavaScript/Node ecosystem coverage, so
 * running three overlapping configs by default can duplicate findings.
 * Deployments can pin a different set through SEMGREP_RULESETS.
 */
async function runSemgrepScan(projectDir) {
  const rulesets = (process.env.SEMGREP_RULESETS || 'p/expressjs')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);

  if (rulesets.length === 0) {
    throw new Error('SEMGREP_RULESETS is empty; at least one Semgrep ruleset is required.');
  }

  const timeoutMs = parseInt(process.env.SEMGREP_TIMEOUT_MS || '120000', 10);
  const args = ['scan', '--json', '--no-git-ignore', '--metrics=off'];
  for (const ruleset of rulesets) args.push('--config', ruleset);
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
    // Semgrep exits non-zero when findings exist; JSON on stdout is still a
    // valid scan result. Treat it as a tool failure only when no JSON exists.
    if (err.stdout) stdout = err.stdout;
    else throw new Error(`Semgrep execution failed: ${err.message}`);
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
    const resultPath = r.path || '';
    const relPath = resultPath.startsWith(projectDir)
      ? resultPath.slice(projectDir.length + 1)
      : resultPath;

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
