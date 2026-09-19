const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { runSemgrepScan } = require('../src/scanners/semgrep.scanner');

const fixtureDir = path.join(__dirname, 'fixtures', 'vulnerable-mern');
const deterministicRules = path.join(__dirname, 'fixtures', 'semgrep-test-rules.yml');

test('Semgrep integration scans the controlled vulnerable fixture', async (t) => {
  if (process.env.SEMGREP_INTEGRATION !== '1') {
    t.skip('Set SEMGREP_INTEGRATION=1 to run the external Semgrep integration test');
    return;
  }

  try {
    execFileSync('semgrep', ['--version'], { stdio: 'ignore' });
  } catch {
    assert.fail('Semgrep is not installed in the integration environment');
  }

  // Use a repository-local rule so this test validates Semgrep execution and
  // JSON parsing deterministically, independent of hosted ruleset changes.
  const previousRulesets = process.env.SEMGREP_RULESETS;
  process.env.SEMGREP_RULESETS = deterministicRules;

  try {
    const result = await runSemgrepScan(fixtureDir);
    assert.ok(Array.isArray(result.findings));
    assert.ok(result.findings.length > 0, 'Semgrep should report at least one finding in the intentionally vulnerable fixture');
    assert.ok(result.findings.every((finding) => finding.engine === 'semgrep'));
    assert.ok(result.findings.every((finding) => finding.heuristic === false));
  } finally {
    if (previousRulesets === undefined) delete process.env.SEMGREP_RULESETS;
    else process.env.SEMGREP_RULESETS = previousRulesets;
  }
});
