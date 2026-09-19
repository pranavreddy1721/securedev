const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { runSemgrepScan } = require('../src/scanners/semgrep.scanner');

const fixtureDir = path.join(__dirname, 'fixtures', 'vulnerable-mern');

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

  const result = await runSemgrepScan(fixtureDir);
  assert.ok(Array.isArray(result.findings));
  assert.ok(result.findings.length > 0, 'Semgrep should report at least one finding in the intentionally vulnerable fixture');
  assert.ok(result.findings.every((finding) => finding.engine === 'semgrep'));
  assert.ok(result.findings.every((finding) => finding.heuristic === false));
});
