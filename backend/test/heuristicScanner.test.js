const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { runHeuristicScan } = require('../src/scanners/heuristic.scanner');

async function scanSource(source) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'securedev-heuristic-test-'));
  try {
    const controller = path.join(root, 'src', 'controllers');
    await fs.mkdir(controller, { recursive: true });
    await fs.writeFile(path.join(controller, 'auth.controller.js'), source);
    return await runHeuristicScan(root);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

test('does not flag an intentionally returned access token by itself', async () => {
  const findings = await scanSource(`
    function login(req, res) {
      const accessToken = signAccessToken(user);
      return res.json({ user: user.toSafeJSON(), accessToken });
    }
  `);
  assert.equal(
    findings.some((finding) => finding.category === 'sensitiveDataExposure' &&
      finding.title === 'Sensitive field may be returned in an API response'),
    false
  );
});

test('continues to flag password hashes in API response expressions', async () => {
  const findings = await scanSource(`
    function unsafe(req, res) {
      return res.json({ user: { passwordHash: user.passwordHash } });
    }
  `);
  assert.equal(
    findings.some((finding) => finding.category === 'sensitiveDataExposure' &&
      finding.title === 'Sensitive field may be returned in an API response'),
    true
  );
});
