const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs/promises');

const { runSecretScan } = require('../src/scanners/secret.scanner');
const { runHeuristicScan } = require('../src/scanners/heuristic.scanner');

const fixture = path.join(__dirname, 'fixtures', 'vulnerable-mern');

function titles(findings) {
  return new Set(findings.map((finding) => finding.title));
}

test('controlled fixture: secret scanner detects source and .env credentials', async () => {
  // Keep credential-shaped test data out of the repository itself. The scanner
  // still receives realistic synthetic values at runtime, so detection coverage
  // remains intact without making the SecureDev repo look like it contains secrets.
  const secretFixture = await fs.mkdtemp(path.join(os.tmpdir(), 'securedev-secret-fixture-'));
  try {
    const jwtSecret = ['local', 'fixture-secret-123456789'].join('-');
    const apiKey = ['1234567890', 'abcdefghijklmnop'].join('');
    const mongoUri = ['mongodb://fixture-user', 'fixture-password@localhost:27017/fixturedb'].join(':');

    await fs.writeFile(
      path.join(secretFixture, '.env.local'),
      `JWT_SECRET="${jwtSecret}"\nAPI_KEY="${apiKey}"\nMONGO_URI="${mongoUri}"\n`,
      'utf8'
    );

    const findings = await runSecretScan(secretFixture);
    const found = titles(findings);

    assert.ok(found.has('Generic JWT Secret assignment'));
    assert.ok(found.has('Generic API Key assignment'));
    assert.ok(found.has('MongoDB Connection String with credentials'));
    assert.ok(findings.some((finding) => finding.file === '.env.local'));
  } finally {
    await fs.rm(secretFixture, { recursive: true, force: true });
  }
});

test('controlled fixture: heuristic scanner detects upload, auth and sensitive-data risks', async () => {
  const findings = await runHeuristicScan(fixture);
  const found = titles(findings);

  assert.ok(found.has('Administrative route may lack an authorization/role check'));
  assert.ok(found.has('Multer configured without upload limits'));
  assert.ok(found.has('Possible path traversal via user-controlled path segment'));
  assert.ok(found.has('Sensitive field logged to console'));
  assert.ok(found.has('Sensitive field may be returned in an API response'));
});
