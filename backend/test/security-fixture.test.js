const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { runSecretScan } = require('../src/scanners/secret.scanner');
const { runHeuristicScan } = require('../src/scanners/heuristic.scanner');

const fixture = path.join(__dirname, 'fixtures', 'vulnerable-mern');

function titles(findings) {
  return new Set(findings.map((finding) => finding.title));
}

test('controlled fixture: secret scanner detects source and .env credentials', async () => {
  const findings = await runSecretScan(fixture);
  const found = titles(findings);

  assert.ok(found.has('Generic JWT Secret assignment'));
  assert.ok(found.has('Generic API Key assignment'));
  assert.ok(found.has('MongoDB Connection String with credentials'));
  assert.ok(findings.some((finding) => finding.file === '.env.local'));
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
