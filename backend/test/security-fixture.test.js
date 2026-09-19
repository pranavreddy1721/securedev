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

  assert.ok(found.has('Potential broken access control'));
  assert.ok(found.has('File upload without visible size limit'));
  assert.ok(found.has('User-controlled path construction'));
  assert.ok(found.has('Potential sensitive data in logs'));
  assert.ok(found.has('Potential sensitive data exposure in response'));
});
