const test = require('node:test');
const assert = require('node:assert/strict');
const { computeScore, computeRawPenalty, applyDiminishingReturns } = require('../src/scoring/scoringEngine');

test('raw penalty is deterministic and severity-weighted', () => {
  const findings = [{ severity: 'high' }, { severity: 'medium' }, { severity: 'low' }];
  assert.equal(computeRawPenalty(findings), 8);
  assert.equal(computeRawPenalty([...findings].reverse()), 8);
});

test('diminishing returns is deterministic and rounded to two decimals', () => {
  const first = applyDiminishingReturns(25, 50);
  const second = applyDiminishingReturns(25, 50);
  assert.equal(first, second);
  assert.equal(first, 60.65);
});

test('same findings in different orders produce the same score', () => {
  const findings = [
    { category: 'dependencyVulnerability', severity: 'high' },
    { category: 'hardcodedSecrets', severity: 'critical' },
    { category: 'xss', severity: 'medium' },
    { category: 'insecureFileUploads', severity: 'low' },
  ];
  assert.deepEqual(computeScore(findings), computeScore([...findings].reverse()));
});

test('empty findings always produce a perfect score', () => {
  const result = computeScore([]);
  assert.equal(result.finalScore, 100);
  assert.deepEqual(result.subScores, {
    dependency: 100,
    authentication: 100,
    secrets: 100,
    owaspCompliance: 100,
    configuration: 100,
  });
});
