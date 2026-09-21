const test = require('node:test');
const assert = require('node:assert/strict');
const { deduplicateFindings, findingKey } = require('../src/utils/findingNormalizer');

test('deduplicates equivalent findings reported by multiple engines', () => {
  const findings = [
    { category: 'hardcodedSecrets', severity: 'medium', title: 'Hardcoded API key', file: './src/config.js', line: 10, engine: 'secret-scanner', heuristic: false },
    { category: 'hardcodedSecrets', severity: 'high', title: 'Hardcoded API key', file: 'src\\config.js', line: 10, engine: 'semgrep', heuristic: false },
  ];
  const result = deduplicateFindings(findings);
  assert.equal(result.length, 1);
  assert.equal(result[0].severity, 'high');
  assert.deepEqual(result[0].engines.sort(), ['secret-scanner', 'semgrep']);
});

test('finding key normalizes path separators and leading ./', () => {
  const a = findingKey({ category: 'xss', file: './src/App.jsx', line: 4, title: 'XSS finding' });
  const b = findingKey({ category: 'xss', file: 'src\\app.jsx', line: 4, title: '  XSS   finding ' });
  assert.equal(a, b);
});

test('normalization is deterministic regardless of scanner completion order', () => {
  const findingsA = [
    { category: 'xss', severity: 'medium', title: 'Reflected XSS', file: 'src\\routes.js', line: 20, engine: 'heuristic', heuristic: true },
    { category: 'injection', severity: 'high', title: 'Command Injection', file: './src/exec.js', line: 7, engine: 'semgrep', heuristic: false },
    { category: 'xss', severity: 'high', title: 'Reflected XSS', file: './SRC/routes.js', line: 20, engine: 'semgrep', heuristic: false },
  ];
  const findingsB = [...findingsA].reverse();
  assert.deepEqual(deduplicateFindings(findingsA), deduplicateFindings(findingsB));
});
