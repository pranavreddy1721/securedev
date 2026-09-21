const test = require('node:test');
const assert = require('node:assert/strict');
const { buildPrompt, parseJsonText } = require('../src/services/aiSecurity.service');

test('AI prompt contains scanner evidence and asks for structured remediation', () => {
  const prompt = buildPrompt({
    category: 'xss',
    severity: 'high',
    title: 'dangerouslySetInnerHTML detected',
    description: 'Untrusted HTML may reach a React sink.',
    file: 'src/App.jsx',
    line: 42,
    owaspRef: 'A03:2021 - Injection',
    engine: 'semgrep',
  });
  assert.match(prompt, /src\/App\.jsx/);
  assert.match(prompt, /42/);
  assert.match(prompt, /remediation/);
  assert.match(prompt, /Do not invent evidence/);
});

test('AI JSON parser accepts fenced JSON and returns an object', () => {
  const result = parseJsonText('```json\n{"explanation":"test","impact":"impact"}\n```');
  assert.deepEqual(result, { explanation: 'test', impact: 'impact' });
});

test('AI JSON parser rejects malformed responses', () => {
  assert.throws(() => parseJsonText('not json'));
});
