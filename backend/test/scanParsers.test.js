const test = require('node:test');
const assert = require('node:assert/strict');
const { parseNpmAuditJson } = require('../src/scanners/npmAudit.scanner');
const { parseSemgrepJson, classifyRuleId } = require('../src/scanners/semgrep.scanner');

test('npm audit parser maps severities and preserves package findings', () => {
  const findings = parseNpmAuditJson({
    vulnerabilities: {
      lodash: {
        severity: 'high',
        range: '<4.17.21',
        via: [{ title: 'Prototype Pollution' }],
        fixAvailable: true,
      },
    },
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].category, 'vulnerableDependencies');
  assert.match(findings[0].title, /Prototype Pollution/);
});

test('Semgrep parser normalizes paths and classifies common rule IDs', () => {
  assert.equal(classifyRuleId('javascript.express.security.xss'), 'xss');
  assert.equal(classifyRuleId('javascript.nodejs.security.command-injection'), 'injectionFlaws');
  assert.equal(classifyRuleId('javascript.express.security.cors'), 'securityMisconfiguration');

  const findings = parseSemgrepJson({
    results: [{
      check_id: 'javascript.express.security.xss',
      path: '/tmp/project/src/App.jsx',
      start: { line: 12 },
      extra: {
        severity: 'ERROR',
        message: 'Potential XSS',
        metadata: { owasp: ['A03:2021'] },
      },
    }],
  }, '/tmp/project');

  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, 'src/App.jsx');
  assert.equal(findings[0].line, 12);
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].category, 'xss');
});
