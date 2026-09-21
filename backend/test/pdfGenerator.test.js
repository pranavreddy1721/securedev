const test = require('node:test');
const assert = require('node:assert/strict');
const { generateScanPdf } = require('../src/reports/pdfGenerator');

test('generates a valid PDF without pagination errors', async () => {
  const scan = {
    status: 'completed',
    assessmentStatus: 'complete',
    finalScore: 61.6,
    riskBand: 'Medium Risk',
    completedAt: new Date('2026-09-21T15:26:28.000Z'),
    durationMs: 42000,
    engineStatus: {
      npmAudit: 'success',
      secretScanner: 'success',
      semgrep: 'success',
    },
    subScores: {
      dependency: 13,
      authentication: 100,
      secrets: 100,
      owaspCompliance: 39,
      configuration: 100,
    },
    findings: [
      {
        category: 'injectionFlaws',
        severity: 'high',
        title: 'gcm-no-tag-length',
        description: 'A security-sensitive operation was detected without the expected protection.',
        file: 'src/utils/crypto.js',
        line: 36,
        engine: 'semgrep',
      },
      {
        category: 'sensitiveDataExposure',
        severity: 'high',
        title: 'Sensitive field may be returned in an API response',
        description: 'A response appears to include a sensitive field. Verify that secrets, tokens, and password-related values are removed before serialization.',
        file: 'src/controllers/auth.controller.js',
        line: 94,
        engine: 'heuristic',
      },
    ],
  };

  const buffer = await generateScanPdf(scan, { name: 'securedev-main' });

  assert.ok(Buffer.isBuffer(buffer));
  assert.ok(buffer.length > 1000);
  assert.equal(buffer.subarray(0, 5).toString(), '%PDF-');
});
