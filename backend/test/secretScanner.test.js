const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { runSecretScan } = require('../src/scanners/secret.scanner');

async function withTempProject(files, fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'securedev-secret-test-'));
  try {
    for (const [name, content] of Object.entries(files)) {
      const target = path.join(dir, name);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, content, 'utf8');
    }
    return await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test('detects secrets in .env and .env.local files', async () => {
  await withTempProject({
    '.env': 'JWT_SECRET="super-secret-value"\n',
    '.env.local': 'API_KEY="1234567890abcdefghijkl"\n',
  }, async (dir) => {
    const findings = await runSecretScan(dir);
    assert.equal(findings.length, 2);
    assert.deepEqual(
      findings.map((f) => f.file).sort(),
      ['.env', '.env.local'].sort()
    );
  });
});

test('does not scan node_modules or build output', async () => {
  await withTempProject({
    'src/app.js': 'const x = "AKIA1234567890ABCDEF";\n',
    'node_modules/pkg/index.js': 'const x = "AKIA1234567890ABCDEF";\n',
    'dist/app.js': 'const x = "AKIA1234567890ABCDEF";\n',
  }, async (dir) => {
    const findings = await runSecretScan(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, path.join('src', 'app.js'));
  });
});
