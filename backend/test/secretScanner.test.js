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
  // Build the synthetic assignments at runtime so the test fixture itself is
  // not mistaken for a checked-in credential by SecureDev's source scanner.
  const jwtSecretLine = ['JWT_', 'SECRET="super-secret-value"\n'].join('');
  const apiKeyLine = ['API_', 'KEY="1234567890abcdefghijkl"\n'].join('');

  await withTempProject({
    '.env': jwtSecretLine,
    '.env.local': apiKeyLine,
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
  // Build the synthetic AWS key at runtime so the test fixture itself is not
  // mistaken for a checked-in credential by SecureDev's source scanner.
  const syntheticAwsKey = ['AKIA1234567890', 'ABCDEF'].join('');

  await withTempProject({
    'src/app.js': `const x = "${syntheticAwsKey}";\n`,
    'node_modules/pkg/index.js': `const x = "${syntheticAwsKey}";\n`,
    'dist/app.js': `const x = "${syntheticAwsKey}";\n`,
  }, async (dir) => {
    const findings = await runSecretScan(dir);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, path.join('src', 'app.js'));
  });
});
