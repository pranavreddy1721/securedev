const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const AdmZip = require('adm-zip');

const { safeExtract } = require('../src/utils/zipExtractor');
const { cloneRepo } = require('../src/utils/repoCloner');

test('zip extractor rejects path traversal entries', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'securedev-zip-test-'));
  const zipPath = path.join(root, 'malicious.zip');
  const destination = path.join(root, 'out');
  await fs.mkdir(destination);

  const zip = new AdmZip();
  zip.addFile('../../outside.txt', Buffer.from('should never be extracted'));
  zip.writeZip(zipPath);

  await assert.rejects(
    () => safeExtract(zipPath, destination),
    /path traversal attempt/
  );

  assert.equal(await fs.access(path.join(root, 'outside.txt')).then(() => true).catch(() => false), false);
  await fs.rm(root, { recursive: true, force: true });
});

test('GitHub cloner rejects non-GitHub clone targets before invoking git', async () => {
  await assert.rejects(
    () => cloneRepo({
      cloneUrl: 'https://example.com/attacker/repository.git',
      accessToken: 'not-a-real-token',
      branch: 'main',
      destDir: path.join(os.tmpdir(), 'securedev-invalid-clone'),
    }),
    /Only GitHub HTTPS repository URLs are allowed/
  );
});

test('GitHub cloner rejects unsafe branch names', async () => {
  await assert.rejects(
    () => cloneRepo({
      cloneUrl: 'https://github.com/example/repository.git',
      accessToken: 'not-a-real-token',
      branch: '../../etc',
      destDir: path.join(os.tmpdir(), 'securedev-invalid-branch'),
    }),
    /Invalid GitHub branch/
  );
});
