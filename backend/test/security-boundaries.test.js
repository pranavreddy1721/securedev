const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const AdmZip = require('adm-zip');

const { safeExtract } = require('../src/utils/zipExtractor');
const { cloneRepo } = require('../src/utils/repoCloner');

test('zip extractor never writes a traversal entry outside destination', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'securedev-zip-test-'));
  const zipPath = path.join(root, 'malicious.zip');
  const destination = path.join(root, 'out');
  const outsidePath = path.join(root, 'outside.txt');
  await fs.mkdir(destination);

  try {
    const zip = new AdmZip();
    // AdmZip normalizes leading ../ segments when writing the archive, so the
    // regression assertion is that extraction can never create a file outside
    // the destination directory even when the source archive contains such input.
    zip.addFile('../../outside.txt', Buffer.from('should never be extracted'));
    zip.writeZip(zipPath);

    safeExtract(zipPath, destination);

    assert.equal(
      await fs.access(outsidePath).then(() => true).catch(() => false),
      false
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
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
