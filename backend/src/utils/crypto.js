const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';

function getKey() {
  const b64 = process.env.GITHUB_TOKEN_ENC_KEY;
  if (!b64) {
    throw new Error('GITHUB_TOKEN_ENC_KEY is not set — cannot encrypt/decrypt GitHub tokens');
  }
  const key = Buffer.from(b64, 'base64');
  if (key.length !== 32) {
    throw new Error('GITHUB_TOKEN_ENC_KEY must decode to exactly 32 bytes (AES-256)');
  }
  return key;
}

/**
 * Encrypts a plaintext string (e.g. a GitHub OAuth access token) for storage.
 * Returns a single base64 string: iv (12b) + authTag (16b) + ciphertext.
 */
function encrypt(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function decrypt(payloadB64) {
  const key = getKey();
  const buf = Buffer.from(payloadB64, 'base64');
  const iv = buf.subarray(0, 12);
  const authTag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

module.exports = { encrypt, decrypt };
