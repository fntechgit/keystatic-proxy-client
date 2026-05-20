// Verifies the package's cookie crypto matches @keystatic/core's scheme:
// HKDF-SHA256 over the secret, AES-GCM-256, with 16-byte salt and 12-byte IV
// prepended to ciphertext, base64url-encoded.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { encryptValue } from './crypto.js';

const SECRET = 'cookie-' + 'a'.repeat(40);
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

async function decryptValue(encrypted, secret) {
    const decoded = Buffer.from(encrypted, 'base64url');
    const salt = decoded.subarray(0, SALT_LENGTH);
    const iv = decoded.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const ciphertext = decoded.subarray(SALT_LENGTH + IV_LENGTH);
    const baseKey = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(secret), 'HKDF', false, ['deriveKey']);
    const key = await webcrypto.subtle.deriveKey(
        { name: 'HKDF', salt, hash: 'SHA-256', info: new Uint8Array(0) },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
    const plaintext = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new TextDecoder().decode(plaintext);
}

test('encryptValue round-trips through Keystatic-compatible decrypt', async () => {
    const original = 'gh_pat_secrettoken';
    const encrypted = await encryptValue(original, SECRET);
    assert.equal(typeof encrypted, 'string');
    const back = await decryptValue(encrypted, SECRET);
    assert.equal(back, original);
});

test('encryptValue uses a fresh random salt+IV each call (no reuse)', async () => {
    const a = await encryptValue('same-value', SECRET);
    const b = await encryptValue('same-value', SECRET);
    assert.notEqual(a, b);
});

test('encryptValue rejects short secrets', async () => {
    await assert.rejects(() => encryptValue('x', 'short'));
});

test('encrypted output has correct prefix lengths', async () => {
    const encrypted = await encryptValue('payload', SECRET);
    const decoded = Buffer.from(encrypted, 'base64url');
    assert.ok(decoded.length > SALT_LENGTH + IV_LENGTH);
});
