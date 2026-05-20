// Cookie crypto compatible with @keystatic/core's getTokenCookies output.
// HKDF-SHA256 over the configured secret, AES-GCM-256, with 16-byte salt and
// 12-byte IV prepended to the ciphertext, all base64url-encoded.
//
// This mirrors exactly what @keystatic/core does internally (see
// keystatic-core-api-generic.js encryptValue / decryptValue), so cookies
// written by this package are indistinguishable from cookies the upstream
// route handler would have written.

import { webcrypto } from 'node:crypto';

const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const encoder = new TextEncoder();

async function deriveKey(secret, salt) {
    if (!secret || secret.length < 32) {
        throw new Error('KEYSTATIC_SECRET must be at least 32 characters long');
    }
    const key = await webcrypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveKey']);
    return webcrypto.subtle.deriveKey(
        { name: 'HKDF', salt, hash: 'SHA-256', info: new Uint8Array(0) },
        key,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

export async function encryptValue(value, secret) {
    const salt = webcrypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = webcrypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const key = await deriveKey(secret, salt);
    const encrypted = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(value));
    const full = new Uint8Array(SALT_LENGTH + IV_LENGTH + encrypted.byteLength);
    full.set(salt);
    full.set(iv, SALT_LENGTH);
    full.set(new Uint8Array(encrypted), SALT_LENGTH + IV_LENGTH);
    return Buffer.from(full).toString('base64url');
}
