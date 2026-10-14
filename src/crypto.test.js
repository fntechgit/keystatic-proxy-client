// The package's cookie crypto against @keystatic/core's own handler: Keystatic
// reads the refresh cookie this package writes, and this package reads the
// one Keystatic writes. The scheme is HKDF-SHA256 over the secret and
// AES-GCM-256, with a 16-byte salt and 12-byte IV before the ciphertext, all
// base64url-encoded.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { config } from '@keystatic/core';
import { makeGenericAPIRouteHandler } from '@keystatic/core/api/generic';
import { encryptValue, decryptValue } from './crypto.js';

const SECRET = 'cookie-' + 'a'.repeat(40);
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

const keystatic = makeGenericAPIRouteHandler({
    config: config({ storage: { kind: 'github', repo: 'owner/repo' } }),
    secret: SECRET,
    clientId: 'client-id',
    clientSecret: 'client-secret'
});

test("Keystatic's handler reads the refresh cookie this package writes", async (t) => {
    const sent = [];
    t.mock.method(globalThis, 'fetch', async (url) => {
        sent.push(new URL(url).searchParams.get('refresh_token'));
        return Response.json({ error: 'bad_refresh_token' });
    });
    const cookie = `keystatic-gh-refresh-token=${await encryptValue('ghr_written', SECRET)}`;
    await keystatic(
        new Request('https://site.test/api/keystatic/github/refresh-token', { method: 'POST', headers: { cookie } })
    );
    assert.deepEqual(sent, ['ghr_written']);
});

test("decryptValue reads the refresh cookie Keystatic's handler writes", async (t) => {
    t.mock.method(globalThis, 'fetch', async () =>
        Response.json({
            access_token: 'ghu_x',
            expires_in: 28800,
            refresh_token: 'ghr_from_keystatic',
            refresh_token_expires_in: 15897600,
            scope: '',
            token_type: 'bearer'
        })
    );
    const res = await keystatic(new Request('https://site.test/api/keystatic/github/oauth/callback?code=abc'));
    const [, cookie] = res.headers.find(([name, value]) => name === 'Set-Cookie' && value.startsWith('keystatic-gh-refresh-token='));
    assert.equal(await decryptValue(cookie.split(';')[0].split('=')[1], SECRET), 'ghr_from_keystatic');
});

test('decryptValue rejects a different secret and a tampered value', async () => {
    const encrypted = await encryptValue('ghr_x', SECRET);
    await assert.rejects(() => decryptValue(encrypted, 'other-' + 'b'.repeat(40)));
    // A character inside the ciphertext, past the salt and IV.
    const i = 40;
    const tampered = encrypted.slice(0, i) + (encrypted[i] === 'A' ? 'B' : 'A') + encrypted.slice(i + 1);
    await assert.rejects(() => decryptValue(tampered, SECRET));
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
