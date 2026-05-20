// Security regression tests for the handoff JWS verifier.
// Run with: pnpm test (uses node --test).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT } from 'jose';
import { verifyHandoff, isValidFrom, keystaticPathRegex } from './handoff.js';

const SECRET = 'shared-' + 'a'.repeat(40);
const KEY = new TextEncoder().encode(SECRET);

async function makeHandoff(claims, opts = {}) {
    return new SignJWT(claims)
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuedAt()
        .setExpirationTime(opts.exp || '60s')
        .sign(opts.key || KEY);
}

test('verifyHandoff round-trips a valid payload', async () => {
    const token = await makeHandoff({ access_token: 't', site: 'https://foo.com' });
    const out = await verifyHandoff(token, SECRET);
    assert.equal(out.access_token, 't');
    assert.equal(out.site, 'https://foo.com');
});

test('verifyHandoff rejects a wrong signature', async () => {
    const token = await makeHandoff({ access_token: 't' });
    const segs = token.split('.');
    segs[2] = segs[2].replace(/^./, (c) => (c === 'a' ? 'b' : 'a'));
    assert.equal(await verifyHandoff(segs.join('.'), SECRET), null);
});

test('verifyHandoff rejects token signed with a different secret', async () => {
    const other = await makeHandoff(
        { access_token: 't' },
        { key: new TextEncoder().encode('other-' + 'b'.repeat(40)) }
    );
    assert.equal(await verifyHandoff(other, SECRET), null);
});

test('verifyHandoff rejects empty/missing inputs', async () => {
    assert.equal(await verifyHandoff('', SECRET), null);
    assert.equal(await verifyHandoff(null, SECRET), null);
    assert.equal(await verifyHandoff('abc', null), null);
    assert.equal(await verifyHandoff(undefined, undefined), null);
});

test('verifyHandoff rejects malformed token', async () => {
    assert.equal(await verifyHandoff('not.a.jwt', SECRET), null);
    assert.equal(await verifyHandoff('only-one-part', SECRET), null);
});

test('verifyHandoff rejects expired token', async () => {
    const expired = await new SignJWT({ access_token: 't' })
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
        .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
        .sign(KEY);
    assert.equal(await verifyHandoff(expired, SECRET), null);
});

test('verifyHandoff rejects alg=none confusion attempt', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
        access_token: 'fake',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60
    })).toString('base64url');
    const noneJwt = `${header}.${payload}.`;
    assert.equal(await verifyHandoff(noneJwt, SECRET), null);
});

test('keystaticPathRegex accepts valid admin paths', () => {
    assert.ok(keystaticPathRegex.test('branch/main'));
    assert.ok(keystaticPathRegex.test('branch/main/collection/posts'));
    assert.ok(keystaticPathRegex.test('branch/main/collection/posts/create'));
    assert.ok(keystaticPathRegex.test('branch/main/collection/posts/item/abc'));
    assert.ok(keystaticPathRegex.test('branch/main/singleton/hero'));
});

test('isValidFrom rejects open-redirect and traversal attempts', () => {
    assert.equal(isValidFrom('//evil.com'), false);
    assert.equal(isValidFrom('https://evil.com'), false);
    assert.equal(isValidFrom('../etc/passwd'), false);
    assert.equal(isValidFrom('branch/main/../../etc/passwd'), false);
    assert.equal(isValidFrom('branch/feature/..'), false);
    assert.equal(isValidFrom(''), false);
    assert.equal(isValidFrom('foo'), false);
});

test('isValidFrom accepts legitimate Keystatic paths', () => {
    assert.ok(isValidFrom('branch/main'));
    assert.ok(isValidFrom('branch/main/collection/posts/item/abc'));
});
