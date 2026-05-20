// Regression tests for siteOriginFromRequest. The wrapper must trust the
// request's Host header rather than new URL(req.url).origin, because Next dev
// rewrites req.url to its configured "Local:" host regardless of the actual
// Host the browser used. Without this, Keystatic's RFC 8252 redirect from
// localhost → 127.0.0.1 sends the wrong site to the proxy and the cookie
// scope never lines up.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { jwtVerify } from 'jose';
import { siteOriginFromRequest, signAuthRequest } from './route-handler.js';

const enc = new TextEncoder();
const SECRET = 'handoff-' + 'a'.repeat(40);
const key = enc.encode(SECRET);

function mockRequest({ url = 'http://stale-host/x', headers = {} } = {}) {
    return {
        url,
        headers: { get: (k) => headers[k.toLowerCase()] ?? null }
    };
}

test('siteOriginFromRequest uses Host header, not req.url', () => {
    const req = mockRequest({
        url: 'http://localhost:3000/api/keystatic/github/login',
        headers: { host: '127.0.0.1:3000' }
    });
    assert.equal(siteOriginFromRequest(req), 'http://127.0.0.1:3000');
});

test('siteOriginFromRequest defaults loopback hosts to http', () => {
    for (const host of ['localhost:3000', '127.0.0.1:3000', '[::1]:3000']) {
        const req = mockRequest({ headers: { host } });
        assert.equal(siteOriginFromRequest(req), `http://${host}`);
    }
});

test('siteOriginFromRequest defaults non-loopback hosts to https', () => {
    const req = mockRequest({ headers: { host: 'foxtrot-november.netlify.app' } });
    assert.equal(siteOriginFromRequest(req), 'https://foxtrot-november.netlify.app');
});

test('siteOriginFromRequest honors x-forwarded-proto when present', () => {
    const req = mockRequest({
        headers: { host: 'foxtrot-november.netlify.app', 'x-forwarded-proto': 'https' }
    });
    assert.equal(siteOriginFromRequest(req), 'https://foxtrot-november.netlify.app');
});

test('siteOriginFromRequest prefers x-forwarded-host over host', () => {
    const req = mockRequest({
        headers: {
            host: 'internal-lb:8080',
            'x-forwarded-host': 'foxtrot-november.netlify.app',
            'x-forwarded-proto': 'https'
        }
    });
    assert.equal(siteOriginFromRequest(req), 'https://foxtrot-november.netlify.app');
});

test('signAuthRequest produces a JWS the proxy can verify with the same secret', async () => {
    const jws = await signAuthRequest({
        site: 'https://foo.com',
        from: 'branch/main',
        handoffSecret: SECRET
    });
    assert.equal(typeof jws, 'string');
    assert.equal(jws.split('.').length, 3);
    const { payload } = await jwtVerify(jws, key, { algorithms: ['HS256'] });
    assert.equal(payload.site, 'https://foo.com');
    assert.equal(payload.from, 'branch/main');
    assert.equal(typeof payload.jti, 'string');
    assert.ok(payload.jti.length > 0, 'jti should be present for replay protection');
    assert.ok(payload.exp - payload.iat <= 10, 'TTL should be at most 10s');
});

test('signAuthRequest generates a fresh jti per call', async () => {
    const a = await signAuthRequest({ site: 'https://foo.com', from: '', handoffSecret: SECRET });
    const b = await signAuthRequest({ site: 'https://foo.com', from: '', handoffSecret: SECRET });
    const { payload: pa } = await jwtVerify(a, key, { algorithms: ['HS256'] });
    const { payload: pb } = await jwtVerify(b, key, { algorithms: ['HS256'] });
    assert.notEqual(pa.jti, pb.jti);
});
