// makeProxyAwareHandler: one (Request) => Promise<Response> handler for any
// host that speaks the Fetch API.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { jwtVerify } from 'jose';
import { config } from '@keystatic/core';
import * as api from './index.js';
import { encryptValue } from './crypto.js';
import { stubProxyRefresh } from './test-helpers.js';

const { makeProxyAwareHandler, siteOriginFromRequest } = api;

const HANDOFF_SECRET = 'handoff-' + 'a'.repeat(40);
const COOKIE_SECRET = 'cookie-' + 'b'.repeat(40);
const keystaticConfig = config({ storage: { kind: 'github', repo: 'owner/repo' } });

const proxied = (overrides = {}) =>
    makeProxyAwareHandler({
        config: keystaticConfig,
        proxyUrl: 'https://proxy.example',
        handoffSecret: HANDOFF_SECRET,
        secret: COOKIE_SECRET,
        ...overrides
    });

async function signedSite(response) {
    const req = new URL(response.headers.get('Location')).searchParams.get('req');
    const { payload } = await jwtVerify(req, new TextEncoder().encode(HANDOFF_SECRET), { algorithms: ['HS256'] });
    return payload.site;
}

test('the package exports the handler and the site-origin helper', () => {
    assert.deepEqual(Object.keys(api).sort(), ['makeProxyAwareHandler', 'siteOriginFromRequest']);
});

test('login goes through the proxy, signed for the request origin', async () => {
    const res = await proxied()(new Request('https://site.example:8443/api/keystatic/github/login'));
    assert.equal(res.status, 307);
    assert.equal(await signedSite(res), 'https://site.example:8443');
});

test('a siteOrigin option overrides the request origin', async () => {
    const handle = proxied({ siteOrigin: () => 'https://public.example' });
    const res = await handle(new Request('http://internal:8080/api/keystatic/github/login'));
    assert.equal(await signedSite(res), 'https://public.example');
});

test('with siteOriginFromRequest, login is signed for the Host the browser used', async () => {
    const handle = proxied({ siteOrigin: siteOriginFromRequest });
    const res = await handle(
        new Request('http://localhost:3000/api/keystatic/github/login', { headers: { host: '127.0.0.1:3000' } })
    );
    assert.equal(await signedSite(res), 'http://127.0.0.1:3000');
});

test('token refresh goes through the proxy', async (t) => {
    const requests = stubProxyRefresh(t, { handoffSecret: HANDOFF_SECRET });
    const res = await proxied()(
        new Request('https://site.example/api/keystatic/github/refresh-token', {
            method: 'POST',
            headers: { cookie: `keystatic-gh-refresh-token=${await encryptValue('ghr_old', COOKIE_SECRET)}` }
        })
    );
    assert.equal(res.status, 200);
    assert.equal(requests[0].url, 'https://proxy.example/refresh');
});

test("other routes reach Keystatic's own handler as a Response", async () => {
    const res = await proxied()(new Request('https://site.example/api/keystatic/github/logout'));
    assert.ok(res instanceof Response);
    assert.equal(res.status, 307);
    assert.equal(res.headers.get('Location'), '/keystatic');
});

test('without proxy settings, login is left to Keystatic', async (t) => {
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';
    t.after(() => {
        process.env.NODE_ENV = previous;
    });
    const handle = makeProxyAwareHandler({ config: keystaticConfig, secret: COOKIE_SECRET });
    const res = await handle(new Request('https://site.example/api/keystatic/github/login'));
    assert.equal(res.status, 307);
    assert.equal(res.headers.get('Location'), '/keystatic/setup');
});

test('requires a Keystatic config', () => {
    assert.throws(() => makeProxyAwareHandler({}), /config/);
});

test('the package source uses no Node-only APIs', () => {
    for (const file of ['index.js', 'handler.js', 'site-origin.js', 'proxy.js', 'crypto.js', 'cookies.js', 'handoff.js']) {
        const source = readFileSync(new URL(file, import.meta.url), 'utf8');
        assert.doesNotMatch(source, /from 'node:|require\(|\bBuffer\b|\bprocess\./, file);
    }
});
