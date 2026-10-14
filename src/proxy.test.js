// The proxy protocol: the routes the site answers itself (login, handoff,
// token refresh, repo-not-found), independent of any framework or runtime.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, jwtVerify } from 'jose';
import { signAuthRequest, handleProxyRoute } from './proxy.js';
import { encryptValue, decryptValue } from './crypto.js';
import { stubProxyRefresh } from './test-helpers.js';

const enc = new TextEncoder();
const HANDOFF_SECRET = 'handoff-' + 'a'.repeat(40);
const COOKIE_SECRET = 'cookie-' + 'b'.repeat(40);
const KEY = enc.encode(HANDOFF_SECRET);
const PROXY_URL = 'https://proxy.example';
const SITE = 'https://site.example';

const ctx = (site = SITE) => ({
    proxyUrl: PROXY_URL,
    handoffSecret: HANDOFF_SECRET,
    secret: COOKIE_SECRET,
    site
});

async function makeHandoff(claims, opts = {}) {
    return new SignJWT(claims)
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuedAt()
        .setExpirationTime(opts.exp || '60s')
        .sign(opts.key || KEY);
}

const handoffClaims = (overrides = {}) => ({
    site: SITE,
    from: 'branch/main/singleton/navbar',
    access_token: 'ghu_access',
    refresh_token: 'ghr_refresh',
    expires_in: 28800,
    refresh_token_expires_in: 15897600,
    ...overrides
});

function cookieNamed(response, name) {
    return response.headers.getSetCookie().find((c) => c.startsWith(`${name}=`));
}

test('signAuthRequest produces a JWS the proxy can verify with the same secret', async () => {
    const jws = await signAuthRequest({ site: SITE, from: 'branch/main', handoffSecret: HANDOFF_SECRET });
    assert.equal(jws.split('.').length, 3);
    const { payload } = await jwtVerify(jws, KEY, { algorithms: ['HS256'] });
    assert.equal(payload.site, SITE);
    assert.equal(payload.from, 'branch/main');
    assert.ok(payload.jti.length > 0, 'jti should be present for replay protection');
    assert.ok(payload.exp - payload.iat <= 10, 'TTL should be at most 10s');
});

test('signAuthRequest generates a fresh jti per call', async () => {
    const a = await signAuthRequest({ site: SITE, from: '', handoffSecret: HANDOFF_SECRET });
    const b = await signAuthRequest({ site: SITE, from: '', handoffSecret: HANDOFF_SECRET });
    const { payload: pa } = await jwtVerify(a, KEY, { algorithms: ['HS256'] });
    const { payload: pb } = await jwtVerify(b, KEY, { algorithms: ['HS256'] });
    assert.notEqual(pa.jti, pb.jti);
});

test('handleProxyRoute leaves every other Keystatic route alone', async () => {
    for (const path of ['/api/keystatic/github/logout', '/api/keystatic/github/oauth/callback', '/api/keystatic']) {
        assert.equal(await handleProxyRoute(new Request(`${SITE}${path}`), ctx()), null);
    }
});

test('login redirects to the proxy with a signed request for this site', async () => {
    const res = await handleProxyRoute(
        new Request(`${SITE}/api/keystatic/github/login?from=branch/main/singleton/navbar`),
        ctx()
    );
    assert.equal(res.status, 307);
    const dest = new URL(res.headers.get('Location'));
    assert.equal(dest.origin + dest.pathname, `${PROXY_URL}/authorize`);
    const { payload } = await jwtVerify(dest.searchParams.get('req'), KEY, { algorithms: ['HS256'] });
    assert.equal(payload.site, SITE);
    assert.equal(payload.from, 'branch/main/singleton/navbar');
});

test('login drops a `from` that is not an admin path', async () => {
    const res = await handleProxyRoute(
        new Request(`${SITE}/api/keystatic/github/login?from=//evil.example`),
        ctx()
    );
    const { payload } = await jwtVerify(
        new URL(res.headers.get('Location')).searchParams.get('req'),
        KEY,
        { algorithms: ['HS256'] }
    );
    assert.equal(payload.from, '');
});

test('handoff writes the Keystatic cookies and returns to the admin page', async () => {
    const token = await makeHandoff(handoffClaims());
    const res = await handleProxyRoute(
        new Request(`${SITE}/api/keystatic/proxy/handoff?token=${token}`),
        ctx()
    );
    assert.equal(res.status, 307);
    assert.equal(res.headers.get('Location'), '/keystatic/branch/main/singleton/navbar');
    assert.equal(res.headers.get('Referrer-Policy'), 'no-referrer');

    const access = cookieNamed(res, 'keystatic-gh-access-token');
    assert.match(access, /^keystatic-gh-access-token=ghu_access;/);
    assert.match(access, /Max-Age=28800/);
    assert.doesNotMatch(access, /HttpOnly/);

    const refresh = cookieNamed(res, 'keystatic-gh-refresh-token');
    assert.match(refresh, /HttpOnly/);
    const encrypted = refresh.split(';')[0].split('=')[1];
    assert.equal(await decryptValue(encrypted, COOKIE_SECRET), 'ghr_refresh');
});

test('handoff cookies are Secure on an https site and not on an http one', async () => {
    const https = await handleProxyRoute(
        new Request(`${SITE}/api/keystatic/proxy/handoff?token=${await makeHandoff(handoffClaims())}`),
        ctx()
    );
    for (const c of https.headers.getSetCookie()) assert.match(c, /; Secure/);

    const local = 'http://127.0.0.1:3000';
    const http = await handleProxyRoute(
        new Request(`${local}/api/keystatic/proxy/handoff?token=${await makeHandoff(handoffClaims({ site: local }))}`),
        ctx(local)
    );
    for (const c of http.headers.getSetCookie()) assert.doesNotMatch(c, /Secure/);
});

test('handoff rejects a token signed for another site', async () => {
    const token = await makeHandoff(handoffClaims({ site: 'https://other.example' }));
    const res = await handleProxyRoute(
        new Request(`${SITE}/api/keystatic/proxy/handoff?token=${token}`),
        ctx()
    );
    assert.equal(res.status, 400);
    assert.equal(res.headers.getSetCookie().length, 0);
});

test('handoff rejects a token that does not verify', async () => {
    const forged = await makeHandoff(handoffClaims(), { key: enc.encode('other-' + 'c'.repeat(40)) });
    for (const token of [forged, '', 'not.a.jwt']) {
        const res = await handleProxyRoute(
            new Request(`${SITE}/api/keystatic/proxy/handoff?token=${token}`),
            ctx()
        );
        assert.equal(res.status, 400);
    }
});

test('handoff ignores a `from` that is not an admin path', async () => {
    const token = await makeHandoff(handoffClaims({ from: '../../evil' }));
    const res = await handleProxyRoute(
        new Request(`${SITE}/api/keystatic/proxy/handoff?token=${token}`),
        ctx()
    );
    assert.equal(res.headers.get('Location'), '/keystatic');
});

const refreshCookie = async (token = 'ghr_old', secret = COOKIE_SECRET) =>
    `keystatic-gh-refresh-token=${await encryptValue(token, secret)}`;

const withCookie = (path, cookie, method = 'GET') =>
    new Request(`${SITE}/api/keystatic/${path}`, { method, headers: cookie ? { cookie } : {} });

async function refreshedCookies(response) {
    const access = cookieNamed(response, 'keystatic-gh-access-token');
    const refresh = cookieNamed(response, 'keystatic-gh-refresh-token');
    return {
        access: access.split(';')[0].split('=')[1],
        refresh: await decryptValue(refresh.split(';')[0].split('=')[1], COOKIE_SECRET),
        secure: [access, refresh].every((c) => /; Secure/.test(c))
    };
}

test('refresh-token renews through the proxy and writes fresh cookies', async (t) => {
    const requests = stubProxyRefresh(t, { handoffSecret: HANDOFF_SECRET });
    const res = await handleProxyRoute(withCookie('github/refresh-token', await refreshCookie(), 'POST'), ctx());
    assert.equal(res.status, 200);
    assert.deepEqual(await refreshedCookies(res), { access: 'ghu_new', refresh: 'ghr_new', secure: true });

    assert.equal(requests.length, 1);
    const [{ url, method, typ, payload }] = requests;
    assert.equal(url, `${PROXY_URL}/refresh`);
    assert.equal(method, 'POST');
    assert.equal(typ, 'keystatic-refresh+jwt');
    assert.equal(payload.site, SITE);
    assert.equal(payload.refresh_token, 'ghr_old');
    assert.ok(payload.jti.length > 0);
    assert.ok(payload.exp - payload.iat <= 10);
});

test('refresh-token answers 401 without asking the proxy when there is no usable cookie', async (t) => {
    const requests = stubProxyRefresh(t, { handoffSecret: HANDOFF_SECRET });
    for (const cookie of [undefined, await refreshCookie('ghr_old', 'other-' + 'c'.repeat(40)), 'keystatic-gh-refresh-token=garbage']) {
        const res = await handleProxyRoute(withCookie('github/refresh-token', cookie, 'POST'), ctx());
        assert.equal(res.status, 401);
        assert.equal(res.headers.getSetCookie().length, 0);
    }
    assert.equal(requests.length, 0);
});

test('refresh-token answers 401 when the proxy refuses or answers for another site', async (t) => {
    for (const reply of [{ status: 502 }, { handoff: { site: 'https://other.example' } }]) {
        t.mock.restoreAll();
        stubProxyRefresh(t, { handoffSecret: HANDOFF_SECRET, ...reply });
        const res = await handleProxyRoute(withCookie('github/refresh-token', await refreshCookie(), 'POST'), ctx());
        assert.equal(res.status, 401);
        assert.equal(res.headers.getSetCookie().length, 0);
    }
});

test("repo-not-found renews through the proxy, then shows Keystatic's page", async (t) => {
    stubProxyRefresh(t, { handoffSecret: HANDOFF_SECRET });
    const res = await handleProxyRoute(withCookie('github/repo-not-found', await refreshCookie()), ctx());
    assert.equal(res.status, 307);
    assert.equal(res.headers.get('Location'), '/keystatic/repo-not-found');
    assert.deepEqual(await refreshedCookies(res), { access: 'ghu_new', refresh: 'ghr_new', secure: true });
});

test('repo-not-found signs in again through the proxy when the token does not renew', async (t) => {
    stubProxyRefresh(t, { handoffSecret: HANDOFF_SECRET, status: 502 });
    const res = await handleProxyRoute(withCookie('github/repo-not-found', await refreshCookie()), ctx());
    assert.equal(res.status, 307);
    const dest = new URL(res.headers.get('Location'));
    assert.equal(dest.origin + dest.pathname, `${PROXY_URL}/authorize`);
});
