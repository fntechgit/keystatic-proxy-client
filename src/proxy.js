// The Keystatic API routes a site answers itself when GitHub OAuth runs
// through the shared auth proxy, which holds the GitHub App's client secret.
// It uses only the Fetch API and WebCrypto, so it runs in any runtime that
// has them.
//
//   GET  /api/keystatic/github/login          -> redirects to the proxy's /authorize
//   GET  /api/keystatic/proxy/handoff         -> verifies the handoff JWS, writes the
//                                                Keystatic cookies, redirects to /keystatic
//   POST /api/keystatic/github/refresh-token  -> renews the tokens at the proxy's /refresh
//   GET  /api/keystatic/github/repo-not-found -> renews the tokens, then shows
//                                                Keystatic's repo-not-found page

import { SignJWT } from 'jose';
import { parse as parseCookies } from 'cookie';
import { encryptValue, decryptValue } from './crypto.js';
import { verifyHandoff, isValidFrom } from './handoff.js';
import { accessTokenCookie, refreshTokenCookie, REFRESH_TOKEN_COOKIE } from './cookies.js';

const enc = new TextEncoder();
const SIGNED_REQUEST_TTL_SEC = 10;
// The proxy refuses a refresh request signed with any other typ, so an auth
// request can't be replayed as one.
const REFRESH_REQUEST_TYP = 'keystatic-refresh+jwt';

// Sign a short-lived auth-request JWS proving the caller holds the shared
// handoff secret. The proxy uses this in lieu of an origin allowlist, so new
// consumer sites can be added without a proxy redeploy.
export async function signAuthRequest({ site, from, handoffSecret }) {
    return new SignJWT({ site, from, jti: crypto.randomUUID() })
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuedAt()
        .setExpirationTime(`${SIGNED_REQUEST_TTL_SEC}s`)
        .sign(enc.encode(handoffSecret));
}

// Sign a short-lived request for the proxy's POST /refresh, carrying the
// editor's refresh token. It goes server to server and never reaches the
// browser.
async function signRefreshRequest({ site, refreshToken, handoffSecret }) {
    return new SignJWT({ site, refresh_token: refreshToken, jti: crypto.randomUUID() })
        .setProtectedHeader({ alg: 'HS256', typ: REFRESH_REQUEST_TYP })
        .setIssuedAt()
        .setExpirationTime(`${SIGNED_REQUEST_TTL_SEC}s`)
        .sign(enc.encode(handoffSecret));
}

// Set-Cookie headers for a set of GitHub tokens, in Keystatic's own cookie
// format. Secure when the site is https: browsers drop Secure cookies on http.
async function tokenCookies(tokens, ctx) {
    const secure = new URL(ctx.site).protocol === 'https:';
    const encryptedRefresh = await encryptValue(tokens.refresh_token, ctx.secret);
    const headers = new Headers();
    headers.append('Set-Cookie', accessTokenCookie(tokens.access_token, tokens.expires_in, { secure }));
    headers.append('Set-Cookie', refreshTokenCookie(encryptedRefresh, tokens.refresh_token_expires_in, { secure }));
    return headers;
}

// Redeem the editor's refresh-token cookie at the proxy. Returns headers that
// set the new token cookies, or null when there is no usable cookie or the
// proxy does not renew it.
async function renewTokens(req, ctx) {
    const encrypted = parseCookies(req.headers.get('cookie') ?? '')[REFRESH_TOKEN_COOKIE];
    if (!encrypted) return null;
    const refreshToken = await decryptValue(encrypted, ctx.secret).catch(() => null);
    if (!refreshToken) return null;

    const signed = await signRefreshRequest({ site: ctx.site, refreshToken, handoffSecret: ctx.handoffSecret });
    const res = await fetch(`${ctx.proxyUrl}/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ req: signed })
    }).catch(() => null);
    if (!res?.ok) return null;

    const { token } = await res.json().catch(() => ({}));
    const data = await verifyHandoff(token, ctx.handoffSecret);
    if (!data || data.site !== ctx.site) return null;
    return tokenCookies(data, ctx);
}

async function login(req, ctx) {
    const rawFrom = new URL(req.url).searchParams.get('from');
    const jws = await signAuthRequest({
        site: ctx.site,
        from: isValidFrom(rawFrom) ? rawFrom : '',
        handoffSecret: ctx.handoffSecret
    });
    const dest = new URL(`${ctx.proxyUrl}/authorize`);
    dest.searchParams.set('req', jws);
    return Response.redirect(dest.toString(), 307);
}

async function handoff(req, ctx) {
    const data = await verifyHandoff(new URL(req.url).searchParams.get('token'), ctx.handoffSecret);
    if (!data) return new Response('Invalid handoff', { status: 400 });

    // Refuse handoffs intended for a different site (cross-site replay).
    if (data.site !== ctx.site) {
        return new Response('Handoff site mismatch', { status: 400 });
    }

    // `from` comes from the signed payload, not the URL, so the post-login
    // destination can't be tampered with after signing. Re-validate as defense
    // in depth even though the proxy already does.
    const from = isValidFrom(data.from) ? data.from : '';

    const headers = await tokenCookies(data, ctx);
    headers.set('Location', `/keystatic${from ? `/${from}` : ''}`);
    // Tokens arrived in the request URL; suppress referer so the destination
    // page can't read them via document.referrer.
    headers.set('Referrer-Policy', 'no-referrer');
    return new Response(null, { status: 307, headers });
}

// Keystatic's editor calls this when the access token has expired.
async function refresh(req, ctx) {
    const headers = await renewTokens(req, ctx);
    if (!headers) return new Response('Authorization failed', { status: 401 });
    return new Response(null, { status: 200, headers });
}

// Keystatic's editor sends the browser here when the signed-in user can't
// reach the repo. A renewed token carries any access granted since sign-in;
// without one, the editor signs in again.
async function repoNotFound(req, ctx) {
    const headers = await renewTokens(req, ctx);
    if (!headers) return login(req, ctx);
    headers.set('Location', '/keystatic/repo-not-found');
    return new Response(null, { status: 307, headers });
}

/**
 * Answer a proxy route, or return null for any other Keystatic route.
 *
 * @param {Request} req
 * @param {{ proxyUrl: string, handoffSecret: string, secret: string, site: string }} ctx
 *   `site` is this site's public origin; it is signed into the auth request and
 *   must match the handoff.
 * @returns {Promise<Response | null>}
 */
export async function handleProxyRoute(req, ctx) {
    const rest = new URL(req.url).pathname.replace(/^\/api\/keystatic\/?/, '');
    if (rest === 'github/login') return login(req, ctx);
    if (rest === 'proxy/handoff') return handoff(req, ctx);
    if (rest === 'github/refresh-token') return refresh(req, ctx);
    if (rest === 'github/repo-not-found') return repoNotFound(req, ctx);
    return null;
}
