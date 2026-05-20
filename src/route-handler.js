// Wrapper around @keystatic/next's makeRouteHandler that routes the GitHub
// OAuth dance through a shared external auth proxy. The proxy holds the
// GitHub App's client secret; this handler only knows the proxy URL and a
// shared HMAC secret for verifying the proxy's handoff.
//
// Intercepted routes (only when proxy config is present):
//   GET /api/keystatic/github/login         -> redirects to proxy /authorize
//   GET /api/keystatic/proxy/handoff        -> verifies the handoff JWS,
//                                              writes Keystatic cookies,
//                                              redirects to /keystatic
//
// All other paths fall through to the upstream Keystatic handler unchanged.
// If proxy config is not provided, behavior is identical to calling
// makeRouteHandler directly.

import crypto from 'node:crypto';
import { SignJWT } from 'jose';
import { makeRouteHandler } from '@keystatic/next/route-handler';
import { encryptValue } from './crypto.js';
import { verifyHandoff, isValidFrom } from './handoff.js';
import { accessTokenCookie, refreshTokenCookie } from './cookies.js';

const enc = new TextEncoder();
const AUTH_REQUEST_TTL_SEC = 10;

// makeRouteHandler validates that GitHub-mode storage has clientId +
// clientSecret at construct time. In proxy mode those values are never
// actually read (our wrapper intercepts the OAuth routes), but the check
// still fires — so we pass these stable placeholders.
const PROXY_PLACEHOLDER_CREDS = { clientId: 'proxy-managed', clientSecret: 'proxy-managed' };

function resolveOptions(options = {}) {
    return {
        config: options.config,
        proxyUrl: options.proxyUrl ?? process.env.KEYSTATIC_AUTH_PROXY_URL,
        handoffSecret: options.handoffSecret ?? process.env.KEYSTATIC_AUTH_PROXY_HANDOFF_SECRET,
        secret: options.secret ?? process.env.KEYSTATIC_SECRET
    };
}

// Next dev rewrites req.url to its configured "Local:" host regardless of the
// actual Host header, so trusting reqUrl.origin breaks when the browser is on
// a different alias (e.g. Keystatic forces localhost → 127.0.0.1 via RFC 8252).
// Read the request's Host + protocol headers directly.
export function siteOriginFromRequest(req) {
    const forwardedHost = req.headers.get('x-forwarded-host');
    const host = forwardedHost ?? req.headers.get('host') ?? '';
    // Strip the optional :port. IPv6 hosts are bracketed (e.g. "[::1]:3000"),
    // so the port separator is the first colon AFTER the closing bracket.
    const hostname = host.startsWith('[')
        ? host.slice(0, host.indexOf(']') + 1)
        : host.split(':')[0];
    const isLoopback = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
    const proto = req.headers.get('x-forwarded-proto') ?? (isLoopback ? 'http' : 'https');
    return `${proto}://${host}`;
}

// Sign a short-lived auth-request JWS proving the caller holds the shared
// handoff secret. The proxy uses this in lieu of an origin allowlist, so new
// consumer sites can be added without a proxy redeploy.
export async function signAuthRequest({ site, from, handoffSecret }) {
    return new SignJWT({ site, from, jti: crypto.randomUUID() })
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuedAt()
        .setExpirationTime(`${AUTH_REQUEST_TTL_SEC}s`)
        .sign(enc.encode(handoffSecret));
}

async function handleProxyLogin(req, ctx) {
    const reqUrl = new URL(req.url);
    const rawFrom = reqUrl.searchParams.get('from');
    const from = isValidFrom(rawFrom) ? rawFrom : '';
    const jws = await signAuthRequest({
        site: siteOriginFromRequest(req),
        from,
        handoffSecret: ctx.handoffSecret
    });
    const dest = new URL(`${ctx.proxyUrl}/authorize`);
    dest.searchParams.set('req', jws);
    return Response.redirect(dest.toString(), 307);
}

async function handleProxyHandoff(req, ctx) {
    const url = new URL(req.url);
    const data = await verifyHandoff(url.searchParams.get('token'), ctx.handoffSecret);
    if (!data) return new Response('Invalid handoff', { status: 400 });

    // Refuse handoffs intended for a different site (cross-site replay).
    if (data.site !== siteOriginFromRequest(req)) {
        return new Response('Handoff site mismatch', { status: 400 });
    }

    const encryptedRefresh = await encryptValue(data.refresh_token, ctx.secret);

    // `from` comes from the signed payload, not the URL, so the post-login
    // destination can't be tampered with after signing. Re-validate as defense
    // in depth even though the proxy already does.
    const from = isValidFrom(data.from) ? data.from : '';
    const dest = `/keystatic${from ? `/${from}` : ''}`;

    const headers = new Headers();
    headers.append('Set-Cookie', accessTokenCookie(data.access_token, data.expires_in));
    headers.append('Set-Cookie', refreshTokenCookie(encryptedRefresh, data.refresh_token_expires_in));
    headers.set('Location', dest);
    // Tokens arrived in the request URL; suppress referer so the destination
    // page can't read them via document.referrer.
    headers.set('Referrer-Policy', 'no-referrer');
    return new Response(null, { status: 307, headers });
}

/**
 * Create a Next.js App Router route handler that wraps @keystatic/next's
 * makeRouteHandler. When proxy options are set (via params or env), GitHub
 * OAuth is routed through the configured external proxy instead of using
 * Keystatic's built-in OAuth handler.
 *
 * @param {object} options
 * @param {object} options.config            Keystatic config (required)
 * @param {string} [options.proxyUrl]        Proxy origin (default: env KEYSTATIC_AUTH_PROXY_URL)
 * @param {string} [options.handoffSecret]   Shared HMAC secret (default: env KEYSTATIC_AUTH_PROXY_HANDOFF_SECRET)
 * @param {string} [options.secret]          Cookie encryption secret (default: env KEYSTATIC_SECRET)
 * @returns {{GET: Function, POST: Function}}
 */
export function makeProxyAwareRouteHandler(options = {}) {
    const ctx = resolveOptions(options);
    if (!ctx.config) {
        throw new Error('makeProxyAwareRouteHandler requires a Keystatic config in options.config');
    }

    const proxyMode = Boolean(ctx.proxyUrl && ctx.handoffSecret && ctx.secret);

    const keystaticHandler = makeRouteHandler(
        proxyMode
            ? { config: ctx.config, ...PROXY_PLACEHOLDER_CREDS }
            : { config: ctx.config }
    );

    async function handle(req) {
        if (proxyMode) {
            const url = new URL(req.url);
            const rest = url.pathname.replace(/^\/api\/keystatic\/?/, '');
            if (rest === 'github/login') return handleProxyLogin(req, ctx);
            if (rest === 'proxy/handoff') return handleProxyHandoff(req, ctx);
        }
        return req.method === 'POST' ? keystaticHandler.POST(req) : keystaticHandler.GET(req);
    }

    return { GET: handle, POST: handle };
}
