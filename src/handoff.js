import { jwtVerify } from 'jose';

const enc = new TextEncoder();

/**
 * Verify a handoff JWS issued by the proxy. Returns the decoded claims on
 * success (including site, from, access_token, refresh_token, expires_in,
 * refresh_token_expires_in, iat, exp), or null on any failure (bad alg, bad
 * signature, expired, missing).
 */
export async function verifyHandoff(token, secret) {
    if (typeof token !== 'string' || !token || typeof secret !== 'string' || !secret) return null;
    try {
        const { payload } = await jwtVerify(token, enc.encode(secret), { algorithms: ['HS256'] });
        return payload;
    } catch {
        return null;
    }
}

// Keystatic's internal regex for valid post-login redirect paths. Restricts
// `from` to the admin route shapes so an attacker can't use the proxy to
// bounce users to arbitrary URLs.
export const keystaticPathRegex = /^branch\/[^]+(\/collection\/[^/]+(|\/(create|item\/[^/]+))|\/singleton\/[^/]+)?$/;

// True when `from` matches the admin-path regex AND contains no path-traversal
// segment. Branch names may legitimately contain `/`, so we can't restrict the
// branch segment to a single component; we just refuse anything with `..`.
export function isValidFrom(s) {
    if (typeof s !== 'string' || s.length === 0) return false;
    if (s.includes('..')) return false;
    return keystaticPathRegex.test(s);
}
