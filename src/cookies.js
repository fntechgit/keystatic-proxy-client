import { serialize } from 'cookie';

// Cookie names mirror @keystatic/core's internal token cookies so the
// admin UI reads them as if Keystatic's own callback handler had set them.
export const ACCESS_TOKEN_COOKIE = 'keystatic-gh-access-token';
export const REFRESH_TOKEN_COOKIE = 'keystatic-gh-refresh-token';

const expiresAt = (seconds) => new Date(Date.now() + seconds * 1000);

// `secure` follows the site's protocol: browsers drop Secure cookies on http.
export function accessTokenCookie(token, expiresInSeconds, { secure }) {
    return serialize(ACCESS_TOKEN_COOKIE, token, {
        path: '/',
        sameSite: 'lax',
        secure,
        maxAge: expiresInSeconds,
        expires: expiresAt(expiresInSeconds)
    });
}

export function refreshTokenCookie(encrypted, expiresInSeconds, { secure }) {
    return serialize(REFRESH_TOKEN_COOKIE, encrypted, {
        path: '/',
        sameSite: 'lax',
        httpOnly: true,
        secure,
        maxAge: expiresInSeconds,
        expires: expiresAt(expiresInSeconds)
    });
}
