import { serialize } from 'cookie';

// Cookie names mirror @keystatic/core's internal token cookies so the
// admin UI reads them as if Keystatic's own callback handler had set them.
export const ACCESS_TOKEN_COOKIE = 'keystatic-gh-access-token';
export const REFRESH_TOKEN_COOKIE = 'keystatic-gh-refresh-token';

const isSecure = () => process.env.NODE_ENV === 'production';
const expiresAt = (seconds) => new Date(Date.now() + seconds * 1000);

export function accessTokenCookie(token, expiresInSeconds) {
    return serialize(ACCESS_TOKEN_COOKIE, token, {
        path: '/',
        sameSite: 'lax',
        secure: isSecure(),
        maxAge: expiresInSeconds,
        expires: expiresAt(expiresInSeconds)
    });
}

export function refreshTokenCookie(encrypted, expiresInSeconds) {
    return serialize(REFRESH_TOKEN_COOKIE, encrypted, {
        path: '/',
        sameSite: 'lax',
        httpOnly: true,
        secure: isSecure(),
        maxAge: expiresInSeconds,
        expires: expiresAt(expiresInSeconds)
    });
}
