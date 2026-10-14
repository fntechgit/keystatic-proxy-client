// Keystatic API handler for any host that speaks the Fetch API:
// (Request) => Promise<Response>. GitHub sign-in and token refresh go through
// the shared auth proxy when the proxy settings are present; every other
// route is Keystatic's own handler.

import { makeGenericAPIRouteHandler } from '@keystatic/core/api/generic';
import { handleProxyRoute } from './proxy.js';

// Keystatic requires GitHub App credentials for GitHub storage. In proxy mode
// the site never holds them, because sign-in and token refresh go through the
// proxy. Keystatic still sends these placeholders to GitHub when it revokes a
// token on logout; GitHub refuses them, and logout clears the cookies anyway.
const PROXY_PLACEHOLDER_CREDS = { clientId: 'proxy-managed', clientSecret: 'proxy-managed' };

const requestOrigin = (req) => new URL(req.url).origin;

/**
 * @param {object} options
 * @param {object} options.config              Keystatic config (required)
 * @param {string} [options.proxyUrl]          Auth proxy origin
 * @param {string} [options.handoffSecret]     Shared HMAC secret for the proxy's JWS
 * @param {string} [options.secret]            Cookie encryption secret (KEYSTATIC_SECRET)
 * @param {(req: Request) => string} [options.siteOrigin]
 *   This site's public origin; defaults to the request URL's origin.
 * @returns {(req: Request) => Promise<Response>}
 */
export function makeProxyAwareHandler({ config, proxyUrl, handoffSecret, secret, siteOrigin = requestOrigin } = {}) {
    if (!config) {
        throw new Error('makeProxyAwareHandler requires a Keystatic config in options.config');
    }

    const proxyMode = Boolean(proxyUrl && handoffSecret && secret);
    const keystatic = makeGenericAPIRouteHandler(
        proxyMode ? { config, secret, ...PROXY_PLACEHOLDER_CREDS } : { config, secret }
    );

    return async function handle(req) {
        if (proxyMode) {
            const proxied = await handleProxyRoute(req, { proxyUrl, handoffSecret, secret, site: siteOrigin(req) });
            if (proxied) return proxied;
        }
        const { body, headers, status } = await keystatic(req);
        return new Response(body, { status, headers });
    };
}
