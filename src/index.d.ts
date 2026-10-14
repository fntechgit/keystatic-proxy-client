import type { Config } from '@keystatic/core';

export interface MakeProxyAwareHandlerOptions {
    /** Keystatic config (required). */
    config: Config<any, any>;
    /** Origin of the auth proxy. */
    proxyUrl?: string;
    /** HMAC key shared with the proxy, for its signed requests and handoffs. */
    handoffSecret?: string;
    /** Cookie encryption key, at least 32 characters (Keystatic's KEYSTATIC_SECRET). */
    secret?: string;
    /** This site's public origin. Defaults to the request URL's origin. */
    siteOrigin?: (req: Request) => string;
}

/**
 * Create a Keystatic API handler for any host that speaks the Fetch API.
 * Mount it on `/api/keystatic/*`. When `proxyUrl`, `handoffSecret` and
 * `secret` are all set, GitHub sign-in and token refresh go through the
 * shared auth proxy; every other route, and every route when they are
 * missing, is Keystatic's own handler.
 */
export function makeProxyAwareHandler(options: MakeProxyAwareHandlerOptions): (req: Request) => Promise<Response>;

/**
 * This site's origin from the Host (or X-Forwarded-Host) and
 * X-Forwarded-Proto headers, for hosts that rewrite the request URL. Pass it
 * as `siteOrigin`. Loopback hosts default to http, others to https.
 */
export function siteOriginFromRequest(req: Request): string;
