import type { Config } from '@keystatic/core';

export interface MakeProxyAwareRouteHandlerOptions {
    /** Keystatic config (required). */
    config: Config<any, any>;
    /** Proxy origin. Defaults to `process.env.KEYSTATIC_AUTH_PROXY_URL`. */
    proxyUrl?: string;
    /** Shared HMAC secret. Defaults to `process.env.KEYSTATIC_AUTH_PROXY_HANDOFF_SECRET`. */
    handoffSecret?: string;
    /** Cookie encryption secret. Defaults to `process.env.KEYSTATIC_SECRET`. */
    secret?: string;
}

export interface ProxyAwareRouteHandler {
    GET: (req: Request) => Promise<Response>;
    POST: (req: Request) => Promise<Response>;
}

/**
 * Create a Next.js App Router route handler that wraps `@keystatic/next`'s
 * `makeRouteHandler`. When proxy options are set (via params or env), GitHub
 * OAuth is routed through the configured external proxy instead of using
 * Keystatic's built-in OAuth handler. When proxy options are missing, behavior
 * is identical to calling `makeRouteHandler` directly (useful for local-mode dev).
 */
export function makeProxyAwareRouteHandler(
    options: MakeProxyAwareRouteHandlerOptions
): ProxyAwareRouteHandler;
