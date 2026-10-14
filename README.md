# keystatic-proxy-client

Keystatic API handler that lets a site authenticate editors through a shared
GitHub OAuth proxy instead of registering its own GitHub App. It runs in any
host that speaks the Fetch API, Next.js route handlers included.

Pairs with [keystatic-auth-proxy](https://github.com/fntechgit/keystatic-auth-proxy).

## Why

[Keystatic](https://keystatic.com) in GitHub-storage mode wants each site to
register its own GitHub App and configure five env vars. This handler
delegates the OAuth code exchange and token refresh to a shared proxy, so a
site only needs three settings (proxy URL + two secrets) and no per-site
GitHub App.

## Install

```bash
pnpm add keystatic-proxy-client
```

Peer dependency: `@keystatic/core`.

## Usage

`makeProxyAwareHandler` returns a `(Request) => Promise<Response>` handler.
Mount it on `/api/keystatic/*` and pass three settings:

| Option | Purpose |
|---|---|
| `proxyUrl` | Origin of the deployed auth proxy |
| `handoffSecret` | HMAC key shared with the proxy, for its signed requests and handoffs |
| `secret` | Cookie encryption key, at least 32 characters (same scheme as Keystatic's `KEYSTATIC_SECRET`) |

When all three are set, sign-in and token refresh go through the proxy. When
any is missing, the handler is Keystatic's own API handler, unchanged (useful
with local storage in development). The handler reads no environment
variables: read them where you create it.

### Next.js

`app/api/keystatic/[...params]/route.js`:

```js
import { makeProxyAwareHandler, siteOriginFromRequest } from 'keystatic-proxy-client';
import keystaticConfig from '../../../../keystatic.config';

const handler = makeProxyAwareHandler({
  config: keystaticConfig,
  proxyUrl: process.env.KEYSTATIC_AUTH_PROXY_URL,
  handoffSecret: process.env.KEYSTATIC_AUTH_PROXY_HANDOFF_SECRET,
  secret: process.env.KEYSTATIC_SECRET,
  siteOrigin: siteOriginFromRequest
});

export { handler as GET, handler as POST };
```

Next.js dev rewrites the request URL to its own configured host, so the
URL's origin is not always the one the browser used. `siteOriginFromRequest`
reads the origin from the Host and forwarding headers instead.

### Other Fetch API hosts

```js
import { makeProxyAwareHandler } from 'keystatic-proxy-client';
import keystaticConfig from './keystatic.config';

const keystatic = makeProxyAwareHandler({
  config: keystaticConfig,
  proxyUrl: env.KEYSTATIC_AUTH_PROXY_URL,
  handoffSecret: env.KEYSTATIC_AUTH_PROXY_HANDOFF_SECRET,
  secret: env.KEYSTATIC_SECRET
});

// For every request under /api/keystatic/*:
return keystatic(request);
```

The site's origin defaults to the request URL's origin. Pass
`siteOrigin: (req) => '...'` when the host sees a different URL than the
browser.

Cookies are `Secure` when the site origin is https.

## How it works

The handler answers four routes itself when proxy mode is active:

- `GET /api/keystatic/github/login` — signs a short-lived JWS containing
  `{site, from, jti}` with the shared handoff secret and redirects to the
  proxy's `/authorize?req=<jws>`. The proxy verifies the signature to gate
  access (no origin allowlist), so adding new consumer sites doesn't require
  a proxy redeploy.
- `GET /api/keystatic/proxy/handoff` — receives the proxy's signed JWS
  carrying access + refresh tokens, verifies it, then writes the same
  `keystatic-gh-access-token` and (AES-GCM-encrypted)
  `keystatic-gh-refresh-token` cookies Keystatic's own callback handler
  would have written. The Keystatic admin UI sees no difference.
- `POST /api/keystatic/github/refresh-token` — called by the admin UI when
  the access token expires. Decrypts the refresh-token cookie,
  POSTs a short-lived JWS carrying it (`typ: keystatic-refresh+jwt`) to the
  proxy's `/refresh`, verifies the handoff JWS the proxy answers with, and
  writes fresh cookies. Answers 401 when there is nothing to renew, so the
  admin UI shows its sign-in button.
- `GET /api/keystatic/github/repo-not-found` — the admin UI sends the
  browser here when the user can't reach the repo. Renews the tokens as
  above, then redirects to Keystatic's repo-not-found page, or signs in
  again through the proxy when renewal fails.

All other paths fall through to Keystatic's own handler unchanged.

## Security model

- The site never holds the GitHub App's client secret.
- Handoff is a signed JWS (HS256, `jose`) with `exp` and a `site` claim;
  the site rejects handoffs with the wrong origin or past expiry.
- `from` (post-login redirect destination) is validated against the
  Keystatic admin-path regex and rejected if it contains `..` — guards
  against open-redirect abuse.
- `Referrer-Policy: no-referrer` on the handoff redirect so the JWS in
  the URL can't leak via `document.referrer`.
- Token refresh runs server to server: the refresh token travels to the
  proxy only in the body of a signed POST, never through the browser.
- The cookie encryption key (`KEYSTATIC_SECRET`) stays on the site and is
  never sent to the proxy. Refresh tokens are re-encrypted before being
  written to cookies, so the proxy never holds long-lived per-editor state.

## Tests

```bash
pnpm test
```

Regression suite covers handoff JWS round-trip, signature tampering,
expired token, `alg=none` confusion, `from` path-traversal rejection,
cookie crypto in both directions against upstream Keystatic's own handler,
the login, handoff, token refresh and repo-not-found routes, the site-origin
helper, and a guard that the package source uses no Node-only APIs.

## License

MIT
