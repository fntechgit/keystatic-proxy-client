# keystatic-proxy-client

Site-side wrapper that lets a Next.js Keystatic site authenticate editors
through a shared FN OAuth proxy instead of registering its own GitHub App.

Pairs with [keystatic-auth-proxy](https://github.com/fntechgit/keystatic-auth-proxy).

## Why

[Keystatic](https://keystatic.com) in GitHub-storage mode wants each site to
register its own GitHub App and configure five env vars. This wrapper
delegates the OAuth code exchange to a shared proxy so a site only needs
three env vars (proxy URL + two secrets) and no per-site GitHub App.

## Install

```bash
pnpm add keystatic-proxy-client
```

Peer deps assumed already installed: `@keystatic/next`, `next`.

## Usage

In `app/api/keystatic/[[...params]]/route.js`:

```js
import { makeProxyAwareRouteHandler } from 'keystatic-proxy-client';
import keystaticConfig from '../../../../keystatic.config';

export const { GET, POST } = makeProxyAwareRouteHandler({ config: keystaticConfig });
```

The wrapper reads three env vars (or accepts them as options):

| Env var | Option key | Purpose |
|---|---|---|
| `KEYSTATIC_AUTH_PROXY_URL` | `proxyUrl` | Origin of the deployed auth proxy |
| `KEYSTATIC_AUTH_PROXY_HANDOFF_SECRET` | `handoffSecret` | HMAC key for verifying the proxy's handoff JWS |
| `KEYSTATIC_SECRET` | `secret` | Cookie encryption key (same scheme as upstream Keystatic) |

When all three are present, GitHub OAuth routes through the proxy. When any
is missing, behavior is identical to calling Keystatic's `makeRouteHandler`
directly (useful for local-mode dev).

### Programmatic config

```js
makeProxyAwareRouteHandler({
  config: keystaticConfig,
  proxyUrl: 'https://keystatic-auth-proxy.netlify.app',
  handoffSecret: process.env.MY_HANDOFF_SECRET,
  secret: process.env.MY_KEYSTATIC_SECRET
});
```

## How it works

The wrapper intercepts two routes when proxy mode is active:

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

All other paths fall through to `makeRouteHandler` unchanged.

## Security model

- The site never holds the GitHub App's client secret.
- Handoff is a signed JWS (HS256, `jose`) with `exp` and a `site` claim;
  the site rejects handoffs with the wrong origin or past expiry.
- `from` (post-login redirect destination) is validated against the
  Keystatic admin-path regex and rejected if it contains `..` — guards
  against open-redirect abuse.
- `Referrer-Policy: no-referrer` on the handoff redirect so the JWS in
  the URL can't leak via `document.referrer`.
- The cookie encryption key (`KEYSTATIC_SECRET`) stays on the site and is
  never sent to the proxy. Refresh tokens are re-encrypted before being
  written to cookies, so the proxy never holds long-lived per-editor state.

## Tests

```bash
pnpm test
```

Regression suite covers handoff JWS round-trip, signature tampering,
expired token, `alg=none` confusion, `from` path-traversal rejection, and
cookie crypto round-trip against upstream Keystatic's scheme.

## License

MIT
