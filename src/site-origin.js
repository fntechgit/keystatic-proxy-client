// This site's origin from the request's Host and forwarding headers. Some
// hosts (Next.js dev, for one) rewrite the request URL to their own
// configured host, so the URL's origin is not always the one the browser
// used, and Keystatic moves the browser from localhost to 127.0.0.1.
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
