// A stand-in for the auth proxy's POST /refresh: it verifies the signed
// refresh request and answers with a handoff JWS carrying new tokens.

import { SignJWT, jwtVerify } from 'jose';

export function stubProxyRefresh(t, { handoffSecret, status = 200, handoff = {} }) {
    const key = new TextEncoder().encode(handoffSecret);
    const requests = [];
    t.mock.method(globalThis, 'fetch', async (url, init) => {
        const { payload, protectedHeader } = await jwtVerify(JSON.parse(init.body).req, key, {
            algorithms: ['HS256']
        });
        requests.push({ url: String(url), method: init.method, typ: protectedHeader.typ, payload });
        if (status !== 200) return new Response('refused', { status });
        const token = await new SignJWT({
            site: payload.site,
            access_token: 'ghu_new',
            expires_in: 28800,
            refresh_token: 'ghr_new',
            refresh_token_expires_in: 15897600,
            ...handoff
        })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setIssuedAt()
            .setExpirationTime('60s')
            .sign(key);
        return Response.json({ token });
    });
    return requests;
}
