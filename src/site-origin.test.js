// siteOriginFromRequest reads the site origin from the Host and forwarding
// headers, for hosts whose request URL is not the one the browser used.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { siteOriginFromRequest } from './site-origin.js';

const request = (headers, url = 'http://stale-host/x') => new Request(url, { headers });

test('uses the Host header, not the request URL', () => {
    const req = request({ host: '127.0.0.1:3000' }, 'http://localhost:3000/api/keystatic/github/login');
    assert.equal(siteOriginFromRequest(req), 'http://127.0.0.1:3000');
});

test('defaults loopback hosts to http', () => {
    for (const host of ['localhost:3000', '127.0.0.1:3000', '[::1]:3000']) {
        assert.equal(siteOriginFromRequest(request({ host })), `http://${host}`);
    }
});

test('defaults other hosts to https', () => {
    assert.equal(siteOriginFromRequest(request({ host: 'site.example' })), 'https://site.example');
});

test('honors x-forwarded-proto', () => {
    const req = request({ host: '127.0.0.1:3000', 'x-forwarded-proto': 'https' });
    assert.equal(siteOriginFromRequest(req), 'https://127.0.0.1:3000');
});

test('prefers x-forwarded-host over host', () => {
    const req = request({ host: 'internal-lb:8080', 'x-forwarded-host': 'site.example', 'x-forwarded-proto': 'https' });
    assert.equal(siteOriginFromRequest(req), 'https://site.example');
});
