// Software tests for the scanner. They exercise the code paths against a
// local loopback server (redirects, duplicate headers, compression, timeouts,
// TLS failures) and pure HTML parsing. They produce no research data.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import { fetchChain, decodeBody, CookieJar, type FetchOptions } from '../scanner/http.ts';
import { extractMetaCsp, extractLinkHosts, selectSubdomains, parseAttributes } from '../scanner/html.ts';
import { parseCsv, toCsv } from '../scanner/csv.ts';
import { accessClass, outsideDomain, mergeRuns, classify } from '../scanner/classify.ts';
import type { ScanRecord } from '../scanner/scan.ts';

const opts: FetchOptions = { userAgent: 'test', timeoutMs: 1500, maxBodyBytes: 64 * 1024 };

// ---------- HTML ----------

test('meta CSP: found in head, ignored after </head>, Report-Only flagged', () => {
  const html = `<html><head>
    <meta charset="utf-8">
    <META HTTP-EQUIV='Content-Security-Policy' CONTENT="script-src 'self'">
    <meta http-equiv="content-security-policy-report-only" content="default-src 'none'">
    </head><body><meta http-equiv="Content-Security-Policy" content="script-src *"></body></html>`;
  assert.deepEqual(extractMetaCsp(html), [
    { value: "script-src 'self'", reportOnly: false },
    { value: "default-src 'none'", reportOnly: true },
  ]);
});

test('meta CSP inside comments or scripts is not real', () => {
  const html = `<head><!-- <meta http-equiv="Content-Security-Policy" content="a"> -->
    <script>document.write('<meta http-equiv="Content-Security-Policy" content="b">')</script></head>`;
  assert.deepEqual(extractMetaCsp(html), []);
});

test('meta CSP content is entity-decoded', () => {
  const html = `<head><meta http-equiv="Content-Security-Policy" content="script-src &#39;self&#39; https://a.com"></head>`;
  assert.equal(extractMetaCsp(html)[0].value, "script-src 'self' https://a.com");
});

test('attributes: unquoted values and first-occurrence wins', () => {
  const a = parseAttributes('<a href=/x href="/y" target=_blank>');
  assert.equal(a.get('href'), '/x');
  assert.equal(a.get('target'), '_blank');
});

test('link hosts: relative, absolute, protocol-relative, <base>, non-http skipped', () => {
  const html = `<head><base href="https://cdn.ornek.com.tr/"></head>
    <a href="/a">x</a><a href="https://Shop.Ornek.com.tr/b">y</a><a href="//shop.ornek.com.tr/c">z</a>
    <a href="mailto:x@ornek.com.tr">m</a><a href="javascript:void(0)">j</a><a href="https://other.com">o</a>`;
  const c = extractLinkHosts(html, 'https://www.ornek.com.tr/');
  assert.equal(c.get('cdn.ornek.com.tr'), 1);
  assert.equal(c.get('shop.ornek.com.tr'), 2);
  assert.equal(c.get('other.com'), 1);
  assert.equal([...c.keys()].length, 3);
});

test('subdomain selection: own domain only, main hosts excluded, by links then name, capped', () => {
  const counts = new Map([
    ['www.ornek.com.tr', 50], ['ornek.com.tr', 3], ['b.ornek.com.tr', 5], ['a.ornek.com.tr', 5],
    ['c.ornek.com.tr', 9], ['evil-ornek.com.tr', 99], ['x.other.com', 7], ['m.ornek.com.tr', 1],
  ]);
  const s = selectSubdomains(counts, 'ornek.com.tr', ['m.ornek.com.tr'], 2);
  assert.deepEqual(s, [{ host: 'c.ornek.com.tr', links: 9 }, { host: 'a.ornek.com.tr', links: 5 }]);
});

// ---------- CSV ----------

test('CSV round trip with BOM, quotes, commas and Turkish characters', () => {
  const rows = [{ a: 'İstanbul, "Kadıköy"', b: true, c: null }];
  const text = toCsv(rows, ['a', 'b', 'c']);
  assert.ok(text.startsWith('﻿'));
  assert.deepEqual(parseCsv(text), [{ a: 'İstanbul, "Kadıköy"', b: '1', c: '' }]);
});

// ---------- HTTP against a loopback server ----------

const server = http.createServer((req, res) => {
  switch (req.url) {
    case '/r1': res.writeHead(301, { Location: '/r2' }); return res.end();
    case '/r2': res.writeHead(302, { Location: 'http://localhost:' + port() + '/ok' }); return res.end();
    case '/ok':
      // Two CSP headers and two cookies must both be kept.
      res.setHeader('Content-Security-Policy', ["script-src 'self'", "object-src 'none'"]);
      res.setHeader('Set-Cookie', ['a=1; HttpOnly', 'b=2; Secure']);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.end('<html><head><meta http-equiv="Content-Security-Policy" content="base-uri \'none\'"></head><body><a href="https://shop.ornek.com.tr/">s</a></body></html>');
    case '/gzip': {
      const body = zlib.gzipSync('<html><head><title>gz</title></head></html>');
      res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Encoding': 'gzip' });
      return res.end(body);
    }
    case '/big':
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('x'.repeat(200 * 1024));
    case '/json':
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end('{"a":1}');
    case '/loop': res.writeHead(302, { Location: '/loop' }); return res.end();
    case '/ftp': res.writeHead(302, { Location: 'ftp://example.org/' }); return res.end();
    case '/slow': return; // never answers
    default: res.writeHead(404); return res.end();
  }
});
await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
const port = () => (server.address() as AddressInfo).port;
const base = () => `http://127.0.0.1:${port()}`;
after(() => server.close());

test('redirect chain: every hop recorded, relative and absolute Location', async () => {
  const c = await fetchChain(`${base()}/r1`, opts);
  assert.equal(c.error, null);
  assert.deepEqual(c.hops.map(h => h.status), [301, 302, 200]);
  assert.equal(c.finalUrl, `http://localhost:${port()}/ok`);
});

test('duplicate headers are preserved as separate pairs', async () => {
  const c = await fetchChain(`${base()}/ok`, opts);
  const h = c.hops[0].headers;
  assert.equal(h.filter(([k]) => k.toLowerCase() === 'content-security-policy').length, 2);
  assert.equal(h.filter(([k]) => k.toLowerCase() === 'set-cookie').length, 2);
});

test('HTML body: hash recorded, html kept in memory only', async () => {
  const c = await fetchChain(`${base()}/ok`, opts);
  assert.match(c.body!.sha256, /^[0-9a-f]{64}$/);
  assert.ok(c.html!.includes('shop.ornek.com.tr'));
});

test('gzip body is decoded', async () => {
  const c = await fetchChain(`${base()}/gzip`, opts);
  assert.ok(c.html!.includes('<title>gz</title>'));
  assert.equal(c.body!.decodeError, null);
});

test('large body is cut at maxBodyBytes and marked truncated', async () => {
  const c = await fetchChain(`${base()}/big`, opts);
  assert.equal(c.body!.bytes, opts.maxBodyBytes);
  assert.equal(c.body!.truncated, true);
});

test('non-HTML 2xx: headers kept, body not read', async () => {
  const c = await fetchChain(`${base()}/json`, opts);
  assert.equal(c.finalStatus, 200);
  assert.equal(c.body, null);
});

test('redirect loop stops at the limit', async () => {
  const c = await fetchChain(`${base()}/loop`, opts, 3);
  assert.equal(c.error, 'TOO_MANY_REDIRECTS');
  assert.equal(c.hops.length, 4);
});

test('redirect to a non-HTTP scheme stops the chain', async () => {
  assert.equal((await fetchChain(`${base()}/ftp`, opts)).error, 'NON_HTTP_REDIRECT');
});

test('timeout is recorded after retries', { timeout: 20000 }, async () => {
  const c = await fetchChain(`${base()}/slow`, { ...opts, timeoutMs: 300 });
  assert.equal(c.error, 'TIMEOUT');
  assert.equal(c.hops[0].attempts, 3);
});

test('connection refused is recorded without hanging', async () => {
  const c = await fetchChain('http://127.0.0.1:1/', opts);
  assert.equal(c.error, 'ECONNREFUSED');
});

test('truncated gzip still decodes what arrived', () => {
  // Varied content, so that half of the compressed stream is real data.
  const page = '<html>' + Array.from({ length: 400 }, (_, i) => `<p>satır ${i} ${i * 7919 % 1000}</p>`).join('') + '</html>';
  const full = zlib.gzipSync(page);
  const r = decodeBody(full.subarray(0, Math.floor(full.length / 2)), 'gzip');
  assert.equal(r.error, null);
  assert.ok(r.text!.startsWith('<html><p>satır 0'));
  assert.ok(r.text!.length > 0 && r.text!.length < page.length);
});

// ---------- TLS: self-signed certificate (needs openssl; skipped otherwise) ----------

function selfSigned(): { key: string; cert: string } | null {
  try {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hl-'));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'), '-days', '1', '-subj', '/CN=127.0.0.1'], { stdio: 'ignore' });
    return { key: fs.readFileSync(path.join(dir, 'k.pem'), 'utf8'), cert: fs.readFileSync(path.join(dir, 'c.pem'), 'utf8') };
  } catch {
    return null;
  }
}
const pem = selfSigned();

test('TLS verification failure: recorded, then measured unverified', { skip: !pem && 'openssl not available' }, async () => {
  const tls = https.createServer(pem!, (_q, s) => { s.writeHead(200, { 'Strict-Transport-Security': 'max-age=31536000', 'Content-Type': 'text/html' }); s.end('<html></html>'); });
  await new Promise<void>(r => tls.listen(0, '127.0.0.1', r));
  try {
    const c = await fetchChain(`https://127.0.0.1:${(tls.address() as AddressInfo).port}/`, opts);
    const hop = c.hops[0];
    assert.equal(c.finalStatus, 200);
    assert.equal(hop.tls!.verified, false);
    assert.equal(hop.tls!.verifyError, 'DEPTH_ZERO_SELF_SIGNED_CERT');
    assert.ok(hop.headers.some(([k]) => k.toLowerCase() === 'strict-transport-security'));
  } finally {
    tls.close();
  }
});

// ---------- classification of raw records ----------

const hop = (url: string, status: number, headers: [string, string][] = []) =>
  ({ url, status, headers, tls: url.startsWith('https:') ? { protocol: 'TLSv1.3', cipher: 'x', verified: true, verifyError: null } : null, ms: 1, error: null, attempts: 1 });
const rec = (p: Partial<ScanRecord>): ScanRecord => ({
  schema: 1, run: 't', domain: 'ornek.com.tr', layer: 'main', host: 'ornek.com.tr', scheme: 'https', started: '', startUrl: '',
  hops: [], finalUrl: null, finalStatus: null, error: null, body: null, metaCsp: [], tool: { commit: 't', node: 't' }, ...p,
});

test('classify: HSTS from the first HTTPS response, other headers from the final one', () => {
  const recs = [
    rec({ scheme: 'http', hops: [hop('http://ornek.com.tr/', 301, [['Location', 'https://ornek.com.tr/']]), hop('https://ornek.com.tr/', 301), hop('https://www.ornek.com.tr/', 200)], finalUrl: 'https://www.ornek.com.tr/', finalStatus: 200 }),
    rec({
      scheme: 'https',
      hops: [hop('https://ornek.com.tr/', 301, [['Strict-Transport-Security', 'max-age=31536000; includeSubDomains']]), hop('https://www.ornek.com.tr/', 200, [['X-Frame-Options', 'DENY']])],
      finalUrl: 'https://www.ornek.com.tr/', finalStatus: 200, metaCsp: [{ value: "script-src 'self' 'unsafe-inline'", reportOnly: false }],
    }),
  ];
  const { main } = classify(recs, new Map([['ornek.com.tr', { alan_adi: 'ornek.com.tr', sektor: 'KAMU', alt_sektor: 'x', kaynak: 'crux_ilk1k' }]]));
  const r = main[0];
  assert.equal(r.erisim, 'ok');
  assert.equal(r.sektor, 'KAMU');
  assert.equal(r.http_https_yonlenir, true);
  assert.equal(r.hsts_guclu, true);
  assert.equal(r.xfo_dogru, true);
  assert.equal(r.csp_sinif, 'atlatilabilir');
  assert.equal(r.csp_kaynak, 'meta');
});

test('classify: unreachable site is kept as a row with the error', () => {
  const recs = [rec({ scheme: 'http', error: 'ENOTFOUND', hops: [] }), rec({ scheme: 'https', error: 'ENOTFOUND', hops: [] })];
  const { main } = classify(recs, new Map());
  assert.equal(main[0].erisim, 'ulasilamadi');
  assert.equal(main[0].hata, 'ENOTFOUND');
});

test('classify: bot challenge and refusals are "engellendi", other errors "hata" (C3)', () => {
  const challenge = [rec({ scheme: 'https', hops: [hop('https://ornek.com.tr/', 403, [['cf-mitigated', 'challenge'], ['X-Frame-Options', 'SAMEORIGIN']])], finalUrl: 'https://ornek.com.tr/', finalStatus: 403 })];
  const { main } = classify(challenge, new Map());
  assert.equal(main[0].erisim, 'engellendi');
  assert.equal(main[0].xfo_var, undefined, 'challenge page headers are not coded');

  const r400 = rec({ scheme: 'https', hops: [hop('https://ornek.com.tr/', 307), hop('https://www.ornek.com.tr/', 400)], finalUrl: 'https://www.ornek.com.tr/', finalStatus: 400 });
  assert.equal(accessClass([r400]), 'engellendi');
  const r404 = rec({ scheme: 'https', hops: [hop('https://ornek.com.tr/', 404)], finalUrl: 'https://ornek.com.tr/', finalStatus: 404 });
  assert.equal(accessClass([r404]), 'hata');
  const timeout = rec({ scheme: 'http', error: 'TIMEOUT', hops: [{ ...hop('http://ornek.com.tr/', 0), status: null, error: 'TIMEOUT' }] as never });
  assert.equal(accessClass([timeout, r404]), 'hata');
  assert.equal(accessClass([timeout]), 'ulasilamadi');
});

test('classify: a subdomain redirecting to another domain is flagged (C4)', () => {
  const recs = [
    rec({ scheme: 'https', hops: [hop('https://ornek.com.tr/', 200)], finalUrl: 'https://ornek.com.tr/', finalStatus: 200 }),
    rec({ layer: 'sub', host: 'e-bayi.ornek.com.tr', scheme: 'https', hops: [hop('https://e-bayi.ornek.com.tr/', 301), hop('https://ebayi.org/', 200)], finalUrl: 'https://ebayi.org/', finalStatus: 200 }),
    rec({ layer: 'sub', host: 'app.ornek.com.tr', scheme: 'https', hops: [hop('https://app.ornek.com.tr/', 200)], finalUrl: 'https://app.ornek.com.tr/', finalStatus: 200 }),
  ];
  const { main, sub } = classify(recs, new Map());
  assert.equal(main[0].alan_disi, false);
  assert.equal(sub.find(r => r.alt_alan === 'e-bayi.ornek.com.tr')!.alan_disi, true);
  assert.equal(sub.find(r => r.alt_alan === 'app.ornek.com.tr')!.alan_disi, false);
  assert.equal(outsideDomain('https://www.ornek.com.tr/x', 'ornek.com.tr'), false);
  assert.equal(outsideDomain('https://ornek.com/', 'ornek.com.tr'), true);
});

test('classify: challenge on https:// does not supply HSTS or hide HTTPS', () => {
  const recs = [
    rec({ scheme: 'http', hops: [hop('http://ornek.com.tr/', 301), hop('https://www.ornek.com.tr/', 200, [['Strict-Transport-Security', 'max-age=31536000']])], finalUrl: 'https://www.ornek.com.tr/', finalStatus: 200 }),
    rec({ scheme: 'https', hops: [hop('https://ornek.com.tr/', 403, [['cf-mitigated', 'challenge'], ['Strict-Transport-Security', 'max-age=60']])], finalUrl: 'https://ornek.com.tr/', finalStatus: 403 }),
  ];
  const r = classify(recs, new Map()).main[0];
  assert.equal(r.erisim, 'ok');
  assert.equal(r.https_erisilir, true);
  assert.equal(r.hsts_max_age, 31536000);
});

test('mergeRuns: a later run replaces all records of the domains it contains', () => {
  const a = [rec({ run: 'a', domain: 'x.com', scheme: 'http' }), rec({ run: 'a', domain: 'x.com', scheme: 'https' }), rec({ run: 'a', domain: 'x.com', layer: 'sub', host: 's.x.com' }), rec({ run: 'a', domain: 'y.com' })];
  const b = [rec({ run: 'b', domain: 'x.com', scheme: 'https' })];
  const m = mergeRuns([a, b]);
  assert.deepEqual(m.filter(r => r.domain === 'x.com').map(r => r.run), ['b']);
  assert.equal(m.filter(r => r.domain === 'y.com').length, 1);
  const rows = classify(m, new Map()).main;
  assert.equal(rows.find(r => r.alan_adi === 'x.com')!.olcum, 'b');
});

// ---------- C6, C7, C8 ----------

test('cookie jar: host-only, Domain, Secure and expiry (C7)', () => {
  const j = new CookieJar();
  j.store('https://a.ornek.com.tr/', ['h=1; Path=/', 'd=2; Domain=.ornek.com.tr; Secure', 'x=3; Domain=baska.com', 'h2=4']);
  assert.equal(j.header('https://a.ornek.com.tr/'), 'h=1; d=2; h2=4');
  assert.equal(j.header('https://b.ornek.com.tr/'), 'd=2');
  assert.equal(j.header('http://b.ornek.com.tr/'), null, 'Secure cookie not sent over http');
  j.store('https://a.ornek.com.tr/', ['h2=; Max-Age=0']);
  assert.equal(j.header('https://a.ornek.com.tr/'), 'h=1; d=2');
});

test('fetchChain keeps cookies within a chain: set-cookie + redirect to self resolves (C7)', async () => {
  const srv = http.createServer((q, s) => {
    if ((q.headers.cookie ?? '').includes('Ref=ok')) { s.writeHead(200, { 'Content-Type': 'text/html' }); s.end('<html></html>'); }
    else { s.writeHead(302, { 'Set-Cookie': 'Ref=ok; Path=/; HttpOnly', Location: '/' }); s.end(); }
  });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', r));
  try {
    const c = await fetchChain(`http://127.0.0.1:${(srv.address() as AddressInfo).port}/`, opts);
    assert.equal(c.error, null);
    assert.equal(c.finalStatus, 200);
    assert.equal(c.hops.length, 2);
    assert.deepEqual(c.hops[1].sentCookies, ['Ref']);
    assert.equal(c.hops[0].ip, '127.0.0.1');
  } finally {
    srv.close();
  }
});

test('classify: www records replace a silent bare domain (C6)', () => {
  const silent = (scheme: 'http' | 'https') => rec({ scheme, error: 'ENOTFOUND', hops: [{ ...hop(`${scheme}://ornek.com.tr/`, 0), status: null, error: 'ENOTFOUND' }] as never });
  const recs = [
    silent('http'), silent('https'),
    rec({ host: 'www.ornek.com.tr', scheme: 'http', hops: [hop('http://www.ornek.com.tr/', 301), hop('https://www.ornek.com.tr/', 200)], finalUrl: 'https://www.ornek.com.tr/', finalStatus: 200 }),
    rec({ host: 'www.ornek.com.tr', scheme: 'https', hops: [hop('https://www.ornek.com.tr/', 200, [['Strict-Transport-Security', 'max-age=31536000']])], finalUrl: 'https://www.ornek.com.tr/', finalStatus: 200 }),
  ];
  const r = classify(recs, new Map()).main[0];
  assert.equal(r.erisim, 'ok');
  assert.equal(r.www_yedek, true);
  assert.equal(r.hsts_max_age, 31536000);
});

test('classify: ISP filter page, and TLS failure at the filter address, are iss_filtresi (C8)', () => {
  const f = (domain: string, p: Partial<ScanRecord>) => rec({ domain, host: domain, ...p });
  const recs = [
    f('a.com', { scheme: 'http', hops: [{ ...hop('http://a.com/', 302, [['Location', 'https://guvenliinternet.turktelekom.com.tr/?host=a.com']]), ip: '195.175.254.2' }, hop('https://guvenliinternet.turktelekom.com.tr/?host=a.com', 200)], finalUrl: 'https://guvenliinternet.turktelekom.com.tr/?host=a.com', finalStatus: 200 }),
    f('b.com', { scheme: 'https', error: 'EPROTO', hops: [{ ...hop('https://b.com/', 0), status: null, error: 'EPROTO', ip: '195.175.254.2' }] as never }),
    f('c.com', { scheme: 'https', hops: [{ ...hop('https://c.com/', 200), ip: '93.184.216.34' }], finalUrl: 'https://c.com/', finalStatus: 200 }),
  ];
  const rows = classify(recs, new Map()).main;
  assert.equal(rows.find(r => r.alan_adi === 'a.com')!.erisim, 'iss_filtresi');
  assert.equal(rows.find(r => r.alan_adi === 'b.com')!.erisim, 'iss_filtresi');
  assert.equal(rows.find(r => r.alan_adi === 'c.com')!.erisim, 'ok');
});
