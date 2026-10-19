// Criteria set v1 — header validity and 2016 comparability tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateHeadersV1, type HeaderMap } from '../criteria/headers-v1.ts';

const run = (headers: HeaderMap, url = 'https://ornek.com.tr/', metaCsp?: string[]) =>
  evaluateHeadersV1({ url, headers, metaCsp });

// ---------- HSTS (K4) ----------

test('HSTS: 6 months is doğru, not güçlü', () => {
  const r = run({ 'strict-transport-security': ['max-age=15768000'] });
  assert.equal(r.hsts_dogru, true);
  assert.equal(r.hsts_guclu, false);
});

test('HSTS: 1 year + includeSubDomains is güçlü', () => {
  const r = run({ 'strict-transport-security': ['max-age=31536000; includeSubDomains; preload'] });
  assert.equal(r.hsts_guclu, true);
  assert.equal(r.hsts_preload, true);
});

test('HSTS: 1 year without includeSubDomains is not güçlü', () => {
  assert.equal(run({ 'strict-transport-security': ['max-age=31536000'] }).hsts_guclu, false);
});

test('HSTS: short max-age is present but not doğru', () => {
  const r = run({ 'strict-transport-security': ['max-age=86400'] });
  assert.equal(r.hsts_var, true);
  assert.equal(r.hsts_dogru, false);
});

test('HSTS: case-insensitive name and quoted value (RFC 6797)', () => {
  const r = run({ 'strict-transport-security': ['MAX-AGE="31536000"; INCLUDESUBDOMAINS'] });
  assert.equal(r.hsts_max_age, 31536000);
  assert.equal(r.hsts_guclu, true);
});

test('HSTS over plain HTTP is ignored', () => {
  const r = run({ 'strict-transport-security': ['max-age=31536000'] }, 'http://ornek.com.tr/');
  assert.equal(r.hsts_var, false);
});

// ---------- clickjacking ----------

test('X-Frame-Options: DENY and SAMEORIGIN are doğru, any case', () => {
  assert.equal(run({ 'x-frame-options': ['deny'] }).xfo_dogru, true);
  assert.equal(run({ 'x-frame-options': ['SAMEORIGIN'] }).xfo_dogru, true);
});

test('X-Frame-Options: ALLOW-FROM is present but not doğru', () => {
  const r = run({ 'x-frame-options': ['ALLOW-FROM https://a.com'] });
  assert.equal(r.xfo_var, true);
  assert.equal(r.xfo_dogru, false);
});

test('X-Frame-Options: conflicting values are not doğru', () => {
  assert.equal(run({ 'x-frame-options': ['DENY, SAMEORIGIN'] }).xfo_dogru, false);
});

test("clickjacking: CSP frame-ancestors 'self' protects without XFO", () => {
  const r = run({ 'content-security-policy': ["frame-ancestors 'self'"] });
  assert.equal(r.xfo_var, false);
  assert.equal(r.clickjacking_korumasi, true);
});

test('clickjacking: frame-ancestors * does not protect', () => {
  assert.equal(run({ 'content-security-policy': ['frame-ancestors *'] }).clickjacking_korumasi, false);
});

test('clickjacking: frame-ancestors in meta or Report-Only is ignored', () => {
  assert.equal(run({}, undefined, ["frame-ancestors 'none'"]).clickjacking_korumasi, false);
  assert.equal(run({ 'content-security-policy-report-only': ["frame-ancestors 'none'"] }).clickjacking_korumasi, false);
});

// ---------- other headers ----------

test('X-Content-Type-Options: only nosniff is doğru', () => {
  assert.equal(run({ 'x-content-type-options': [' NoSniff '] }).xcto_dogru, true);
  assert.equal(run({ 'x-content-type-options': ['sniff'] }).xcto_dogru, false);
});

test('Referrer-Policy: weak values are not doğru', () => {
  assert.equal(run({ 'referrer-policy': ['unsafe-url'] }).referrer_dogru, false);
  assert.equal(run({ 'referrer-policy': ['no-referrer-when-downgrade'] }).referrer_dogru, false);
  assert.equal(run({ 'referrer-policy': ['origin'] }).referrer_dogru, true);
});

test('Referrer-Policy: last recognized token wins', () => {
  const r = run({ 'referrer-policy': ['unsafe-url, strict-origin-when-cross-origin, made-up'] });
  assert.equal(r.referrer_etkin, 'strict-origin-when-cross-origin');
  assert.equal(r.referrer_dogru, true);
});

test('Referrer-Policy: only unknown tokens → present, not doğru', () => {
  const r = run({ 'referrer-policy': ['made-up'] });
  assert.equal(r.referrer_var, true);
  assert.equal(r.referrer_dogru, false);
});

test('presence-only headers', () => {
  const r = run({
    'permissions-policy': ['camera=()'],
    'cross-origin-opener-policy': ['same-origin'],
    'cross-origin-embedder-policy': ['require-corp'],
    'cross-origin-resource-policy': ['same-site'],
  });
  assert.ok(r.permissions_var && r.coop_var && r.coep_var && r.corp_var);
});

// ---------- cookies (K6) ----------

test('cookies: site level is all-or-nothing', () => {
  const r = run({ 'set-cookie': ['a=1; Secure; HttpOnly; SameSite=Lax', 'b=2; HttpOnly'] });
  assert.equal(r.cerez_sayisi, 2);
  assert.equal(r.cerez_tum_secure, false);
  assert.equal(r.cerez_tum_httponly, true);
  assert.equal(r.cerez_tum_samesite, false);
});

test('cookies: none set → null, not false', () => {
  const r = run({});
  assert.equal(r.cerez_tum_secure, null);
  assert.equal(r.cerez_tum_httponly, null);
});

test('cookies over HTTP are never Secure at site level', () => {
  assert.equal(run({ 'set-cookie': ['a=1; Secure'] }, 'http://ornek.com.tr/').cerez_tum_secure, false);
});

// ---------- CSP integration ----------

test('CSP: header, Report-Only and meta reach the classifier', () => {
  assert.equal(run({ 'content-security-policy-report-only': ["script-src 'self'"] }).csp.cls, 'uygulanmiyor');
  assert.equal(run({}, undefined, ["script-src 'self' 'unsafe-inline'"]).csp.cls, 'atlatilabilir');
});

test('csp_baslik_var counts only the enforced header (as in 2016)', () => {
  const ro = run({ 'content-security-policy-report-only': ["script-src 'self'"] });
  assert.equal(ro.csp_var, true);
  assert.equal(ro.csp_baslik_var, false);
});

// ---------- 2016 comparability ----------

test('2016: any Set-Cookie counts as "a security header"', () => {
  const r = run({ 'set-cookie': ['a=1'] });
  assert.equal(r.hic_baslik_yok_2016, false);
});

test('2016: no listed header at all', () => {
  assert.equal(run({ 'referrer-policy': ['no-referrer'] }).hic_baslik_yok_2016, true);
});

test('2016: Secure was detected by substring, which can over-count', () => {
  // A cookie whose value contains "secure" but has no Secure attribute.
  const r = run({ 'set-cookie': ['mode=secure_login; HttpOnly'] });
  assert.equal(r.secure_2016, true);
  assert.equal(r.cerez_tum_secure, false);
  assert.equal(r.httponly_2016, true);
});
