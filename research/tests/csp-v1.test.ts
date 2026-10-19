// Criteria set v1 — CSP classification tests.
// The first block is the reference example table of criteria set v1, verbatim.
// If one of these fails, the code no longer implements the published criteria.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyCsp, type CspInput } from '../criteria/csp-v1.ts';

const header = (value: string): CspInput => ({ value, source: 'header', reportOnly: false });
const reportOnly = (value: string): CspInput => ({ value, source: 'header', reportOnly: true });
const meta = (value: string, ro = false): CspInput => ({ value, source: 'meta', reportOnly: ro });

// ---------- reference examples (sınıflandırma örnekleri) ----------

test('example #1: unsafe-inline without nonce → atlatilabilir (H1)', () => {
  const r = classifyCsp([header("default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com")]);
  assert.equal(r.cls, 'atlatilabilir');
  assert.ok(r.flags.includes('H1'));
});

test('example #2: upgrade-insecure-requests only → xss_kapsami_yok (H9)', () => {
  const r = classifyCsp([header('upgrade-insecure-requests')]);
  assert.equal(r.cls, 'xss_kapsami_yok');
  assert.deepEqual(r.flags, ['H9']);
});

test("example #3: frame-ancestors 'self' only → xss_kapsami_yok", () => {
  const r = classifyCsp([header("frame-ancestors 'self'")]);
  assert.equal(r.cls, 'xss_kapsami_yok');
});

test('example #4: clean host allowlist, no base-uri → kismen_etkili (H6)', () => {
  const r = classifyCsp([header("script-src 'self' https://cdn.ornek.com.tr; object-src 'none'")]);
  assert.equal(r.cls, 'kismen_etkili');
  assert.deepEqual(r.flags, ['H6']);
});

test('example #5: strict CSP pattern → etkili, no flags', () => {
  const r = classifyCsp([header("script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'")]);
  assert.equal(r.cls, 'etkili');
  assert.deepEqual(r.flags, []);
});

test("example #6: script-src 'nonce-abc' only → kismen_etkili (H5, H6)", () => {
  const r = classifyCsp([header("script-src 'nonce-abc'")]);
  assert.equal(r.cls, 'kismen_etkili');
  assert.deepEqual(r.flags, ['H5', 'H6']);
});

test('example #7: Report-Only only → uygulanmiyor (H8)', () => {
  const r = classifyCsp([reportOnly("script-src 'self'")]);
  assert.equal(r.cls, 'uygulanmiyor');
  assert.deepEqual(r.flags, ['H8']);
});

test('rule 1: no CSP → yok', () => {
  assert.equal(classifyCsp([]).cls, 'yok');
});

// ---------- rule 4 details ----------

test('H2: wildcard, bare scheme and https://* are broad', () => {
  for (const src of ['*', 'https:', 'http:', 'https://*']) {
    const r = classifyCsp([header(`script-src ${src}; object-src 'none'; base-uri 'none'`)]);
    assert.equal(r.cls, 'atlatilabilir', src);
    assert.ok(r.flags.includes('H2'), src);
  }
});

test('H3: data: in script-src → atlatilabilir', () => {
  const r = classifyCsp([header("script-src 'self' data:; object-src 'none'; base-uri 'self'")]);
  assert.equal(r.cls, 'atlatilabilir');
  assert.ok(r.flags.includes('H3'));
});

test('H4: host serving AngularJS → atlatilabilir', () => {
  const r = classifyCsp([header("script-src 'self' https://ajax.googleapis.com; object-src 'none'; base-uri 'self'")]);
  assert.equal(r.cls, 'atlatilabilir');
  assert.ok(r.flags.includes('H4'));
});

test('H4: subdomain wildcard matches the bypass host', () => {
  const r = classifyCsp([header("script-src *.googleapis.com; object-src 'none'; base-uri 'self'")]);
  assert.ok(r.flags.includes('H4'));
});

test('H4: JSONP host that needs eval only counts with unsafe-eval', () => {
  const without = classifyCsp([header("script-src https://www.google-analytics.com; object-src 'none'; base-uri 'self'")]);
  assert.ok(!without.flags.includes('H4'));
  const withEval = classifyCsp([header("script-src https://www.google-analytics.com 'unsafe-eval'; object-src 'none'; base-uri 'self'")]);
  assert.ok(withEval.flags.includes('H4'));
  assert.ok(withEval.flags.includes('H7'));
});

test('H4: unrelated host is not risky', () => {
  const r = classifyCsp([header("script-src https://cdn.ornek.com.tr; object-src 'none'; base-uri 'self'")]);
  assert.ok(!r.flags.includes('H4'));
});

test('H7 alone does not make a policy atlatilabilir', () => {
  const r = classifyCsp([header("script-src 'nonce-a' 'unsafe-eval'; object-src 'none'; base-uri 'none'")]);
  assert.equal(r.cls, 'etkili');
  assert.deepEqual(r.flags, ['H7']);
});

test('keywords are case-insensitive', () => {
  const r = classifyCsp([header("script-src 'UNSAFE-INLINE'; object-src 'none'; base-uri 'none'")]);
  assert.equal(r.cls, 'atlatilabilir');
  assert.ok(r.flags.includes('H1'));
});

test('default-src is the fallback for script-src and object-src', () => {
  const r = classifyCsp([header("default-src 'none'; script-src 'sha256-abc='; base-uri 'none'")]);
  assert.equal(r.cls, 'etkili');
});

// ---------- clarifications C1 and C2 ----------

test('C1: strict-dynamic neutralizes data: and risky hosts', () => {
  const r = classifyCsp([header("script-src 'nonce-a' 'strict-dynamic' data: https://ajax.googleapis.com; object-src 'none'; base-uri 'none'")]);
  assert.equal(r.cls, 'etkili');
  assert.ok(!r.flags.includes('H3'));
  assert.ok(!r.flags.includes('H4'));
});

test("C2: script policy 'none' counts as nonce/hash", () => {
  const r = classifyCsp([header("default-src 'none'; base-uri 'none'")]);
  assert.equal(r.cls, 'etkili');
});

// ---------- several policies, Report-Only and meta ----------

test('several enforced policies → most protective class, its flags', () => {
  const r = classifyCsp([header("script-src 'unsafe-inline', script-src 'nonce-a' 'strict-dynamic'; object-src 'none'; base-uri 'none'")]);
  assert.equal(r.enforcedCount, 2);
  assert.equal(r.cls, 'etkili');
  assert.deepEqual(r.flags, []);
});

test('enforced + Report-Only → class from the enforced policy, no H8', () => {
  const r = classifyCsp([header("script-src 'self' 'unsafe-inline'"), reportOnly("script-src 'nonce-a'")]);
  assert.equal(r.cls, 'atlatilabilir');
  assert.ok(!r.flags.includes('H8'));
  assert.equal(r.reportOnlyCount, 1);
});

test('repeated directive: the first one wins', () => {
  const r = classifyCsp([header("script-src 'nonce-a' 'strict-dynamic'; script-src *; object-src 'none'; base-uri 'none'")]);
  assert.equal(r.cls, 'etkili');
});

test('meta CSP is enforced and recorded as meta', () => {
  const r = classifyCsp([meta("script-src 'self' 'unsafe-inline'")]);
  assert.equal(r.cls, 'atlatilabilir');
  assert.equal(r.enforcedFrom, 'meta');
});

test('Report-Only in meta is ignored by browsers', () => {
  assert.equal(classifyCsp([meta("script-src 'self'", true)]).cls, 'yok');
});

test('header and meta together → enforcedFrom both', () => {
  const r = classifyCsp([header("frame-ancestors 'none'"), meta("script-src 'nonce-a'; object-src 'none'; base-uri 'self'")]);
  assert.equal(r.enforcedFrom, 'both');
  assert.equal(r.cls, 'etkili');
});
