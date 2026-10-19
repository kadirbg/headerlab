// Regression tests for the web tool's shared libraries (src/lib).
// Each case is a defect found on 2026-10-19 while comparing the evaluator with
// criteria set v1. They keep headerlab.dev and the research classifier in
// agreement on the parser.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCSP, parseCSP, parseCSPList } from '../../src/lib/csp-evaluator.ts';
import { analyzeHeaders } from '../../src/lib/headers.ts';

const severities = (policy: string) => evaluateCSP(policy).findings.map(f => f.severity);

test("#1 nonce + 'unsafe-inline' (no strict-dynamic) is not critical", () => {
  const r = evaluateCSP("script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'");
  assert.ok(!r.findings.some(f => f.severity === 'critical'));
  assert.ok(r.findings.some(f => f.title.includes('ignored (nonce/hash present)')));
});

test('#2 Google/OWASP strict CSP pattern has no high or critical finding', () => {
  const s = severities("script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'");
  assert.ok(!s.includes('critical') && !s.includes('high'));
});

test('#3 several comma-separated policies are split, not merged', () => {
  const list = parseCSPList("default-src 'self', script-src 'unsafe-inline'");
  assert.equal(list.length, 2);
  assert.deepEqual(list[0].directives.get('default-src'), ["'self'"]);
  assert.deepEqual(parseCSP("default-src 'self', script-src 'unsafe-inline'").directives.get('default-src'), ["'self'"]);
  assert.ok(evaluateCSP("default-src 'self', script-src *").findings.some(f => f.title.includes('2 policies found')));
});

test('#4 a repeated directive keeps the first occurrence', () => {
  assert.deepEqual(parseCSP("script-src 'self'; script-src *").directives.get('script-src'), ["'self'"]);
});

test('#5 keywords are matched case-insensitively', () => {
  assert.ok(severities("script-src 'UNSAFE-INLINE'").includes('critical'));
});

test('nonce and hash values keep their case', () => {
  assert.deepEqual(parseCSP("script-src 'NONCE-AbC' 'SHA256-XyZ='").directives.get('script-src'), ["'nonce-AbC'", "'sha256-XyZ='"]);
});

test('allowlisted host with a known bypass is reported', () => {
  const r = evaluateCSP("script-src 'self' https://ajax.googleapis.com; object-src 'none'; base-uri 'self'");
  assert.ok(r.findings.some(f => f.severity === 'high' && f.title.includes('ajax.googleapis.com')));
});

test('Referrer-Policy no-referrer-when-downgrade is a warning, not a pass', () => {
  const r = analyzeHeaders({ 'referrer-policy': 'no-referrer-when-downgrade' }, new URL('https://ornek.com.tr'));
  assert.equal(r.checks.find(c => c.id === 'referrer')!.status, 'warn');
});
