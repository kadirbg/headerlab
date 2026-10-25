// RFC 3161 request/response handling, checked against a local openssl TSA.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildRequest, isoTime, parseResponse } from '../scanner/seal.ts';

const hasOpenssl = (() => {
  try { execFileSync('openssl', ['version']); return true; } catch { return false; }
})();

test('request and response round-trip through an openssl TSA', { skip: !hasOpenssl && 'openssl not installed' }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tsa-'));
  const run = (...a: string[]) => execFileSync('openssl', a, { cwd: dir, stdio: 'pipe' }).toString();
  run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'tsa.key', '-out', 'tsa.crt', '-days', '2',
    '-subj', '/CN=Test TSA', '-addext', 'extendedKeyUsage=critical,timeStamping');
  fs.writeFileSync(path.join(dir, 'serial'), '01\n');
  fs.writeFileSync(path.join(dir, 'tsa.cnf'), [
    '[ tsa ]', 'default_tsa = c', '[ c ]', 'serial = ./serial', 'signer_cert = ./tsa.crt', 'signer_key = ./tsa.key',
    'signer_digest = sha256', 'default_policy = 1.2.3.4.1', 'digests = sha256', 'ess_cert_id_alg = sha256', '',
  ].join('\n'));
  const data = Buffer.from('{"domain":"example.com.tr"}\n');
  fs.writeFileSync(path.join(dir, 'scan.jsonl'), data);
  const hash = createHash('sha256').update(data).digest();

  fs.writeFileSync(path.join(dir, 'q.tsq'), buildRequest(hash, Buffer.from('00a1b2c3d4e5f607', 'hex')));
  const text = run('ts', '-query', '-in', 'q.tsq', '-text');
  assert.match(text, /Hash Algorithm: sha256/);
  assert.match(text, /Nonce: 0xA1B2C3D4E5F607/);
  assert.match(text, /Certificate required: yes/);

  run('ts', '-reply', '-config', 'tsa.cnf', '-queryfile', 'q.tsq', '-out', 'r.tsr');
  const info = parseResponse(fs.readFileSync(path.join(dir, 'r.tsr')));
  assert.equal(info.status, 0);
  assert.equal(info.imprint, hash.toString('hex'));
  assert.equal(info.nonce, 'a1b2c3d4e5f607');
  assert.equal(info.policy, '1.2.3.4.1');
  assert.match(isoTime(info.genTime!), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.match(run('ts', '-verify', '-data', 'scan.jsonl', '-in', 'r.tsr', '-CAfile', 'tsa.crt'), /Verification: OK/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('isoTime keeps fractional seconds', () => {
  assert.equal(isoTime('20261025112233.5Z'), '2026-10-25T11:22:33.5Z');
});
