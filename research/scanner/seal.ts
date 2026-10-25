// Seals a raw scan file with an RFC 3161 timestamp (no openssl needed).
//
// Usage (Node.js 22+):
//   node --experimental-strip-types research/scanner/seal.ts --run pilot-1 [--tsa https://freetsa.org/tsr]
//
// Writes next to scan.jsonl:
//   scan.tsq   the timestamp request (DER)
//   scan.tsr   the TSA's signed response (DER) — this is the proof
// and adds a "seal" entry to manifest.json. The response can be verified on any
// machine with openssl (see research/README.md, "Sealing the raw data").

import { parseArgs } from 'node:util';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';

// --- minimal DER encoding ---------------------------------------------------

function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag: number, body: Buffer) => Buffer.concat([Buffer.from([tag]), len(body.length), body]);
const seq = (...items: Buffer[]) => tlv(0x30, Buffer.concat(items));

/** DER INTEGER from unsigned big-endian bytes. */
function int(bytes: Buffer): Buffer {
  let b = bytes;
  while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}

const SHA256_OID = Buffer.from('0609608648016503040201', 'hex'); // 2.16.840.1.101.3.4.2.1
const NULL = Buffer.from('0500', 'hex');

/** TimeStampReq (RFC 3161 §2.4.1): v1, SHA-256 imprint, nonce, certReq TRUE. */
export function buildRequest(sha256: Buffer, nonce: Buffer): Buffer {
  return seq(
    int(Buffer.from([1])),
    seq(seq(SHA256_OID, NULL), tlv(0x04, sha256)),
    int(nonce),
    tlv(0x01, Buffer.from([0xff])),
  );
}

// --- minimal DER decoding ---------------------------------------------------

interface Node { tag: number; start: number; end: number; body: Buffer }

function read(buf: Buffer, off: number): Node {
  const tag = buf[off];
  let l = buf[off + 1];
  let p = off + 2;
  if (l & 0x80) {
    const n = l & 0x7f;
    l = 0;
    for (let i = 0; i < n; i++) l = l * 256 + buf[p + i];
    p += n;
  }
  if (p + l > buf.length) throw new Error('truncated DER');
  return { tag, start: off, end: p + l, body: buf.subarray(p, p + l) };
}

function children(n: Node): Node[] {
  const out: Node[] = [];
  for (let o = 0; o < n.body.length; ) {
    const c = read(n.body, o);
    out.push(c);
    o = c.end;
  }
  return out;
}

const uint = (b: Buffer) => b.reduce((a, x) => a * 256n + BigInt(x), 0n);

export interface TsrInfo {
  status: number;
  genTime: string | null;
  imprint: string | null;
  nonce: string | null;
  serial: string | null;
  policy: string | null;
}

function oid(b: Buffer): string {
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (const x of b.subarray(1)) {
    v = v * 128 + (x & 0x7f);
    if (!(x & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}

/** Reads status and TSTInfo fields from a TimeStampResp. Does not check the signature. */
export function parseResponse(der: Buffer): TsrInfo {
  const resp = children(read(der, 0));
  const status = Number(uint(children(resp[0])[0].body));
  const info: TsrInfo = { status, genTime: null, imprint: null, nonce: null, serial: null, policy: null };
  if (!resp[1]) return info;
  // ContentInfo → [0] → SignedData → encapContentInfo → [0] → OCTET STRING → TSTInfo
  const signedData = children(children(resp[1])[1])[0];
  const encap = children(signedData)[2];
  const octets = children(children(encap)[1])[0];
  const tst = children(read(octets.body, 0));
  info.policy = oid(tst[1].body);
  info.imprint = children(tst[2])[1].body.toString('hex');
  info.serial = uint(tst[3].body).toString();
  info.genTime = tst[4].body.toString('ascii');
  for (const f of tst.slice(5)) if (f.tag === 0x02) info.nonce = uint(f.body).toString(16);
  return info;
}

/** "20261025112233Z" or with fraction → ISO 8601. */
export function isoTime(g: string): string {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(g);
  return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7] ?? ''}Z` : g;
}

async function main() {
  const { values } = parseArgs({
    options: {
      run: { type: 'string' },
      out: { type: 'string', default: 'research/output' },
      file: { type: 'string', default: 'scan.jsonl' },
      tsa: { type: 'string', default: 'https://freetsa.org/tsr' },
    },
  });
  if (!values.run) throw new Error('--run is required');
  const dir = path.join(values.out!, values.run);
  const file = path.join(dir, values.file!);
  const stem = values.file!.replace(/\.[^.]+$/, '');

  const hash = createHash('sha256').update(fs.readFileSync(file)).digest();
  const nonce = randomBytes(8);
  nonce[0] &= 0x7f;
  const req = buildRequest(hash, nonce);
  fs.writeFileSync(path.join(dir, `${stem}.tsq`), req);

  const res = await fetch(values.tsa!, { method: 'POST', headers: { 'Content-Type': 'application/timestamp-query' }, body: req });
  if (!res.ok) throw new Error(`TSA answered HTTP ${res.status}`);
  const tsr = Buffer.from(await res.arrayBuffer());
  fs.writeFileSync(path.join(dir, `${stem}.tsr`), tsr);

  const info = parseResponse(tsr);
  if (info.status > 1) throw new Error(`TSA refused the request (status ${info.status})`);
  if (info.imprint !== hash.toString('hex')) throw new Error('hash in the response does not match the file');
  if (info.nonce !== uint(nonce).toString(16)) throw new Error('nonce in the response does not match the request');

  const manifestPath = path.join(dir, 'manifest.json');
  if (fs.existsSync(manifestPath)) {
    const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    m.seal = [...(m.seal ?? []), { file: values.file, sha256: info.imprint, tsa: values.tsa, genTime: isoTime(info.genTime!), serial: info.serial, policy: info.policy, response: `${stem}.tsr` }];
    fs.writeFileSync(manifestPath, JSON.stringify(m, null, 2));
  }

  console.log(`${values.file} sha256 ${info.imprint}`);
  console.log(`sealed by ${values.tsa} at ${isoTime(info.genTime!)} (serial ${info.serial})`);
  console.log(`wrote ${stem}.tsq and ${stem}.tsr; keep them with ${values.file} and manifest.json`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(e => {
    console.error(e.message ?? e);
    process.exit(1);
  });
}
