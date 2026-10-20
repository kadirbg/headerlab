// HTTP layer of the research scanner.
//
// Uses node:http / node:https directly instead of fetch() because the study
// needs things fetch() hides: every redirect hop, response headers exactly as
// sent (duplicates and order preserved via rawHeaders), TLS details, and a
// controlled fallback when certificate verification fails.

import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';
import type { TLSSocket } from 'node:tls';

export interface FetchOptions {
  userAgent: string;
  /** Hard deadline for one request (connect + headers + body), in ms. */
  timeoutMs: number;
  /** Maximum body bytes read from the wire (compressed). */
  maxBodyBytes: number;
}

export interface TlsInfo {
  protocol: string | null;
  cipher: string | null;
  /** false when this hop was fetched with certificate verification switched off. */
  verified: boolean;
  /** Verification error that triggered the unverified retry, if any. */
  verifyError: string | null;
}

export interface Hop {
  url: string;
  status: number | null;
  /** Response headers as [name, value] pairs, names as sent, duplicates kept. */
  headers: [string, string][];
  tls: TlsInfo | null;
  ms: number;
  error: string | null;
  attempts: number;
}

export interface BodyInfo {
  sha256: string;
  bytes: number;
  truncated: boolean;
  contentType: string | null;
  decodeError: string | null;
}

export interface ChainResult {
  startUrl: string;
  hops: Hop[];
  finalUrl: string | null;
  finalStatus: number | null;
  error: string | null;
  /** Decoded HTML of the final 2xx HTML response; not stored in the output. */
  html: string | null;
  body: BodyInfo | null;
}

const TLS_VERIFY_ERRORS = new Set([
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_UNTRUSTED',
  'CERT_REVOKED',
]);

/** Transient network errors worth retrying. DNS "not found" is final. */
const RETRYABLE = new Set(['ECONNRESET', 'ETIMEDOUT', 'TIMEOUT', 'EAI_AGAIN', 'EPIPE', 'ECONNABORTED', 'EHOSTUNREACH', 'ENETUNREACH']);

export const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

interface RawResult {
  status: number | null;
  headers: [string, string][];
  tls: { protocol: string | null; cipher: string | null } | null;
  body: Buffer | null;
  truncated: boolean;
  error: string | null;
  ms: number;
}

function pairs(raw: string[]): [string, string][] {
  const out: [string, string][] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) out.push([raw[i], raw[i + 1]]);
  return out;
}

const header = (h: [string, string][], name: string) =>
  h.find(([k]) => k.toLowerCase() === name)?.[1] ?? null;

const isHtml = (ct: string | null) => !ct || /text\/html|application\/xhtml\+xml/i.test(ct);

function requestOnce(url: string, opts: FetchOptions, verifyTls: boolean, readBody: boolean): Promise<RawResult> {
  return new Promise(resolve => {
    const started = Date.now();
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    let settled = false;
    const done = (r: Omit<RawResult, 'ms'>) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      resolve({ ...r, ms: Date.now() - started });
    };

    const req = lib.request(u, {
      method: 'GET',
      agent: false,
      rejectUnauthorized: verifyTls,
      servername: u.hostname,
      headers: {
        'User-Agent': opts.userAgent,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'tr-TR,tr;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
      },
    });

    const deadline = setTimeout(() => {
      req.destroy(Object.assign(new Error('timeout'), { code: 'TIMEOUT' }));
    }, opts.timeoutMs);

    req.on('error', (err: NodeJS.ErrnoException) => {
      done({ status: null, headers: [], tls: null, body: null, truncated: false, error: err.code ?? err.message });
    });

    req.on('response', res => {
      const headers = pairs(res.rawHeaders);
      const sock = res.socket as TLSSocket;
      const tls = typeof sock.getProtocol === 'function'
        ? { protocol: sock.getProtocol() ?? null, cipher: sock.getCipher?.()?.name ?? null }
        : null;
      const status = res.statusCode ?? null;
      const wantBody = readBody && status !== null && status >= 200 && status < 300 && isHtml(header(headers, 'content-type'));

      if (!wantBody) {
        res.resume();
        res.on('end', () => done({ status, headers, tls, body: null, truncated: false, error: null }));
        res.on('error', () => done({ status, headers, tls, body: null, truncated: false, error: null }));
        return;
      }

      const chunks: Buffer[] = [];
      let size = 0;
      let truncated = false;
      res.on('data', (c: Buffer) => {
        if (truncated) return;
        size += c.length;
        if (size > opts.maxBodyBytes) {
          chunks.push(c.subarray(0, c.length - (size - opts.maxBodyBytes)));
          truncated = true;
          done({ status, headers, tls, body: Buffer.concat(chunks), truncated, error: null });
          res.destroy();
          return;
        }
        chunks.push(c);
      });
      res.on('end', () => done({ status, headers, tls, body: Buffer.concat(chunks), truncated, error: null }));
      // A body cut off mid-stream still has usable headers.
      res.on('error', () => done({ status, headers, tls, body: Buffer.concat(chunks), truncated: true, error: null }));
    });

    req.end();
  });
}

/** Decompresses a (possibly truncated) body; returns text or an error code. */
export function decodeBody(body: Buffer, encoding: string | null): { text: string | null; error: string | null } {
  try {
    const enc = (encoding ?? '').trim().toLowerCase();
    let raw = body;
    if (enc === 'gzip' || enc === 'x-gzip') raw = zlib.gunzipSync(body, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
    else if (enc === 'br') raw = zlib.brotliDecompressSync(body, { finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH });
    else if (enc === 'deflate') raw = zlib.inflateSync(body, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
    else if (enc && enc !== 'identity') return { text: null, error: `unsupported encoding: ${enc}` };
    return { text: raw.toString('utf8'), error: null };
  } catch (e) {
    return { text: null, error: (e as NodeJS.ErrnoException).code ?? 'decode failed' };
  }
}

/**
 * One request with retries and the TLS fallback:
 * - transient network errors are retried (2 more attempts, 2 s then 4 s apart);
 * - a certificate verification error is recorded and the request repeated once
 *   with verification off, so the headers are still measured; the hop is then
 *   marked verified=false.
 */
export async function fetchHop(url: string, opts: FetchOptions, readBody: boolean): Promise<{ hop: Hop; body: Buffer | null; truncated: boolean }> {
  let attempts = 0;
  let verifyError: string | null = null;
  let verify = true;
  let r: RawResult;

  for (;;) {
    attempts++;
    r = await requestOnce(url, opts, verify, readBody);
    if (r.error && verify && TLS_VERIFY_ERRORS.has(r.error)) {
      verifyError = r.error;
      verify = false;
      continue;
    }
    if (r.error && RETRYABLE.has(r.error) && attempts < 3) {
      await sleep(2000 * attempts);
      continue;
    }
    break;
  }

  const hop: Hop = {
    url,
    status: r.status,
    headers: r.headers,
    tls: r.tls ? { ...r.tls, verified: verify, verifyError } : (url.startsWith('https:') && verifyError ? { protocol: null, cipher: null, verified: false, verifyError } : null),
    ms: r.ms,
    error: r.error,
    attempts,
  };
  return { hop, body: r.body, truncated: r.truncated };
}

/** Follows redirects one hop at a time (max `maxRedirects`), recording each hop. */
export async function fetchChain(startUrl: string, opts: FetchOptions, maxRedirects = 10): Promise<ChainResult> {
  const hops: Hop[] = [];
  let url = startUrl;

  for (let i = 0; i <= maxRedirects; i++) {
    const { hop, body, truncated } = await fetchHop(url, opts, true);
    hops.push(hop);

    if (hop.error) return { startUrl, hops, finalUrl: url, finalStatus: null, error: hop.error, html: null, body: null };

    const location = header(hop.headers, 'location');
    if (hop.status !== null && hop.status >= 300 && hop.status < 400 && location) {
      let next: URL;
      try {
        next = new URL(location, url);
      } catch {
        return { startUrl, hops, finalUrl: url, finalStatus: hop.status, error: 'BAD_LOCATION', html: null, body: null };
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        return { startUrl, hops, finalUrl: url, finalStatus: hop.status, error: 'NON_HTTP_REDIRECT', html: null, body: null };
      }
      url = next.toString();
      continue;
    }

    let html: string | null = null;
    let info: BodyInfo | null = null;
    if (body) {
      const decoded = decodeBody(body, header(hop.headers, 'content-encoding'));
      html = decoded.text;
      info = {
        sha256: createHash('sha256').update(body).digest('hex'),
        bytes: body.length,
        truncated,
        contentType: header(hop.headers, 'content-type'),
        decodeError: decoded.error,
      };
    }
    return { startUrl, hops, finalUrl: url, finalStatus: hop.status, error: null, html, body: info };
  }

  return { startUrl, hops, finalUrl: url, finalStatus: null, error: 'TOO_MANY_REDIRECTS', html: null, body: null };
}
