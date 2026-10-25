// Classification step: raw scan.jsonl → one CSV row per site (main layer) and
// one per scanned subdomain (secondary layer), coded with criteria set v1.
//
// Usage:
//   node --experimental-strip-types research/scanner/classify.ts \
//     --run pilot-1 [--sample research/data/sample/orneklem_v1.csv]
//
// Writes research/output/<run>/main.csv and sub.csv.

import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import { evaluateHeadersV1, type HeaderMap, type HeaderResult } from '../criteria/headers-v1.ts';
import { CRITERIA_VERSION } from '../criteria/csp-v1.ts';
import { parseCsv, toCsv } from './csv.ts';
import type { ScanRecord } from './scan.ts';

export function headerMap(pairs: [string, string][]): HeaderMap {
  const m: HeaderMap = {};
  for (const [k, v] of pairs) (m[k.toLowerCase()] ??= []).push(v);
  return m;
}

const reached = (r: ScanRecord | undefined): r is ScanRecord =>
  !!r && !r.error && r.finalStatus !== null && r.finalStatus >= 200 && r.finalStatus < 300;

export interface Row extends Record<string, unknown> {}

/** Flattens a HeaderResult into CSV columns (drops per-cookie and per-policy detail). */
function flat(h: HeaderResult): Row {
  const { cerezler: _c, csp, ...rest } = h;
  return {
    ...rest,
    csp_sinif: csp.cls,
    csp_bayraklar: csp.flags.join(' '),
    csp_kaynak: csp.enforcedFrom ?? '',
    csp_uygulanan_politika: csp.enforcedCount,
    csp_report_only_politika: csp.reportOnlyCount,
    ...Object.fromEntries(['H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'H7', 'H8', 'H9'].map(f => [`csp_${f}`, csp.flags.includes(f as never)])),
  };
}

/**
 * Codes one reached page. HSTS comes from the first HTTPS response of the
 * https:// chain (v1, section A); every other header from the final response.
 */
export function codePage(page: ScanRecord, httpsChain: ScanRecord | undefined): Row {
  const last = page.hops[page.hops.length - 1];
  const headers = headerMap(last.headers);
  const firstHttps = httpsChain?.hops.find(h => h.url.startsWith('https:') && h.status !== null);
  if (firstHttps) {
    const hsts = headerMap(firstHttps.headers)['strict-transport-security'];
    if (hsts) headers['strict-transport-security'] = hsts;
    else delete headers['strict-transport-security'];
  }
  const result = evaluateHeadersV1({ url: page.finalUrl!, headers, metaCsp: page.metaCsp.filter(m => !m.reportOnly).map(m => m.value) });
  return flat(result);
}

const tlsUnverified = (recs: ScanRecord[]) => recs.some(r => r.hops.some(h => h.tls && !h.tls.verified));

export function classify(records: ScanRecord[], sample: Map<string, Record<string, string>>): { main: Row[]; sub: Row[] } {
  const byDomain = new Map<string, ScanRecord[]>();
  for (const r of records) (byDomain.get(r.domain) ?? byDomain.set(r.domain, []).get(r.domain)!).push(r);

  const main: Row[] = [];
  const sub: Row[] = [];

  for (const [domain, recs] of byDomain) {
    const meta = sample.get(domain) ?? {};
    const base = { alan_adi: domain, kaynak: meta.kaynak ?? '', sektor: meta.sektor ?? '', alt_sektor: meta.alt_sektor ?? '' };
    const http = recs.find(r => r.layer === 'main' && r.scheme === 'http');
    const https = recs.find(r => r.layer === 'main' && r.scheme === 'https');
    const page = reached(https) ? https : reached(http) ? http : undefined;

    const common = {
      ...base,
      https_erisilir: reached(https),
      http_https_yonlenir: !!http?.finalUrl?.startsWith('https:') && reached(http),
      tls_dogrulanmadi: tlsUnverified([http, https].filter(Boolean) as ScanRecord[]),
      alt_alan_sayisi: (page?.selectedSubdomains ?? []).length,
    };

    if (!page) {
      main.push({ ...common, erisim: 'hata', son_url: https?.finalUrl ?? http?.finalUrl ?? '', son_durum: https?.finalStatus ?? http?.finalStatus ?? '', hata: https?.error ?? http?.error ?? `HTTP ${https?.finalStatus ?? http?.finalStatus}` });
      continue;
    }
    main.push({ ...common, erisim: 'ok', son_url: page.finalUrl, son_durum: page.finalStatus, hata: '', ...codePage(page, https) });

    for (const host of new Set(recs.filter(r => r.layer === 'sub').map(r => r.host))) {
      const sh = recs.find(r => r.layer === 'sub' && r.host === host && r.scheme === 'https');
      const sp = recs.find(r => r.layer === 'sub' && r.host === host && r.scheme === 'http');
      const p = reached(sh) ? sh : reached(sp) ? sp : undefined;
      const sbase = { ...base, alt_alan: host, tls_dogrulanmadi: tlsUnverified([sh, sp].filter(Boolean) as ScanRecord[]) };
      if (!p) sub.push({ ...sbase, erisim: 'hata', son_url: sh?.finalUrl ?? sp?.finalUrl ?? '', son_durum: sh?.finalStatus ?? sp?.finalStatus ?? '', hata: sh?.error ?? sp?.error ?? 'non-2xx' });
      else sub.push({ ...sbase, erisim: 'ok', son_url: p.finalUrl, son_durum: p.finalStatus, hata: '', ...codePage(p, sh) });
    }
  }
  return { main, sub };
}

const columnsOf = (rows: Row[]) => {
  const seen: string[] = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!seen.includes(k)) seen.push(k);
  return seen;
};

function main() {
  const { values } = parseArgs({
    options: {
      run: { type: 'string' },
      out: { type: 'string', default: 'research/output' },
      sample: { type: 'string', default: 'research/data/sample/orneklem_v1.csv' },
    },
  });
  if (!values.run) throw new Error('--run is required');
  const dir = path.join(values.out!, values.run);
  const records = fs.readFileSync(path.join(dir, 'scan.jsonl'), 'utf8').split('\n').filter(l => l.trim()).map(l => JSON.parse(l) as ScanRecord);
  const sample = new Map(parseCsv(fs.readFileSync(values.sample!, 'utf8')).map(r => [r.alan_adi.toLowerCase(), r]));

  const { main, sub } = classify(records, sample);
  fs.writeFileSync(path.join(dir, 'main.csv'), toCsv(main, columnsOf(main)));
  fs.writeFileSync(path.join(dir, 'sub.csv'), toCsv(sub, columnsOf(sub)));

  const okCount = main.filter(r => r.erisim === 'ok').length;
  console.log(`criteria ${CRITERIA_VERSION}: ${main.length} sites (${okCount} reached), ${sub.length} subdomains`);
  console.log(`wrote ${path.join(dir, 'main.csv')} and sub.csv`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
