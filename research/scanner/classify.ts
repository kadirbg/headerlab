// Classification step: raw scan.jsonl → one CSV row per site (main layer) and
// one per scanned subdomain (secondary layer), coded with criteria set v1.
//
// Usage:
//   node --experimental-strip-types research/scanner/classify.ts \
//     --run pilot-1 [--sample research/data/sample/orneklem_v1.csv] [--merge run-b]
//
// --merge: for every domain present in the listed runs (comma-separated, later
// wins), all of its records from --run are replaced by those of the later run.
// Each row's olcum column names the run its data came from.
//
// Writes research/output/<run>/main.csv and sub.csv (main-merged.csv and
// sub-merged.csv with --merge).

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
 * When the https:// chain did not load (e.g. a bot challenge), the first HTTPS
 * response of the page's own chain is used, never the challenge response.
 */
export function evaluatePage(page: ScanRecord, httpsChain: ScanRecord | undefined): HeaderResult {
  const last = page.hops[page.hops.length - 1];
  const headers = headerMap(last.headers);
  const firstHttps = httpsChain?.hops.find(h => h.url.startsWith('https:') && h.status !== null);
  if (firstHttps) {
    const hsts = headerMap(firstHttps.headers)['strict-transport-security'];
    if (hsts) headers['strict-transport-security'] = hsts;
    else delete headers['strict-transport-security'];
  }
  return evaluateHeadersV1({ url: page.finalUrl!, headers, metaCsp: page.metaCsp.filter(m => !m.reportOnly).map(m => m.value) });
}

export const codePage = (page: ScanRecord, httpsChain: ScanRecord | undefined): Row => flat(evaluatePage(page, httpsChain));

export interface MainSelection {
  mainHost: string;
  http: ScanRecord | undefined;
  https: ScanRecord | undefined;
  filtered: boolean;
  /** The page that is coded, or undefined when the site was not reached. */
  page: ScanRecord | undefined;
  /** The chain HSTS is read from. */
  hstsChain: ScanRecord | undefined;
}

/** Picks the records of a site's main layer that classification uses (C6, C8). */
export function selectMain(recs: ScanRecord[], domain: string, filterIps: Set<string>): MainSelection {
  // C6: www.<domain> records exist only when the bare domain did not answer.
  const mainHost = recs.some(r => r.layer === 'main' && r.host === `www.${domain}`) ? `www.${domain}` : domain;
  const http = recs.find(r => r.layer === 'main' && r.scheme === 'http' && r.host === mainHost);
  const https = recs.find(r => r.layer === 'main' && r.scheme === 'https' && r.host === mainHost);
  const filtered = ispFiltered(recs.filter(r => r.layer === 'main'), filterIps);
  const page = filtered ? undefined : reached(https) ? https : reached(http) ? http : undefined;
  return { mainHost, http, https, filtered, page, hstsChain: page && (reached(https) ? https : page) };
}

/** Final statuses that mean the scanner was refused rather than the page missing (C3). */
const BLOCK_STATUSES = new Set([400, 403, 406, 429]);

/**
 * Access class of a site or subdomain (C3):
 *   ok          a 2xx page was received
 *   engellendi  refused: 400/403/406/429, or a bot challenge (cf-mitigated)
 *   ulasilamadi no HTTP response at all (DNS, connection, timeout)
 *   hata        any other outcome (404, 5xx, redirect loop, …)
 * classify() adds iss_filtresi (C8) before these: the ISP served a filter page.
 * Pages that are not "ok" are never coded: a challenge page carries the
 * protection service's headers, not the site's.
 */
/** Pages an ISP shows instead of a filtered site (C8). */
export const ISP_FILTER_HOSTS = new Set(['guvenliinternet.turktelekom.com.tr']);

const hostOf = (u: string) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } };

/**
 * Addresses of ISP filter servers, learned from the data: a hop that redirected
 * to a filter page was answered by the filter, so every hop that connected to
 * the same address was filtered too (also when TLS then failed).
 */
export function filterAddresses(records: ScanRecord[]): Set<string> {
  const ips = new Set<string>();
  for (const r of records) {
    for (const h of r.hops) {
      const loc = h.headers.find(([k]) => k.toLowerCase() === 'location')?.[1];
      if (h.ip && loc && ISP_FILTER_HOSTS.has(hostOf(new URL(loc, h.url).toString()))) ips.add(h.ip);
    }
  }
  return ips;
}

export const ispFiltered = (recs: (ScanRecord | undefined)[], ips: Set<string>) =>
  recs.some(r => r?.hops.some(h => ISP_FILTER_HOSTS.has(hostOf(h.url)) || (!!h.ip && ips.has(h.ip))));

export function accessClass(recs: (ScanRecord | undefined)[]): 'ok' | 'engellendi' | 'ulasilamadi' | 'hata' {
  const rs = recs.filter((r): r is ScanRecord => !!r);
  if (rs.some(reached)) return 'ok';
  const answered = rs.filter(r => r.hops.some(h => h.status !== null));
  if (!answered.length) return 'ulasilamadi';
  const blocked = answered.some(r => {
    const last = [...r.hops].reverse().find(h => h.status !== null)!;
    return BLOCK_STATUSES.has(last.status!) || last.headers.some(([k]) => k.toLowerCase() === 'cf-mitigated');
  });
  return blocked ? 'engellendi' : 'hata';
}

/** True when the final URL is outside the site's registrable domain (C4). */
export function outsideDomain(finalUrl: string | null | undefined, domain: string): boolean {
  if (!finalUrl) return false;
  const h = new URL(finalUrl).hostname.toLowerCase();
  return h !== domain && !h.endsWith(`.${domain}`);
}

const tlsUnverified = (recs: ScanRecord[]) => recs.some(r => r.hops.some(h => h.tls && !h.tls.verified));

export function classify(records: ScanRecord[], sample: Map<string, Record<string, string>>): { main: Row[]; sub: Row[] } {
  const byDomain = new Map<string, ScanRecord[]>();
  for (const r of records) (byDomain.get(r.domain) ?? byDomain.set(r.domain, []).get(r.domain)!).push(r);

  const main: Row[] = [];
  const sub: Row[] = [];
  const filterIps = filterAddresses(records);

  for (const [domain, recs] of byDomain) {
    const meta = sample.get(domain) ?? {};
    const base = { alan_adi: domain, kaynak: meta.kaynak ?? '', sektor: meta.sektor ?? '', alt_sektor: meta.alt_sektor ?? '', olcum: recs[0].run };
    const { mainHost, http, https, filtered, page, hstsChain } = selectMain(recs, domain, filterIps);

    const common = {
      ...base,
      // HTTPS works if https:// loaded, or the http:// chain ended on an HTTPS page
      // (a bot challenge on one request must not count as "no HTTPS").
      https_erisilir: reached(https) || (!!page && page.finalUrl!.startsWith('https:')),
      http_https_yonlenir: !!http?.finalUrl?.startsWith('https:') && reached(http),
      tls_dogrulanmadi: tlsUnverified([http, https].filter(Boolean) as ScanRecord[]),
      alt_alan_sayisi: (page?.selectedSubdomains ?? []).length,
      www_yedek: mainHost !== domain,
    };

    if (!page) {
      main.push({ ...common, erisim: filtered ? 'iss_filtresi' : accessClass([http, https]), alan_disi: false, son_url: https?.finalUrl ?? http?.finalUrl ?? '', son_durum: https?.finalStatus ?? http?.finalStatus ?? '', hata: https?.error ?? http?.error ?? `HTTP ${https?.finalStatus ?? http?.finalStatus}` });
      continue;
    }
    main.push({ ...common, erisim: 'ok', alan_disi: outsideDomain(page.finalUrl, domain), son_url: page.finalUrl, son_durum: page.finalStatus, hata: '', ...codePage(page, hstsChain) });

    for (const host of new Set(recs.filter(r => r.layer === 'sub').map(r => r.host))) {
      const sh = recs.find(r => r.layer === 'sub' && r.host === host && r.scheme === 'https');
      const sp = recs.find(r => r.layer === 'sub' && r.host === host && r.scheme === 'http');
      const sf = ispFiltered([sh, sp], filterIps);
      const p = sf ? undefined : reached(sh) ? sh : reached(sp) ? sp : undefined;
      const sbase = { ...base, alt_alan: host, tls_dogrulanmadi: tlsUnverified([sh, sp].filter(Boolean) as ScanRecord[]) };
      if (!p) sub.push({ ...sbase, erisim: sf ? 'iss_filtresi' : accessClass([sh, sp]), alan_disi: false, son_url: sh?.finalUrl ?? sp?.finalUrl ?? '', son_durum: sh?.finalStatus ?? sp?.finalStatus ?? '', hata: sh?.error ?? sp?.error ?? `HTTP ${sh?.finalStatus ?? sp?.finalStatus}` });
      else sub.push({ ...sbase, erisim: 'ok', alan_disi: outsideDomain(p.finalUrl, domain), son_url: p.finalUrl, son_durum: p.finalStatus, hata: '', ...codePage(p, reached(sh) ? sh : p) });
    }
  }
  return { main, sub };
}

/** Replaces a domain's records with those of later runs (re-measurement). */
export function mergeRuns(runs: ScanRecord[][]): ScanRecord[] {
  const byDomain = new Map<string, ScanRecord[]>();
  for (const recs of runs) {
    const fresh = new Map<string, ScanRecord[]>();
    for (const r of recs) (fresh.get(r.domain) ?? fresh.set(r.domain, []).get(r.domain)!).push(r);
    for (const [d, rs] of fresh) byDomain.set(d, rs);
  }
  return [...byDomain.values()].flat();
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
      merge: { type: 'string' },
    },
  });
  if (!values.run) throw new Error('--run is required');
  const dir = path.join(values.out!, values.run);
  const load = (run: string) => fs.readFileSync(path.join(values.out!, run, 'scan.jsonl'), 'utf8').split('\n').filter(l => l.trim()).map(l => JSON.parse(l) as ScanRecord);
  const extra = values.merge ? values.merge.split(',').map(s => s.trim()).filter(Boolean) : [];
  const records = mergeRuns([load(values.run), ...extra.map(load)]);
  const sample = new Map(parseCsv(fs.readFileSync(values.sample!, 'utf8')).map(r => [r.alan_adi.toLowerCase(), r]));

  const { main, sub } = classify(records, sample);
  const suffix = extra.length ? '-merged' : '';
  fs.writeFileSync(path.join(dir, `main${suffix}.csv`), toCsv(main, columnsOf(main)));
  fs.writeFileSync(path.join(dir, `sub${suffix}.csv`), toCsv(sub, columnsOf(sub)));
  for (const run of extra) console.log(`merged ${run}: ${main.filter(r => r.olcum === run).length} sites taken from it`);

  const count = (rows: Row[]) => ['ok', 'engellendi', 'iss_filtresi', 'ulasilamadi', 'hata'].map(k => `${k} ${rows.filter(r => r.erisim === k).length}`).join(', ');
  console.log(`criteria ${CRITERIA_VERSION}: ${main.length} sites (${count(main)}), ${sub.filter(r => r.alan_disi).length ? `${sub.filter(r => r.alan_disi).length} outside domain, ` : ''}${sub.length} subdomains (${count(sub)})`);
  console.log(`wrote ${path.join(dir, `main${suffix}.csv`)} and sub${suffix}.csv`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
