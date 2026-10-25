// Research scanner: collects raw HTTP response data for a list of sites.
//
// For every site in the sample it records, without interpreting anything:
//   1. the redirect chain of http://<domain>/
//   2. the redirect chain of https://<domain>/
//   3. CSP <meta> tags of the main page and the hosts it links to
//   4. the chains of up to N linked subdomains (secondary layer, rule K1)
// If the bare domain answers on neither scheme, www.<domain> is tried (C6).
// Every chain becomes one JSON line in scan.jsonl. Classification is a separate
// step (classify.ts) so the raw data can be re-analysed without re-scanning.
//
// Usage (Node.js 22+):
//   node --experimental-strip-types research/scanner/scan.ts \
//     --input research/data/sample/orneklem_v1.csv --run pilot-1 [--limit 20]
//   --only-file <txt> scans only the domains listed (one per line), e.g. a
//   re-measurement of sites whose first measurement failed at network level.
//
// Politeness: one GET per page, no forms or logins, at most --concurrency
// sites at a time, --gap ms between consecutive requests to the same site.

import { parseArgs } from 'node:util';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchChain, sleep, REQUEST_HEADERS, type ChainResult, type FetchOptions } from './http.ts';
import { extractLinkHosts, extractMetaCsp, selectSubdomains } from './html.ts';
import { parseCsv } from './csv.ts';

export const SCHEMA_VERSION = 1;

/** Update the Chrome version to the one installed on the scanning machine. */
export const DEFAULT_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 HeaderLabResearch/1.0 (+https://headerlab.dev/research)';

export interface ScanRecord {
  schema: number;
  run: string;
  domain: string;
  layer: 'main' | 'sub';
  host: string;
  scheme: 'http' | 'https';
  started: string;
  startUrl: string;
  hops: ChainResult['hops'];
  finalUrl: string | null;
  finalStatus: number | null;
  error: string | null;
  body: ChainResult['body'];
  metaCsp: { value: string; reportOnly: boolean }[];
  /** Only on the main https (or http fallback) record: linked hosts and the selection. */
  linkedHosts?: { host: string; links: number }[];
  selectedSubdomains?: string[];
  tool: { commit: string; node: string };
}

export interface ScanConfig {
  run: string;
  fetch: FetchOptions;
  gapMs: number;
  maxSubdomains: number;
  maxRedirects: number;
  commit: string;
}

const iso = () => new Date().toISOString();

function record(cfg: ScanConfig, domain: string, layer: 'main' | 'sub', host: string, scheme: 'http' | 'https', started: string, c: ChainResult): ScanRecord {
  return {
    schema: SCHEMA_VERSION,
    run: cfg.run,
    domain,
    layer,
    host,
    scheme,
    started,
    startUrl: c.startUrl,
    hops: c.hops,
    finalUrl: c.finalUrl,
    finalStatus: c.finalStatus,
    error: c.error,
    body: c.body,
    metaCsp: c.html ? extractMetaCsp(c.html) : [],
    tool: { commit: cfg.commit, node: process.version },
  };
}

const ok = (c: ChainResult) => !c.error && c.finalStatus !== null && c.finalStatus >= 200 && c.finalStatus < 300;

/** Scans one site; returns all its records (written together, so resume is per site). */
export async function scanSite(domain: string, cfg: ScanConfig): Promise<ScanRecord[]> {
  const out: ScanRecord[] = [];
  const chain = (url: string) => fetchChain(url, cfg.fetch, cfg.maxRedirects);

  let t = iso();
  let viaHttp = await chain(`http://${domain}/`);
  let httpRec = record(cfg, domain, 'main', domain, 'http', t, viaHttp);
  out.push(httpRec);

  await sleep(cfg.gapMs);
  t = iso();
  let viaHttps = await chain(`https://${domain}/`);
  let httpsRec = record(cfg, domain, 'main', domain, 'https', t, viaHttps);
  out.push(httpsRec);

  // C6: if the bare domain gave no HTTP response on either scheme, try www.
  const silent = (c: ChainResult) => c.hops.every(h => h.status === null);
  if (silent(viaHttp) && silent(viaHttps) && !domain.startsWith('www.')) {
    const www = `www.${domain}`;
    await sleep(cfg.gapMs);
    t = iso();
    viaHttp = await chain(`http://${www}/`);
    httpRec = record(cfg, domain, 'main', www, 'http', t, viaHttp);
    out.push(httpRec);
    await sleep(cfg.gapMs);
    t = iso();
    viaHttps = await chain(`https://${www}/`);
    httpsRec = record(cfg, domain, 'main', www, 'https', t, viaHttps);
    out.push(httpsRec);
  }

  // The page used for links: the https result if it loaded, else the http one.
  const [page, pageRec] = ok(viaHttps) ? [viaHttps, httpsRec] : [viaHttp, httpRec];
  if (!page.html || !page.finalUrl) return out;

  const counts = extractLinkHosts(page.html, page.finalUrl);
  const mainHosts = [new URL(page.finalUrl).hostname, ...[viaHttp, viaHttps].flatMap(c => c.hops.map(h => new URL(h.url).hostname))];
  const selected = selectSubdomains(counts, domain, mainHosts, cfg.maxSubdomains);
  pageRec.linkedHosts = [...counts.entries()]
    .filter(([h]) => h === domain || h.endsWith(`.${domain}`))
    .map(([host, links]) => ({ host, links }))
    .sort((a, b) => b.links - a.links || a.host.localeCompare(b.host));
  pageRec.selectedSubdomains = selected.map(s => s.host);

  for (const { host } of selected) {
    await sleep(cfg.gapMs);
    t = iso();
    const s = await chain(`https://${host}/`);
    out.push(record(cfg, domain, 'sub', host, 'https', t, s));
    // Fall back to plain HTTP only when HTTPS gave no response at all.
    if (s.error && s.hops.every(h => h.status === null)) {
      await sleep(cfg.gapMs);
      t = iso();
      out.push(record(cfg, domain, 'sub', host, 'http', t, await chain(`http://${host}/`)));
    }
  }
  return out;
}

function gitCommit(): string {
  try {
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const dirty = execFileSync('git', ['status', '--porcelain', '--', 'research/scanner', 'research/criteria', 'src/lib'], { encoding: 'utf8' }).trim();
    return dirty ? `${sha}+dirty` : sha;
  } catch {
    return 'unknown';
  }
}

const sha256File = (p: string) => createHash('sha256').update(fs.readFileSync(p)).digest('hex');

async function main() {
  const { values } = parseArgs({
    options: {
      input: { type: 'string', default: 'research/data/sample/orneklem_v1.csv' },
      run: { type: 'string' },
      out: { type: 'string', default: 'research/output' },
      limit: { type: 'string' },
      only: { type: 'string' },
      'only-file': { type: 'string' },
      concurrency: { type: 'string', default: '4' },
      gap: { type: 'string', default: '2000' },
      timeout: { type: 'string', default: '15000' },
      'max-body': { type: 'string', default: String(2 * 1024 * 1024) },
      'max-subdomains': { type: 'string', default: '10' },
      ua: { type: 'string', default: DEFAULT_UA },
      'opt-out': { type: 'string', default: 'research/data/opt-out.txt' },
    },
  });

  const run = values.run ?? `scan-${iso().slice(0, 10)}`;
  const dir = path.join(values.out!, run);
  fs.mkdirSync(dir, { recursive: true });
  const jsonl = path.join(dir, 'scan.jsonl');
  const manifestPath = path.join(dir, 'manifest.json');

  const sites = parseCsv(fs.readFileSync(values.input!, 'utf8'));
  const optOut = fs.existsSync(values['opt-out']!)
    ? new Set(fs.readFileSync(values['opt-out']!, 'utf8').split(/\r?\n/).map(s => s.trim().toLowerCase()).filter(s => s && !s.startsWith('#')))
    : new Set<string>();
  let domains = sites.map(s => s.alan_adi.toLowerCase()).filter(d => d && !optOut.has(d));
  if (values.only) domains = domains.filter(d => values.only!.split(',').includes(d));
  if (values['only-file']) {
    const keep = new Set(fs.readFileSync(values['only-file'], 'utf8').split(/\r?\n/).map(s => s.trim().toLowerCase()).filter(s => s && !s.startsWith('#')));
    domains = domains.filter(d => keep.has(d));
  }
  if (values.limit) domains = domains.slice(0, Number(values.limit));

  // Resume: skip sites whose records are already in scan.jsonl.
  const done = new Set<string>();
  if (fs.existsSync(jsonl)) {
    for (const line of fs.readFileSync(jsonl, 'utf8').split('\n')) {
      if (line.trim()) done.add((JSON.parse(line) as ScanRecord).domain);
    }
  }
  const todo = domains.filter(d => !done.has(d));

  const cfg: ScanConfig = {
    run,
    fetch: { userAgent: values.ua!, timeoutMs: Number(values.timeout), maxBodyBytes: Number(values['max-body']) },
    gapMs: Number(values.gap),
    maxSubdomains: Number(values['max-subdomains']),
    maxRedirects: 10,
    commit: gitCommit(),
  };

  const manifest: Record<string, unknown> = fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath, 'utf8')) : {};
  manifest.run = run;
  manifest.schema = SCHEMA_VERSION;
  manifest.input = { path: values.input, sha256: sha256File(values.input!), rows: sites.length };
  manifest.optOutCount = optOut.size;
  if (values['only-file']) manifest.onlyFile = { path: values['only-file'], sha256: sha256File(values['only-file']), sites: domains.length };
  manifest.parameters = { concurrency: Number(values.concurrency), gapMs: cfg.gapMs, timeoutMs: cfg.fetch.timeoutMs, maxBodyBytes: cfg.fetch.maxBodyBytes, maxSubdomains: cfg.maxSubdomains, maxRedirects: cfg.maxRedirects, userAgent: cfg.fetch.userAgent, requestHeaders: REQUEST_HEADERS };
  manifest.tool = { commit: cfg.commit, node: process.version, platform: `${process.platform}-${process.arch}` };
  manifest.sessions = [...((manifest.sessions as unknown[]) ?? []), { started: iso(), sites: todo.length, resumedAfter: done.size }];
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  console.log(`run ${run}: ${todo.length} site to scan (${done.size} already done, ${optOut.size} opted out)`);
  const out = fs.createWriteStream(jsonl, { flags: 'a' });
  let finished = 0;
  let failed = 0;
  const queue = [...todo];

  async function worker() {
    for (;;) {
      const domain = queue.shift();
      if (!domain) return;
      try {
        const recs = await scanSite(domain, cfg);
        out.write(recs.map(r => JSON.stringify(r)).join('\n') + '\n');
        const main = recs.filter(r => r.layer === 'main');
        if (main.every(r => r.error)) failed++;
        finished++;
        const subs = recs.filter(r => r.layer === 'sub').length;
        console.log(`[${finished}/${todo.length}] ${domain}  ${main.map(r => `${r.scheme}:${r.finalStatus ?? r.error}`).join(' ')}  +${subs} sub`);
      } catch (e) {
        failed++;
        finished++;
        console.error(`[${finished}/${todo.length}] ${domain}  INTERNAL ERROR ${(e as Error).message}`);
      }
    }
  }

  await Promise.all(Array.from({ length: Math.max(1, Number(values.concurrency)) }, worker));
  await new Promise<void>(r => out.end(r));

  const sessions = manifest.sessions as Record<string, unknown>[];
  Object.assign(sessions[sessions.length - 1], { finished: iso(), scanned: finished, unreachable: failed });
  manifest.output = { file: 'scan.jsonl', sha256: sha256File(jsonl) };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  console.log(`\ndone: ${finished} scanned, ${failed} unreachable`);
  console.log(`scan.jsonl sha256 ${manifest.output && (manifest.output as { sha256: string }).sha256}`);
  console.log('Seal it with an RFC 3161 timestamp: see research/README.md, "Sealing the raw data".');
}

// Run only when executed directly, not when imported by tests.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(e => {
    console.error(e);
    process.exit(1);
  });
}
