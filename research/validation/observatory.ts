// Runs the MDN HTTP Observatory scanner (the open-source scanner behind
// developer.mozilla.org/observatory) on a list of hosts from this machine, so
// its results can be compared with the research scanner measured at the same
// time from the same connection.
//
// Usage (Node.js 24+, after `npm install` in research/validation):
//   node --experimental-strip-types --no-warnings research/validation/observatory.ts \
//     --hosts list.txt --dest <run dir> [--ua "<User-Agent>"] [--gap 2000]
//
// Writes <dest>/observatory.jsonl: one line per host with the scanner's JSON
// output (scan summary and per-test results), the start time and the scanner
// version. Hosts already in the file are skipped (resume).

import { parseArgs } from 'node:util';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgDir = path.join(here, 'node_modules', '@mdn', 'mdn-http-observatory');
const scanJs = path.join(pkgDir, 'src', 'scan.js');
const caBundle = path.join(here, 'node_modules', 'node_extra_ca_certs_mozilla_bundle', 'ca_bundle', 'ca_intermediate_bundle.pem');

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

async function main() {
  const { values } = parseArgs({
    options: {
      hosts: { type: 'string' },
      dest: { type: 'string' },
      ua: { type: 'string' },
      gap: { type: 'string', default: '2000' },
    },
  });
  if (!values.hosts || !values.dest) throw new Error('--hosts and --dest are required');
  if (!fs.existsSync(scanJs)) throw new Error('Observatory not installed: run `npm install` in research/validation');
  if (!fs.existsSync(path.join(pkgDir, 'conf', 'hsts-preload.json'))) throw new Error('Observatory data files missing: run `npm install` in research/validation (needs network for its install step)');
  if (!fs.existsSync(caBundle)) console.warn(`warning: ${caBundle} missing; servers with incomplete chains may fail TLS`);

  const version = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')).version;
  const hosts = fs.readFileSync(values.hosts, 'utf8').split(/\r?\n/).map(s => s.trim().toLowerCase()).filter(s => s && !s.startsWith('#'));
  fs.mkdirSync(values.dest, { recursive: true });
  const out = path.join(values.dest, 'observatory.jsonl');
  const done = new Set(fs.existsSync(out) ? fs.readFileSync(out, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l).host) : []);

  const args = values.ua ? ['--headers', JSON.stringify({ 'User-Agent': values.ua }), '--send-headers-over-http'] : [];
  const todo = hosts.filter(h => !done.has(h));
  console.log(`observatory ${version}: ${todo.length} hosts (${done.size} already done)`);

  for (const [i, host] of todo.entries()) {
    const started = new Date().toISOString();
    const r = spawnSync(process.execPath, [scanJs, host, ...args], {
      env: { ...process.env, NODE_EXTRA_CA_CERTS: caBundle },
      encoding: 'utf8',
      timeout: 180_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    let result: unknown;
    try {
      result = JSON.parse(r.stdout);
    } catch {
      result = { error: `no JSON output (exit ${r.status}${r.error ? `, ${r.error.message}` : ''})`, stderr: r.stderr?.slice(0, 2000) };
    }
    fs.appendFileSync(out, JSON.stringify({ host, started, observatory: version, result }) + '\n');
    const res = result as { scan?: { grade?: string; score?: number }; error?: string };
    console.log(`[${i + 1}/${todo.length}] ${host}  ${res.scan ? `${res.scan.grade} (${res.scan.score})` : `ERROR ${res.error}`}`);
    if (i < todo.length - 1) await sleep(Number(values.gap));
  }
  console.log(`wrote ${out}`);
}

main().catch(e => {
  console.error(e.message ?? e);
  process.exit(1);
});
