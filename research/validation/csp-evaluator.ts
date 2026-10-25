// Compares the CSP coding of criteria set v1 with Google's CSP Evaluator on
// every reached main page that has an enforced CSP. Offline: works on the raw
// scan files, no network.
//
// Usage (from the repository root, after `npm install` in research/validation):
//   node --experimental-strip-types --no-warnings research/validation/csp-evaluator.ts \
//     --out ../headerlab-veri/output --run ana-1 --merge ana-1b,ana-1c --dest ../headerlab-veri/analiz/v1
//
// The policy compared is the one that decided the v1 class (the most protective
// enforced policy). For each flag, the matching Evaluator finding is:
//   H1 ↔ SCRIPT_UNSAFE_INLINE        H2/H3 ↔ PLAIN_WILDCARD or PLAIN_URL_SCHEMES (script)
//   H4 ↔ SCRIPT_ALLOWLIST_BYPASS (HIGH; MEDIUM_MAYBE is the Evaluator's generic
//        "check this host" note)    H5 ↔ MISSING_DIRECTIVES object-src
//   H6 ↔ MISSING_DIRECTIVES base-uri  H7 ↔ SCRIPT_UNSAFE_EVAL
//   H9 ↔ MISSING_DIRECTIVES script-src
// v1 records H5/H6 only for policies with a script directive, while the
// Evaluator reports base-uri only for nonce/hash policies, so H5 is also
// compared among policies with a script directive and H6 among nonce/hash
// policies (rows H5_kosullu, H6_kosullu).
// and at policy level: v1 "no XSS protection" (xss_kapsami_yok, atlatilabilir)
// ↔ at least one HIGH finding.

import { parseArgs } from 'node:util';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { classify, evaluatePage, filterAddresses, mergeRuns, selectMain } from '../scanner/classify.ts';
import type { ScanRecord } from '../scanner/scan.ts';
import { toCsv } from '../scanner/csv.ts';

const require = createRequire(import.meta.url);
const { CspEvaluator } = require('csp_evaluator/dist/evaluator.js');
const { CspParser } = require('csp_evaluator/dist/parser.js');
const { Type, Severity } = require('csp_evaluator/dist/finding.js');

interface Finding { type: number; severity: number; directive: string; value?: string }

const SCRIPT_DIRS = new Set(['script-src', 'script-src-elem', 'default-src']);

export function evaluatorFlags(policy: string): { flags: Set<string>; high: boolean; findings: Finding[] } {
  const findings: Finding[] = new CspEvaluator(new CspParser(policy).csp).evaluate();
  const has = (t: number, dir?: string) => findings.some(f => f.type === t && (!dir || f.directive === dir));
  const hasScript = (t: number) => findings.some(f => f.type === t && SCRIPT_DIRS.has(f.directive));
  const flags = new Set<string>();
  if (hasScript(Type.SCRIPT_UNSAFE_INLINE)) flags.add('H1');
  if (hasScript(Type.PLAIN_WILDCARD) || hasScript(Type.PLAIN_URL_SCHEMES)) flags.add('H2H3');
  if (findings.some(f => f.type === Type.SCRIPT_ALLOWLIST_BYPASS && f.severity === Severity.HIGH)) flags.add('H4');
  if (has(Type.MISSING_DIRECTIVES, 'object-src')) flags.add('H5');
  if (has(Type.MISSING_DIRECTIVES, 'base-uri')) flags.add('H6');
  if (hasScript(Type.SCRIPT_UNSAFE_EVAL)) flags.add('H7');
  if (has(Type.MISSING_DIRECTIVES, 'script-src')) flags.add('H9');
  return { flags, high: findings.some(f => f.severity === Severity.HIGH), findings };
}

function kappa(a: boolean[], b: boolean[]) {
  const n = a.length;
  const both = a.filter((x, i) => x && b[i]).length;
  const neither = a.filter((x, i) => !x && !b[i]).length;
  const po = (both + neither) / n;
  const pa = a.filter(Boolean).length / n;
  const pb = b.filter(Boolean).length / n;
  const pe = pa * pb + (1 - pa) * (1 - pb);
  return { n, both, onlyV1: a.filter((x, i) => x && !b[i]).length, onlyEvaluator: a.filter((x, i) => !x && b[i]).length, neither, agreement: po, kappa: pe === 1 ? 1 : (po - pe) / (1 - pe) };
}

function main() {
  const { values } = parseArgs({ options: { out: { type: 'string', default: 'research/output' }, run: { type: 'string' }, merge: { type: 'string' }, dest: { type: 'string' } } });
  if (!values.run || !values.dest) throw new Error('--run and --dest are required');
  const load = (run: string) => fs.readFileSync(path.join(values.out!, run, 'scan.jsonl'), 'utf8').split('\n').filter(l => l.trim()).map(l => JSON.parse(l) as ScanRecord);
  const records = mergeRuns([load(values.run), ...(values.merge ? values.merge.split(',').map(load) : [])]);
  const filterIps = filterAddresses(records);
  const rows = classify(records, new Map()).main;

  const byDomain = new Map<string, ScanRecord[]>();
  for (const r of records) (byDomain.get(r.domain) ?? byDomain.set(r.domain, []).get(r.domain)!).push(r);

  const sites: Record<string, unknown>[] = [];
  const pairs: Record<string, [boolean[], boolean[]]> = {};
  const add = (k: string, a: boolean, b: boolean) => { (pairs[k] ??= [[], []]); pairs[k][0].push(a); pairs[k][1].push(b); };

  for (const [domain, recs] of byDomain) {
    const sel = selectMain(recs, domain, filterIps);
    if (!sel.page) continue;
    const csp = evaluatePage(sel.page, sel.hstsChain).csp;
    if (csp.enforcedCount === 0) continue;
    const row = rows.find(r => r.alan_adi === domain)!;
    if (row.csp_sinif !== csp.cls) throw new Error(`class mismatch for ${domain}`);
    const decided = csp.policies.filter(p => !p.reportOnly).find(p => p.cls === csp.cls)!;
    const ev = evaluatorFlags(decided.raw);
    const v1 = new Set(decided.flags.map(f => (f === 'H2' || f === 'H3' ? 'H2H3' : f)));
    for (const k of ['H1', 'H2H3', 'H4', 'H5', 'H6', 'H7', 'H9']) add(k, v1.has(k), ev.flags.has(k));
    if (!v1.has('H9')) add('H5_kosullu', v1.has('H5'), ev.flags.has('H5'));
    if (/'nonce-|'sha(256|384|512)-/.test(decided.raw)) add('H6_kosullu', v1.has('H6'), ev.flags.has('H6'));
    const v1NoProtection = csp.cls === 'xss_kapsami_yok' || csp.cls === 'atlatilabilir';
    add('koruma_yok_vs_HIGH', v1NoProtection, ev.high);
    sites.push({
      alan_adi: domain, v1_sinif: csp.cls, v1_bayraklar: decided.flags.join(' '),
      evaluator_bayraklar: [...ev.flags].join(' '), evaluator_high: ev.high,
      evaluator_bulgular: ev.findings.map(f => `${Type[f.type]}@${f.directive}/${Severity[f.severity]}`).join(' '),
    });
  }

  const summary = Object.entries(pairs).map(([k, [a, b]]) => {
    const s = kappa(a, b);
    return { karsilastirma: k, ...s, agreement: s.agreement.toFixed(3), kappa: s.kappa.toFixed(3) };
  });
  fs.mkdirSync(values.dest, { recursive: true });
  fs.writeFileSync(path.join(values.dest, 'dogrulama_csp_evaluator_siteler.csv'), toCsv(sites, Object.keys(sites[0])));
  fs.writeFileSync(path.join(values.dest, 'dogrulama_csp_evaluator_ozet.csv'), toCsv(summary, Object.keys(summary[0])));
  console.table(summary);
  console.log(`${sites.length} enforced policies compared; written to ${values.dest}`);
}

main();
