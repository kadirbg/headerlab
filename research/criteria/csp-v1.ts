// Criteria set v1 (ölçüt seti v1) — CSP effectiveness classification.
//
// Implements the frozen classification rules of criteria set v1
// (2026-10-17) exactly as written. It deliberately does NOT reuse
// HeaderLab's A–F grade: the study reports rule-based classes, not a
// weighted score. Only the parser is shared with the website.
//
// Rules are applied in order; the first match wins:
//   1. yok              – no CSP at all
//   2. uygulanmiyor     – only Content-Security-Policy-Report-Only
//   3. xss_kapsami_yok  – no script-src and no default-src
//   4. atlatilabilir    – effective script policy has H1, H2, H3 or H4
//   5. etkili           – nonce/hash, allowlist only with 'strict-dynamic',
//                         object-src 'none', base-uri 'none' or 'self'
//   6. kismen_etkili    – everything else
//
// Two clarifications of v1 are implemented here (see the criteria changelog
// in research/README.md); they follow browser behaviour and do not change the
// intent of a rule:
//   C1. Under 'strict-dynamic' browsers ignore host and scheme sources, so *,
//       https:, http:, data: and risky hosts do not trigger rule 4 (H2–H4).
//       v1 states this for *, https:, http: and risky hosts; C1 extends it to
//       data:, which browsers ignore the same way.
//   C2. A script policy that is exactly 'none' blocks all script, so it meets
//       the "nonce or hash" condition of rule 5.

import { parseCSPList, type ParsedCSP } from '../../src/lib/csp-evaluator.ts';
import { matchBypassUrl } from '../../src/lib/csp-bypass-hosts.ts';

export const CRITERIA_VERSION = 'v1';
export const CRITERIA_DATE = '2026-10-17';

export type CspClass =
  | 'yok'
  | 'uygulanmiyor'
  | 'xss_kapsami_yok'
  | 'atlatilabilir'
  | 'kismen_etkili'
  | 'etkili';

/**
 * Error flags, recorded independently of the class:
 * H1 'unsafe-inline' without nonce/hash · H2 wildcard or bare scheme ·
 * H3 data: · H4 risky allowlisted host · H5 no effective object-src ·
 * H6 no base-uri · H7 'unsafe-eval' · H8 only Report-Only · H9 no script directive
 */
export type CspFlag = 'H1' | 'H2' | 'H3' | 'H4' | 'H5' | 'H6' | 'H7' | 'H8' | 'H9';

export type CspSource = 'header' | 'meta';

export interface CspInput {
  /** Header or meta value; may hold several comma-separated policies. */
  value: string;
  source: CspSource;
  reportOnly: boolean;
}

export interface PolicyResult {
  raw: string;
  source: CspSource;
  reportOnly: boolean;
  cls: CspClass;
  flags: CspFlag[];
}

export interface CspResult {
  cls: CspClass;
  /** Flags of the policy that determined the class (or H8 when report-only). */
  flags: CspFlag[];
  /** Every policy seen, enforced and report-only, with its own result. */
  policies: PolicyResult[];
  enforcedCount: number;
  reportOnlyCount: number;
  /** Where enforced policies came from: 'header', 'meta' or 'both'. */
  enforcedFrom: 'header' | 'meta' | 'both' | null;
}

const RANK: Record<CspClass, number> = {
  yok: 0,
  uygulanmiyor: 1,
  xss_kapsami_yok: 2,
  atlatilabilir: 3,
  kismen_etkili: 4,
  etkili: 5,
};

const FLAG_ORDER: CspFlag[] = ['H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'H7', 'H8', 'H9'];

const isNonceOrHash = (s: string) => s.startsWith("'nonce-") || /^'sha(256|384|512)-/.test(s);

/** Sources that allow script from any (secure) origin. */
const isBroad = (s: string) =>
  s === '*' || s === 'https:' || s === 'http:' || /^https?:\/\/\*$/.test(s);

const sortFlags = (flags: Set<CspFlag>) => FLAG_ORDER.filter(f => flags.has(f));

/** Classifies one parsed policy as if it were enforced (rules 3–6). */
export function classifyPolicy(p: ParsedCSP): { cls: CspClass; flags: CspFlag[] } {
  const d = p.directives;
  const flags = new Set<CspFlag>();

  const script = d.get('script-src') ?? d.get('default-src');
  if (!script) {
    flags.add('H9');
    return { cls: 'xss_kapsami_yok', flags: sortFlags(flags) };
  }

  const scriptNone = script.length === 1 && script[0] === "'none'"; // C2
  const nonceOrHash = script.some(isNonceOrHash);
  const strictDynamic = script.includes("'strict-dynamic'");
  const allowsEval = script.includes("'unsafe-eval'");

  // Host and scheme sources ('self' and other keywords excluded).
  const allowlist = script.filter(s => !s.startsWith("'"));
  // What the browser actually honours (C1).
  const effectiveAllowlist = strictDynamic ? [] : allowlist;

  if (script.includes("'unsafe-inline'") && !nonceOrHash) flags.add('H1');
  if (effectiveAllowlist.some(isBroad)) flags.add('H2');
  if (effectiveAllowlist.includes('data:')) flags.add('H3');
  if (effectiveAllowlist.some(s => matchBypassUrl(s, allowsEval) !== null)) flags.add('H4');

  const objectEffective = d.get('object-src') ?? d.get('default-src');
  if (!objectEffective) flags.add('H5');
  if (!d.has('base-uri')) flags.add('H6');
  if (allowsEval) flags.add('H7');

  if (flags.has('H1') || flags.has('H2') || flags.has('H3') || flags.has('H4')) {
    return { cls: 'atlatilabilir', flags: sortFlags(flags) };
  }

  const objectNone = !!objectEffective && objectEffective.length === 1 && objectEffective[0] === "'none'";
  const base = d.get('base-uri');
  const baseOk = !!base && base.length === 1 && (base[0] === "'none'" || base[0] === "'self'");
  const allowlistOk = allowlist.length === 0 || strictDynamic;

  if ((nonceOrHash || scriptNone) && allowlistOk && objectNone && baseOk) {
    return { cls: 'etkili', flags: sortFlags(flags) };
  }
  return { cls: 'kismen_etkili', flags: sortFlags(flags) };
}

/**
 * Classifies everything a page sent: CSP headers, CSP-Report-Only headers and
 * <meta http-equiv> policies. Browsers ignore Report-Only in a meta tag, so
 * such inputs are dropped. With several enforced policies the browser applies
 * all of them; v1 assigns the class of the most protective single policy.
 */
export function classifyCsp(inputs: CspInput[]): CspResult {
  const policies: PolicyResult[] = [];

  for (const input of inputs) {
    if (input.source === 'meta' && input.reportOnly) continue;
    for (const p of parseCSPList(input.value)) {
      if (p.directives.size === 0) continue;
      const { cls, flags } = classifyPolicy(p);
      policies.push({ raw: p.raw, source: input.source, reportOnly: input.reportOnly, cls, flags });
    }
  }

  const enforced = policies.filter(p => !p.reportOnly);
  const reportOnlyCount = policies.length - enforced.length;

  if (policies.length === 0) {
    return { cls: 'yok', flags: [], policies, enforcedCount: 0, reportOnlyCount: 0, enforcedFrom: null };
  }
  if (enforced.length === 0) {
    return { cls: 'uygulanmiyor', flags: ['H8'], policies, enforcedCount: 0, reportOnlyCount, enforcedFrom: null };
  }

  const best = enforced.reduce((a, b) => (RANK[b.cls] > RANK[a.cls] ? b : a));
  const fromHeader = enforced.some(p => p.source === 'header');
  const fromMeta = enforced.some(p => p.source === 'meta');

  return {
    cls: best.cls,
    flags: best.flags,
    policies,
    enforcedCount: enforced.length,
    reportOnlyCount,
    enforcedFrom: fromHeader && fromMeta ? 'both' : fromHeader ? 'header' : 'meta',
  };
}
