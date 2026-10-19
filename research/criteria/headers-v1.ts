// Criteria set v1 (ölçüt seti v1) — header validity rules and variables for
// the comparison with 2016.
//
// Every header is coded with two variables: `_var` (present in the response)
// and `_dogru` (the value actually protects). Decisions K4 and K6 apply:
//   K4  HSTS max-age >= 6 months is "doğru"; >= 1 year with includeSubDomains
//       is reported separately as "güçlü".
//   K6  Cookies are reported at site level ("all cookies Secure"), with
//       cookie-level detail kept in the raw data.
//
// The *_2016 variables reproduce the definitions of Kısa & Tatlı (2016) and
// their SecurityHeaderChecker tool, so that 2016 and 2026 rates are computed
// the same way. They are NOT the project's own measure of correctness.

import { parseCSPList } from '../../src/lib/csp-evaluator.ts';
import { classifyCsp, type CspInput, type CspResult } from './csp-v1.ts';

/** 6 months in seconds (182.5 days), the threshold used by MDN HTTP Observatory. */
export const HSTS_MIN_DOGRU = 15_768_000;
export const HSTS_MIN_GUCLU = 31_536_000;

/** Response headers with lower-case names; a header may occur several times. */
export type HeaderMap = Record<string, string[]>;

export interface HeaderInput {
  /** Final URL after redirects. */
  url: string;
  headers: HeaderMap;
  /** Values of <meta http-equiv="Content-Security-Policy"> tags in the page. */
  metaCsp?: string[];
}

export interface CookieInfo {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

export interface HeaderResult {
  https: boolean;

  hsts_var: boolean;
  hsts_dogru: boolean;
  hsts_guclu: boolean;
  hsts_preload: boolean;
  hsts_max_age: number | null;

  xfo_var: boolean;
  xfo_dogru: boolean;
  frame_ancestors_korur: boolean;
  /** Composite: X-Frame-Options correct OR enforced header CSP frame-ancestors protects. */
  clickjacking_korumasi: boolean;

  xcto_var: boolean;
  xcto_dogru: boolean;

  referrer_var: boolean;
  referrer_dogru: boolean;
  referrer_etkin: string | null;

  permissions_var: boolean;
  feature_policy_var: boolean;

  coop_var: boolean;
  coep_var: boolean;
  corp_var: boolean;

  cerez_sayisi: number;
  /** null when the page sets no cookies. */
  cerez_tum_secure: boolean | null;
  cerez_tum_httponly: boolean | null;
  cerez_tum_samesite: boolean | null;
  cerezler: CookieInfo[];

  xxss_var: boolean;
  xxss_deger: string | null;
  hpkp_var: boolean;

  csp: CspResult;
  /** Any CSP: enforced header, Report-Only header or meta tag. */
  csp_var: boolean;
  /** Enforced Content-Security-Policy response header (what 2016 counted). */
  csp_baslik_var: boolean;

  /** Kısa & Tatlı (2016): none of the ten headers their tool looked for, Set-Cookie included. */
  hic_baslik_yok_2016: boolean;
  /** 2016 tool: any Set-Cookie text contains "httponly". */
  httponly_2016: boolean;
  /** 2016 tool: any Set-Cookie text contains "secure" (substring match, as in 2016). */
  secure_2016: boolean;
}

const first = (h: HeaderMap, name: string): string | undefined => {
  const v = h[name];
  return v && v.length > 0 ? v[0] : undefined;
};
const has = (h: HeaderMap, name: string) => (h[name]?.length ?? 0) > 0;

/** RFC 6797 §6.1: directive names are case-insensitive, values may be quoted. */
export function parseHsts(value: string): { maxAge: number | null; includeSubDomains: boolean; preload: boolean } {
  let maxAge: number | null = null;
  let includeSubDomains = false;
  let preload = false;
  for (const part of value.split(';')) {
    const [rawName, ...rest] = part.split('=');
    const name = rawName.trim().toLowerCase();
    const val = rest.join('=').trim().replace(/^"(.*)"$/, '$1');
    if (name === 'max-age' && maxAge === null && /^\d+$/.test(val)) maxAge = parseInt(val, 10);
    else if (name === 'includesubdomains') includeSubDomains = true;
    else if (name === 'preload') preload = true;
  }
  return { maxAge, includeSubDomains, preload };
}

const REFERRER_TOKENS = new Set([
  'no-referrer',
  'no-referrer-when-downgrade',
  'same-origin',
  'origin',
  'strict-origin',
  'origin-when-cross-origin',
  'strict-origin-when-cross-origin',
  'unsafe-url',
]);
const REFERRER_WEAK = new Set(['unsafe-url', 'no-referrer-when-downgrade']);

/** The browser uses the last recognized token across all Referrer-Policy values. */
export function effectiveReferrerPolicy(values: string[]): string | null {
  const tokens = values.flatMap(v => v.split(',')).map(t => t.trim().toLowerCase()).filter(Boolean);
  for (let i = tokens.length - 1; i >= 0; i--) if (REFERRER_TOKENS.has(tokens[i])) return tokens[i];
  return null;
}

export function parseSetCookie(value: string): CookieInfo {
  const [pair, ...attrs] = value.split(';');
  const name = pair.split('=')[0].trim();
  let secure = false;
  let httpOnly = false;
  let sameSite: string | null = null;
  for (const a of attrs) {
    const [k, ...v] = a.split('=');
    const key = k.trim().toLowerCase();
    if (key === 'secure') secure = true;
    else if (key === 'httponly') httpOnly = true;
    else if (key === 'samesite') sameSite = v.join('=').trim().toLowerCase() || null;
  }
  return { name, secure, httpOnly, sameSite };
}

/** frame-ancestors protects unless it allows any origin ('*' or a bare scheme). */
function frameAncestorsProtects(headers: HeaderMap): boolean {
  // Only enforced CSP headers count: frame-ancestors is ignored in <meta>
  // and in Report-Only policies.
  for (const value of headers['content-security-policy'] ?? []) {
    for (const p of parseCSPList(value)) {
      const fa = p.directives.get('frame-ancestors');
      if (!fa || fa.length === 0) continue;
      if (fa.some(s => s === '*' || s === 'https:' || s === 'http:')) continue;
      return true;
    }
  }
  return false;
}

const HEADERS_2016 = [
  'content-security-policy',
  'x-xss-protection',
  'x-frame-options',
  'strict-transport-security',
  'set-cookie',
  'x-content-type-options',
  'x-download-options',
  'x-permitted-cross-domain-policies',
  'public-key-pins',
  'public-key-pins-report-only',
];

export function evaluateHeadersV1(input: HeaderInput): HeaderResult {
  const h = input.headers;
  const https = new URL(input.url).protocol === 'https:';

  // HSTS: ignored by browsers over plain HTTP; the first header is used.
  const hstsRaw = https ? first(h, 'strict-transport-security') : undefined;
  const hsts = hstsRaw ? parseHsts(hstsRaw) : { maxAge: null, includeSubDomains: false, preload: false };
  const hstsVar = !!hstsRaw;
  const hstsDogru = hstsVar && hsts.maxAge !== null && hsts.maxAge >= HSTS_MIN_DOGRU;

  // X-Frame-Options: several values (or a comma list) must all agree.
  const xfoValues = (h['x-frame-options'] ?? []).flatMap(v => v.split(',')).map(v => v.trim().toUpperCase()).filter(Boolean);
  const xfoDogru = xfoValues.length > 0 && new Set(xfoValues).size === 1 && (xfoValues[0] === 'DENY' || xfoValues[0] === 'SAMEORIGIN');
  const faKorur = frameAncestorsProtects(h);

  const xcto = first(h, 'x-content-type-options');

  const referrerValues = h['referrer-policy'] ?? [];
  const referrerEtkin = effectiveReferrerPolicy(referrerValues);

  const cookieHeaders = h['set-cookie'] ?? [];
  const cerezler = cookieHeaders.map(parseSetCookie);
  const n = cerezler.length;
  const all = (pred: (c: CookieInfo) => boolean) => (n === 0 ? null : cerezler.every(pred));

  const cspInputs: CspInput[] = [
    ...(h['content-security-policy'] ?? []).map(value => ({ value, source: 'header' as const, reportOnly: false })),
    ...(h['content-security-policy-report-only'] ?? []).map(value => ({ value, source: 'header' as const, reportOnly: true })),
    ...(input.metaCsp ?? []).map(value => ({ value, source: 'meta' as const, reportOnly: false })),
  ];
  const csp = classifyCsp(cspInputs);

  const cookieText = cookieHeaders.join(', ').toLowerCase();

  return {
    https,

    hsts_var: hstsVar,
    hsts_dogru: hstsDogru,
    hsts_guclu: hstsDogru && hsts.maxAge! >= HSTS_MIN_GUCLU && hsts.includeSubDomains,
    hsts_preload: hstsVar && hsts.preload,
    hsts_max_age: hsts.maxAge,

    xfo_var: has(h, 'x-frame-options'),
    xfo_dogru: xfoDogru,
    frame_ancestors_korur: faKorur,
    clickjacking_korumasi: xfoDogru || faKorur,

    xcto_var: !!xcto,
    xcto_dogru: !!xcto && xcto.trim().toLowerCase() === 'nosniff',

    referrer_var: referrerValues.length > 0,
    referrer_dogru: referrerEtkin !== null && !REFERRER_WEAK.has(referrerEtkin),
    referrer_etkin: referrerEtkin,

    permissions_var: has(h, 'permissions-policy'),
    feature_policy_var: has(h, 'feature-policy'),

    coop_var: has(h, 'cross-origin-opener-policy'),
    coep_var: has(h, 'cross-origin-embedder-policy'),
    corp_var: has(h, 'cross-origin-resource-policy'),

    cerez_sayisi: n,
    cerez_tum_secure: https ? all(c => c.secure) : n === 0 ? null : false,
    cerez_tum_httponly: all(c => c.httpOnly),
    cerez_tum_samesite: all(c => c.sameSite !== null),
    cerezler,

    xxss_var: has(h, 'x-xss-protection'),
    xxss_deger: first(h, 'x-xss-protection')?.trim() ?? null,
    hpkp_var: has(h, 'public-key-pins'),

    csp,
    csp_var: csp.cls !== 'yok',
    csp_baslik_var: has(h, 'content-security-policy'),

    hic_baslik_yok_2016: !HEADERS_2016.some(name => has(h, name)),
    httponly_2016: cookieText.includes('httponly'),
    secure_2016: cookieText.includes('secure'),
  };
}
