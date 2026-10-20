// HTML extraction for the research scanner: CSP <meta> tags and the hosts
// linked from a page. Dependency-free; tolerant of messy real-world markup.

export interface MetaCsp {
  value: string;
  reportOnly: boolean;
}

const ENTITIES: Record<string, string> = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>', nbsp: ' ' };

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(n) ? String.fromCodePoint(n) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

/** Attributes of one start tag, names lower-cased, values entity-decoded. */
export function parseAttributes(tag: string): Map<string, string> {
  const attrs = new Map<string, string>();
  const body = tag.replace(/^<[a-z0-9]+/i, '').replace(/\/?>$/, '');
  const re = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body))) {
    const name = m[1].toLowerCase();
    if (attrs.has(name)) continue; // first occurrence wins, as in browsers
    attrs.set(name, decodeEntities(m[2] ?? m[3] ?? m[4] ?? ''));
  }
  return attrs;
}

/** Removes comments and script/style contents so their text cannot fake tags. */
function stripNonMarkup(html: string): string {
  return html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style|template|noscript)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '');
}

/**
 * CSP delivered via <meta http-equiv>. Browsers only honour it inside <head>,
 * so tags after </head> (or after <body>) are ignored.
 */
export function extractMetaCsp(html: string): MetaCsp[] {
  const clean = stripNonMarkup(html);
  const end = clean.search(/<\/head\s*>|<body[\s>]/i);
  const head = end === -1 ? clean : clean.slice(0, end);
  const out: MetaCsp[] = [];
  for (const m of head.matchAll(/<meta\b[^>]*>/gi)) {
    const a = parseAttributes(m[0]);
    const equiv = (a.get('http-equiv') ?? '').trim().toLowerCase();
    if (equiv !== 'content-security-policy' && equiv !== 'content-security-policy-report-only') continue;
    const value = (a.get('content') ?? '').trim();
    if (value) out.push({ value, reportOnly: equiv.endsWith('-report-only') });
  }
  return out;
}

/** Counts the hosts of http(s) links (<a href>) on a page, resolved against baseUrl. */
export function extractLinkHosts(html: string, baseUrl: string): Map<string, number> {
  const clean = stripNonMarkup(html);
  let base = baseUrl;
  const baseTag = clean.match(/<base\b[^>]*>/i);
  if (baseTag) {
    const href = parseAttributes(baseTag[0]).get('href');
    if (href) {
      try {
        base = new URL(href, baseUrl).toString();
      } catch { /* keep page URL */ }
    }
  }
  const counts = new Map<string, number>();
  for (const m of clean.matchAll(/<a\b[^>]*>/gi)) {
    const href = parseAttributes(m[0]).get('href');
    if (!href) continue;
    let u: URL;
    try {
      u = new URL(href.trim(), base);
    } catch {
      continue;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    counts.set(host, (counts.get(host) ?? 0) + 1);
  }
  return counts;
}

/**
 * Secondary-layer selection rule (K1): hosts under the site's registered
 * domain, other than the main page's own hosts, ranked by how many links point
 * to them, ties broken alphabetically. Deterministic for a given page.
 */
export function selectSubdomains(counts: Map<string, number>, siteDomain: string, mainHosts: Iterable<string>, max: number): { host: string; links: number }[] {
  const domain = siteDomain.toLowerCase();
  const skip = new Set([domain, `www.${domain}`, ...[...mainHosts].map(h => h.toLowerCase())]);
  return [...counts.entries()]
    .filter(([h]) => h.endsWith(`.${domain}`) && !skip.has(h))
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .slice(0, max)
    .map(([host, links]) => ({ host, links }));
}
