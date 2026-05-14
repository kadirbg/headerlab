// Security header analysis engine

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type CheckStatus = 'pass' | 'fail' | 'warn';

export interface HeaderCheck {
  id: string;
  name: string;
  present: boolean;
  value: string | null;
  severity: Severity;
  status: CheckStatus;
  description: string;
  recommendation: string;
  reference: string;
}

export interface AnalysisResult {
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  checks: HeaderCheck[];
  summary: { pass: number; fail: number; warn: number };
}

interface HeaderDef {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  reference: string;
  validate: (value: string | undefined, url: URL) => CheckStatus;
}

const HEADER_DEFS: HeaderDef[] = [
  {
    id: 'hsts',
    name: 'Strict-Transport-Security',
    severity: 'critical',
    description: 'Forces browsers to use HTTPS only, preventing downgrade attacks and cookie hijacking on public networks.',
    recommendation: 'Set max-age to at least 31536000 (1 year), with includeSubDomains and preload.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
    validate: (value, url) => {
      if (url.protocol !== 'https:') return 'warn';
      if (!value) return 'fail';
      const m = /max-age=(\d+)/.exec(value);
      if (!m) return 'fail';
      return parseInt(m[1], 10) < 31536000 ? 'warn' : 'pass';
    }
  },
  {
    id: 'csp',
    name: 'Content-Security-Policy',
    severity: 'critical',
    description: 'Mitigates XSS and code injection by whitelisting trusted sources of scripts, styles, and other resources.',
    recommendation: "Start strict: default-src 'self'. Avoid 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for inline scripts.",
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
    validate: (value) => {
      if (!value) return 'fail';
      if (/unsafe-inline|unsafe-eval/i.test(value)) return 'warn';
      return 'pass';
    }
  },
  {
    id: 'xfo',
    name: 'X-Frame-Options',
    severity: 'high',
    description: 'Prevents clickjacking by controlling whether your page can be embedded in iframes on other sites.',
    recommendation: 'Set to DENY if you never need framing, or SAMEORIGIN for same-domain framing. (CSP frame-ancestors is the modern replacement.)',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
    validate: (value) => {
      if (!value) return 'fail';
      const v = value.toUpperCase().trim();
      return (v === 'DENY' || v === 'SAMEORIGIN') ? 'pass' : 'warn';
    }
  },
  {
    id: 'xcto',
    name: 'X-Content-Type-Options',
    severity: 'medium',
    description: 'Prevents browsers from MIME-sniffing the response, which can lead to malicious content being interpreted as something else.',
    recommendation: 'Set to "nosniff".',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
    validate: (value) => {
      if (!value) return 'fail';
      return value.toLowerCase().trim() === 'nosniff' ? 'pass' : 'warn';
    }
  },
  {
    id: 'referrer',
    name: 'Referrer-Policy',
    severity: 'medium',
    description: 'Controls how much URL information is sent in the Referer header when navigating away, preventing leakage of sensitive paths.',
    recommendation: 'Use "strict-origin-when-cross-origin" (default in modern browsers) or "no-referrer" for maximum privacy.',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
    validate: (value) => {
      if (!value) return 'fail';
      const safe = ['no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
      return safe.includes(value.toLowerCase().trim()) ? 'pass' : 'warn';
    }
  },
  {
    id: 'permissions',
    name: 'Permissions-Policy',
    severity: 'low',
    description: 'Restricts which powerful browser features (camera, microphone, geolocation, etc.) can be used on your site.',
    recommendation: 'Explicitly disable features you don\'t use, e.g., "camera=(), microphone=(), geolocation=(), payment=()".',
    reference: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy',
    validate: (value) => (value ? 'pass' : 'fail')
  },
];

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 28, high: 20, medium: 12, low: 6
};

export function analyzeHeaders(headers: Record<string, string>, url: URL): AnalysisResult {
  const checks: HeaderCheck[] = [];
  let totalPossible = 0, totalEarned = 0;
  let pass = 0, fail = 0, warn = 0;

  for (const def of HEADER_DEFS) {
    const value = headers[def.name.toLowerCase()];
    const status = def.validate(value, url);
    const weight = SEVERITY_WEIGHTS[def.severity];

    totalPossible += weight;
    if (status === 'pass') { totalEarned += weight; pass++; }
    else if (status === 'warn') { totalEarned += weight * 0.5; warn++; }
    else { fail++; }

    checks.push({
      id: def.id, name: def.name,
      present: !!value, value: value || null,
      severity: def.severity, status,
      description: def.description, recommendation: def.recommendation,
      reference: def.reference,
    });
  }

  const score = Math.round((totalEarned / totalPossible) * 100);
  const grade = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 70 ? 'B'
              : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';

  return { score, grade, checks, summary: { pass, fail, warn } };
}