// Content Security Policy evaluation engine

import { matchBypassUrl } from './csp-bypass-hosts.ts';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export interface Finding {
  severity: Severity;
  title: string;
  description: string;
  directive?: string;
  recommendation: string;
}

export interface ParsedCSP {
  directives: Map<string, string[]>;
  reportOnly: boolean;
  raw: string;
}

export interface EvaluationResult {
  parsed: ParsedCSP;
  findings: Finding[];
  score: number;
  grade: Grade;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
}

const FETCH_DIRECTIVES = [
  'default-src', 'script-src', 'style-src', 'img-src', 'font-src',
  'connect-src', 'media-src', 'object-src', 'frame-src',
  'worker-src', 'manifest-src', 'child-src'
];

const SEVERITY_PENALTIES: Record<Severity, number> = {
  critical: 25, high: 15, medium: 8, low: 3, info: 0
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4
};

// Keywords ('self', 'unsafe-inline', ...) and scheme sources (https:) are
// case-insensitive per the CSP spec; nonce and hash values are not.
function normalizeSource(token: string): string {
  const lower = token.toLowerCase();
  if (lower.startsWith("'nonce-") || /^'sha(256|384|512)-/.test(lower)) {
    const dash = token.indexOf('-');
    return lower.slice(0, dash + 1) + token.slice(dash + 1);
  }
  if (token.startsWith("'") || /^[a-z][a-z0-9+.-]*:$/i.test(token)) return lower;
  return token;
}

function parseSinglePolicy(policy: string, reportOnly: boolean, raw: string): ParsedCSP {
  const directives = new Map<string, string[]>();
  const parts = policy.split(';').map(s => s.trim()).filter(Boolean);

  for (const part of parts) {
    const tokens = part.split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const directive = tokens[0].toLowerCase();
    // Per CSP3 §2.2.1, a repeated directive is ignored: the first one wins.
    if (directives.has(directive)) continue;
    directives.set(directive, tokens.slice(1).map(normalizeSource));
  }

  return { directives, reportOnly, raw };
}

/**
 * Parses a serialized CSP list. Several CSP headers on one response are joined
 * with ", " by fetch(), and the spec defines each comma-separated part as a
 * separate policy (CSP3 §2.2.2). Each policy is enforced independently.
 */
export function parseCSPList(input: string): ParsedCSP[] {
  let text = input.trim();
  let reportOnly = false;

  // Strip "Content-Security-Policy:" or "Content-Security-Policy-Report-Only:" prefix
  const headerMatch = text.match(/^content-security-policy(-report-only)?\s*:\s*/i);
  if (headerMatch) {
    reportOnly = !!headerMatch[1];
    text = text.slice(headerMatch[0].length);
  }

  return text
    .split(',')
    .map(p => p.trim())
    .filter(Boolean)
    .map(p => parseSinglePolicy(p, reportOnly, p));
}

/** Parses the first policy of a (possibly comma-separated) CSP value. */
export function parseCSP(input: string): ParsedCSP {
  const policies = parseCSPList(input);
  if (policies.length === 0) return { directives: new Map(), reportOnly: false, raw: input.trim() };
  return { ...policies[0], raw: input.trim() };
}

export function evaluateCSP(input: string): EvaluationResult {
  const parsed = parseCSP(input);
  const findings: Finding[] = [];
  const dir = parsed.directives;

  const policyCount = parseCSPList(input).length;
  if (policyCount > 1) {
    findings.push({
      severity: 'info',
      title: `${policyCount} policies found; only the first is evaluated`,
      description: 'The input contains several comma-separated policies, as happens when a response sends more than one CSP header. Browsers enforce every policy, and a resource must pass all of them.',
      recommendation: 'Paste each policy separately to see its findings.'
    });
  }

  // Empty/invalid input
  if (dir.size === 0) {
    findings.push({
      severity: 'critical',
      title: 'No directives found',
      description: 'The CSP appears to be empty or unparseable.',
      recommendation: 'Ensure you pasted a valid CSP. Example: "default-src \'self\'; script-src \'self\'"'
    });
    return finalize(parsed, findings);
  }

  // ===== Script source analysis =====
  const scriptSrc = dir.get('script-src') || dir.get('default-src');
  const scriptDirName = dir.has('script-src') ? 'script-src' : 'default-src';

  if (!scriptSrc) {
    findings.push({
      severity: 'critical',
      title: 'No script-src or default-src',
      description: 'Without script-src (or default-src as fallback), scripts can be loaded from any origin — defeats CSP\'s primary XSS protection.',
      recommendation: "Add `script-src 'self'` or `default-src 'self'` at minimum."
    });
  } else {
    const hasStrictDynamic = scriptSrc.includes("'strict-dynamic'");
    const hasNonceOrHash = scriptSrc.some(s => s.startsWith("'nonce-") || /^'sha(256|384|512)-/.test(s));
    // With 'strict-dynamic', browsers ignore host and scheme sources (and
    // 'self'), so *, https:, http:, data: and allowlisted hosts are inert.
    const allowlistIgnored = hasStrictDynamic;

    if (scriptSrc.includes("'unsafe-inline'")) {
      if (hasNonceOrHash) {
        findings.push({
          severity: 'info',
          title: "'unsafe-inline' present but ignored (nonce/hash present)",
          description: "Browsers supporting CSP Level 2 or later ignore 'unsafe-inline' when the directive also has a nonce or hash. This is a backward-compatibility pattern for legacy browsers.",
          directive: scriptDirName,
          recommendation: "Safe as-is. You can remove 'unsafe-inline' if you don't need legacy browser support."
        });
      } else {
        findings.push({
          severity: 'critical',
          title: "'unsafe-inline' in " + scriptDirName,
          description: "Allows inline <script> blocks and javascript: URLs. Effectively disables CSP's main XSS protection.",
          directive: scriptDirName,
          recommendation: "Remove 'unsafe-inline'. Use nonces ('nonce-...') or hashes ('sha256-...') for inline scripts, or move scripts to external files."
        });
      }
    }

    if (scriptSrc.includes("'unsafe-eval'")) {
      findings.push({
        severity: 'critical',
        title: "'unsafe-eval' in " + scriptDirName,
        description: "Allows eval(), new Function(), setTimeout(string), and setInterval(string). These are major XSS vectors.",
        directive: scriptDirName,
        recommendation: "Remove 'unsafe-eval'. Check if your library has a CSP-friendly build. WebAssembly often needs this — see 'wasm-unsafe-eval' instead."
      });
    }

    if (allowlistIgnored && scriptSrc.some(s => !s.startsWith("'"))) {
      findings.push({
        severity: 'info',
        title: "Host and scheme sources ignored ('strict-dynamic')",
        description: "With 'strict-dynamic', modern browsers ignore host allowlists and scheme sources such as https:. They are kept only as a fallback for older browsers.",
        directive: scriptDirName,
        recommendation: 'No action needed. This is the recommended strict CSP pattern.'
      });
    }

    if (!allowlistIgnored && scriptSrc.includes('*')) {
      findings.push({
        severity: 'critical',
        title: 'Wildcard (*) in ' + scriptDirName,
        description: 'Allows scripts from any origin. Essentially disables CSP for scripts.',
        directive: scriptDirName,
        recommendation: "Replace * with 'self' plus specific trusted origins."
      });
    }

    if (!allowlistIgnored) {
      const allowsEval = scriptSrc.includes("'unsafe-eval'");
      for (const s of scriptSrc) {
        const bypass = matchBypassUrl(s, allowsEval);
        if (!bypass) continue;
        findings.push({
          severity: 'high',
          title: `Allowlisted host with known CSP bypass: ${bypass.hostname}`,
          description: bypass.kind === 'angular'
            ? `${s} serves AngularJS builds. An attacker who can inject HTML can load AngularJS from this host and execute script through its template syntax.`
            : `${s} hosts a JSONP endpoint. An attacker can load it as a script with a chosen callback and execute arbitrary code.`,
          directive: scriptDirName,
          recommendation: "Remove the host from the allowlist, or switch to a nonce-based policy with 'strict-dynamic'."
        });
      }
    }

    if (!allowlistIgnored && scriptSrc.includes('http:')) {
      findings.push({
        severity: 'critical',
        title: 'Plain http: scheme in ' + scriptDirName,
        description: 'Allows scripts loaded over unencrypted HTTP. Attackers on the network can inject malicious code (man-in-the-middle).',
        directive: scriptDirName,
        recommendation: 'Remove http:. Use https: scheme or specific HTTPS origins.'
      });
    }

    if (!allowlistIgnored && scriptSrc.includes('https:')) {
      findings.push({
        severity: 'high',
        title: 'Broad https: scheme in ' + scriptDirName,
        description: 'Allows scripts from any HTTPS origin. Compromised CDNs, open redirects, and JSONP endpoints can still be exploited.',
        directive: scriptDirName,
        recommendation: 'Replace https: with specific origins (e.g., https://cdn.example.com).'
      });
    }

    if (!allowlistIgnored && scriptSrc.includes('data:')) {
      findings.push({
        severity: 'high',
        title: "data: scheme in " + scriptDirName,
        description: "Allows scripts loaded from data: URIs. This is a known XSS vector — attackers can embed scripts directly in data URLs.",
        directive: scriptDirName,
        recommendation: "Remove data: from script-src. There's almost never a legitimate need for it."
      });
    }
  }

  // ===== Style source analysis =====
  const styleSrc = dir.get('style-src') || dir.get('default-src');
  const styleDirName = dir.has('style-src') ? 'style-src' : 'default-src';
  if (styleSrc) {
    if (styleSrc.includes("'unsafe-inline'")) {
      findings.push({
        severity: 'medium',
        title: "'unsafe-inline' in " + styleDirName,
        description: "Allows inline <style> blocks and style attributes. Lower risk than in script-src (no code execution) but permits CSS-based attacks like data exfiltration via background-image URLs.",
        directive: styleDirName,
        recommendation: "Use nonces or hashes if possible. This is a common compromise — many frameworks (Tailwind, CSS-in-JS) require it."
      });
    }
    if (styleSrc.includes('*')) {
      findings.push({
        severity: 'medium',
        title: 'Wildcard (*) in ' + styleDirName,
        description: 'Allows stylesheets from any origin.',
        directive: styleDirName,
        recommendation: "Use 'self' plus specific origins instead."
      });
    }
  }

  // ===== Missing critical directives =====
  if (!dir.has('object-src') && !dir.has('default-src')) {
    findings.push({
      severity: 'high',
      title: 'No object-src directive',
      description: "Without object-src, attackers can use <object>, <embed>, or <applet> to load plugins that bypass other restrictions.",
      recommendation: "Add `object-src 'none'` (recommended for almost all modern sites)."
    });
  } else if (dir.has('object-src')) {
    const obj = dir.get('object-src')!;
    if (!obj.includes("'none'") && obj.length > 0) {
      findings.push({
        severity: 'medium',
        title: "object-src is not 'none'",
        description: "Setting object-src to 'none' is the strictest and recommended for sites that don't use legacy plugins.",
        directive: 'object-src',
        recommendation: "Change to `object-src 'none'` unless you have a specific need for plugins."
      });
    }
  }

  if (!dir.has('base-uri')) {
    findings.push({
      severity: 'medium',
      title: 'No base-uri directive',
      description: "Without base-uri, attackers who inject a <base> tag can change resolution of relative URLs across your page.",
      recommendation: "Add `base-uri 'self'` or `base-uri 'none'`."
    });
  }

  if (!dir.has('frame-ancestors')) {
    findings.push({
      severity: 'medium',
      title: 'No frame-ancestors directive',
      description: "Without frame-ancestors, your page can be embedded in iframes on other sites, enabling clickjacking. Note: default-src does NOT cover frame-ancestors.",
      recommendation: "Add `frame-ancestors 'none'` or `frame-ancestors 'self'`. This replaces the legacy X-Frame-Options header."
    });
  }

  if (!dir.has('form-action')) {
    findings.push({
      severity: 'low',
      title: 'No form-action directive',
      description: "Without form-action, injected <form> tags can redirect submissions to attacker-controlled servers.",
      recommendation: "Add `form-action 'self'`."
    });
  }

  // ===== Wildcards in other fetch directives =====
  for (const d of FETCH_DIRECTIVES) {
    if (['script-src', 'default-src', 'style-src', 'object-src'].includes(d)) continue;
    const sources = dir.get(d);
    if (sources?.includes('*')) {
      findings.push({
        severity: 'high',
        title: `Wildcard (*) in ${d}`,
        description: `Allows resources from any origin for ${d}.`,
        directive: d,
        recommendation: 'Replace * with specific origins.'
      });
    }
  }

  // ===== Deprecated directives =====
  const deprecated: Record<string, string> = {
    'referrer': 'Use the standalone Referrer-Policy HTTP header instead.',
    'block-all-mixed-content': 'Deprecated. Modern browsers block mixed content by default.',
    'plugin-types': 'Removed from the spec. Use `object-src \'none\'` to block plugins entirely.',
    'prefetch-src': 'Deprecated. Removed from Chrome and most browsers.'
  };
  for (const [d, msg] of Object.entries(deprecated)) {
    if (dir.has(d)) {
      findings.push({
        severity: 'info',
        title: `Deprecated directive: ${d}`,
        description: msg,
        directive: d,
        recommendation: 'Remove this directive from your policy.'
      });
    }
  }

  // ===== Positive signals =====
  if (scriptSrc?.includes("'strict-dynamic'")) {
    findings.push({
      severity: 'info',
      title: "Modern CSP3 pattern: 'strict-dynamic' detected",
      description: "Your CSP uses 'strict-dynamic', which trusts scripts loaded by other already-trusted scripts. This is the recommended modern approach.",
      directive: scriptDirName,
      recommendation: 'No action needed — this is good practice.'
    });
  }

  if (parsed.reportOnly) {
    findings.push({
      severity: 'info',
      title: 'Policy is in Report-Only mode',
      description: 'This CSP uses Content-Security-Policy-Report-Only header — violations are logged but not blocked.',
      recommendation: "Report-only is great for testing. Once confident, switch to the enforcing Content-Security-Policy header."
    });
  }

  return finalize(parsed, findings);
}

function finalize(parsed: ParsedCSP, findings: Finding[]): EvaluationResult {
  const summary = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
    total: findings.length
  };

  let score = 100;
  score -= summary.critical * SEVERITY_PENALTIES.critical;
  score -= summary.high * SEVERITY_PENALTIES.high;
  score -= summary.medium * SEVERITY_PENALTIES.medium;
  score -= summary.low * SEVERITY_PENALTIES.low;
  score = Math.max(0, score);

  const grade: Grade =
    score >= 95 ? 'A+' :
    score >= 85 ? 'A' :
    score >= 70 ? 'B' :
    score >= 55 ? 'C' :
    score >= 35 ? 'D' : 'F';

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  return { parsed, findings, score, grade, summary };
}