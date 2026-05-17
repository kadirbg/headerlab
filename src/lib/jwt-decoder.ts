/**
 * JWT Decoder & Analyzer
 *
 * Pure TypeScript, no dependencies. Decodes JWTs and produces a structured
 * security analysis. All processing happens client-side; nothing is sent
 * over the network.
 *
 * Standards reference: RFC 7519 (JWT), RFC 7515 (JWS).
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface JWTHeader {
  alg?: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: unknown;
}

export interface ParsedJWT {
  header: JWTHeader;
  payload: JWTPayload;
  signature: string;
  raw: {
    header: string;
    payload: string;
    signature: string;
  };
}

export type ParseResult =
  | { ok: true; data: ParsedJWT }
  | { ok: false; error: string };

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation?: string;
}

export interface ClaimInfo {
  name: string;
  value: unknown;
  description: string;
  status?: 'expired' | 'not-yet-valid' | 'future-issued' | 'valid';
  humanReadable?: string;
}

export interface JWTAnalysis {
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  claims: ClaimInfo[];
  algorithm: string | null;
  isExpired: boolean;
  isNotYetValid: boolean;
}

// ─── Base64url decoding ────────────────────────────────────────────────

function base64UrlDecode(input: string): string {
  // base64url → base64
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  // restore padding
  const padLength = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(padLength);

  try {
    const binaryString = atob(base64);
    // Decode UTF-8 properly (atob returns a binary/latin-1 string)
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  } catch {
    throw new Error('Invalid base64url encoding');
  }
}

// ─── Parse ─────────────────────────────────────────────────────────────

export function parseJWT(token: string): ParseResult {
  if (!token || typeof token !== 'string') {
    return { ok: false, error: 'Token is empty.' };
  }

  // trim → strip "Bearer " prefix → strip any internal whitespace from paste
  let cleaned = token.trim().replace(/^Bearer\s+/i, '');
  cleaned = cleaned.replace(/\s/g, '');

  if (!cleaned) {
    return { ok: false, error: 'Token is empty.' };
  }

  const parts = cleaned.split('.');
  if (parts.length !== 3) {
    return {
      ok: false,
      error: `Expected 3 parts separated by dots, got ${parts.length}. Format: header.payload.signature`
    };
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  if (!headerB64 || !payloadB64) {
    return { ok: false, error: 'Header or payload segment is empty.' };
  }

  // Decode header
  let header: JWTHeader;
  try {
    const headerJson = base64UrlDecode(headerB64);
    const parsedHeader = JSON.parse(headerJson);
    if (typeof parsedHeader !== 'object' || parsedHeader === null || Array.isArray(parsedHeader)) {
      return { ok: false, error: 'Header is not a JSON object.' };
    }
    header = parsedHeader;
  } catch {
    return { ok: false, error: 'Cannot decode header — invalid base64url or JSON.' };
  }

  // Decode payload
  let payload: JWTPayload;
  try {
    const payloadJson = base64UrlDecode(payloadB64);
    const parsedPayload = JSON.parse(payloadJson);
    if (typeof parsedPayload !== 'object' || parsedPayload === null || Array.isArray(parsedPayload)) {
      return { ok: false, error: 'Payload is not a JSON object.' };
    }
    payload = parsedPayload;
  } catch {
    return { ok: false, error: 'Cannot decode payload — invalid base64url or JSON.' };
  }

  return {
    ok: true,
    data: {
      header,
      payload,
      signature: signatureB64,
      raw: {
        header: headerB64,
        payload: payloadB64,
        signature: signatureB64
      }
    }
  };
}

// ─── Time helpers ──────────────────────────────────────────────────────

function formatRelativeTime(seconds: number, nowSec: number): string {
  const diff = seconds - nowSec;
  const absDiff = Math.abs(diff);

  const MIN = 60;
  const HOUR = 3600;
  const DAY = 86400;
  const WEEK = DAY * 7;
  const MONTH = DAY * 30;
  const YEAR = DAY * 365;

  let value: number;
  let unit: string;

  if (absDiff < MIN) {
    value = absDiff;
    unit = 'second';
  } else if (absDiff < HOUR) {
    value = Math.floor(absDiff / MIN);
    unit = 'minute';
  } else if (absDiff < DAY) {
    value = Math.floor(absDiff / HOUR);
    unit = 'hour';
  } else if (absDiff < WEEK) {
    value = Math.floor(absDiff / DAY);
    unit = 'day';
  } else if (absDiff < MONTH) {
    value = Math.floor(absDiff / WEEK);
    unit = 'week';
  } else if (absDiff < YEAR) {
    value = Math.floor(absDiff / MONTH);
    unit = 'month';
  } else {
    value = Math.floor(absDiff / YEAR);
    unit = 'year';
  }

  const plural = value === 1 ? '' : 's';
  if (diff > 0) return `in ${value} ${unit}${plural}`;
  if (diff < 0) return `${value} ${unit}${plural} ago`;
  return 'now';
}

function formatAbsoluteTime(seconds: number): string {
  const date = new Date(seconds * 1000);
  return date.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

// ─── Sensitive-key detection ───────────────────────────────────────────

const SENSITIVE_KEY_PATTERNS: RegExp[] = [
  /password/i,
  /passwd/i,
  /^pwd$/i,
  /secret/i,
  /api[_-]?key/i,
  /private[_-]?key/i,
  /credit[_-]?card/i,
  /^ccn$/i,
  /^cvv$/i,
  /^ssn$/i,
  /social[_-]?security/i,
];

function findSensitiveKeys(obj: unknown, path = ''): string[] {
  if (!obj || typeof obj !== 'object') return [];
  const results: string[] = [];
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const fullPath = path ? `${path}.${key}` : key;
    if (SENSITIVE_KEY_PATTERNS.some(p => p.test(key))) {
      results.push(fullPath);
    }
    if (value && typeof value === 'object') {
      results.push(...findSensitiveKeys(value, fullPath));
    }
  }
  return results;
}

// ─── Claim descriptions ────────────────────────────────────────────────

const STANDARD_CLAIM_DESCRIPTIONS: Record<string, string> = {
  iss: 'Issuer — the principal that issued the JWT.',
  sub: 'Subject — the principal that is the subject of the JWT.',
  aud: 'Audience — the recipients the JWT is intended for.',
  exp: 'Expiration time — JWT must not be accepted after this time.',
  nbf: 'Not before — JWT must not be accepted before this time.',
  iat: 'Issued at — when the JWT was issued.',
  jti: 'JWT ID — unique identifier for this JWT.'
};

const STANDARD_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'] as const;

// ─── Algorithm classification ──────────────────────────────────────────

const SYMMETRIC_ALGS = new Set(['HS256', 'HS384', 'HS512']);
const ASYMMETRIC_ALGS = new Set([
  'RS256', 'RS384', 'RS512',
  'ES256', 'ES384', 'ES512',
  'PS256', 'PS384', 'PS512',
  'EdDSA'
]);

// ─── Analyze ───────────────────────────────────────────────────────────

export function analyzeJWT(parsed: ParsedJWT, nowSec?: number): JWTAnalysis {
  const now = nowSec ?? Math.floor(Date.now() / 1000);
  const { header, payload } = parsed;
  const findings: Finding[] = [];

  const alg = typeof header.alg === 'string' ? header.alg : null;

  // ── Algorithm checks ──
  if (!alg) {
    findings.push({
      id: 'missing-alg',
      severity: 'critical',
      title: 'Missing algorithm header',
      description: 'The JWT header does not declare an "alg" claim. A valid JWT must specify its algorithm. This token is malformed or tampered.',
      recommendation: 'Reject the token. Configure your library to require the "alg" header.'
    });
  } else if (alg.toLowerCase() === 'none') {
    findings.push({
      id: 'alg-none',
      severity: 'critical',
      title: 'Algorithm is "none" — token is unsigned',
      description: 'This JWT uses the "none" algorithm, which means no signature is verified. Anyone can create or modify such tokens without detection.',
      recommendation: 'Never accept JWTs with alg=none in production. Configure your library to explicitly reject this algorithm and to enforce an allowlist of expected algorithms.'
    });
  } else if (SYMMETRIC_ALGS.has(alg)) {
    findings.push({
      id: 'symmetric-alg',
      severity: 'info',
      title: `Symmetric algorithm: ${alg}`,
      description: 'This token uses an HMAC-based algorithm with a shared secret. Verification requires the same secret used to sign it.',
      recommendation: 'Ensure your library strictly validates the expected algorithm. Algorithm confusion attacks exploit servers that accept multiple algorithm types — for example, treating an RSA public key as an HMAC secret.'
    });
  } else if (ASYMMETRIC_ALGS.has(alg)) {
    findings.push({
      id: 'asymmetric-alg',
      severity: 'info',
      title: `Asymmetric algorithm: ${alg}`,
      description: 'This token uses public-key cryptography. Verification requires the corresponding public key.'
    });
  } else {
    findings.push({
      id: 'unknown-alg',
      severity: 'medium',
      title: `Unrecognized algorithm: ${alg}`,
      description: `The algorithm "${alg}" is not a standard JWT algorithm. Verify that your library supports it and that this is intentional.`,
      recommendation: 'Prefer standard algorithms: RS256, ES256, or EdDSA for asymmetric; HS256 for symmetric with a strong secret.'
    });
  }

  // ── Expiration & timing ──
  const exp = typeof payload.exp === 'number' ? payload.exp : null;
  const iat = typeof payload.iat === 'number' ? payload.iat : null;
  const nbf = typeof payload.nbf === 'number' ? payload.nbf : null;

  const isExpired = exp !== null && exp < now;
  const isNotYetValid = nbf !== null && nbf > now;

  if (exp === null) {
    findings.push({
      id: 'missing-exp',
      severity: 'medium',
      title: 'No expiration time set',
      description: 'This token does not include an "exp" claim, meaning it never expires from the validator\'s perspective. If compromised, an attacker can use it indefinitely.',
      recommendation: 'Always set an "exp" claim. Typical access tokens expire within minutes to hours; refresh tokens within days.'
    });
  } else if (isExpired) {
    findings.push({
      id: 'expired',
      severity: 'info',
      title: 'Token is expired',
      description: `This token expired ${formatRelativeTime(exp, now)} (at ${formatAbsoluteTime(exp)}). A correctly configured server will reject it.`
    });
  }

  if (iat === null) {
    findings.push({
      id: 'missing-iat',
      severity: 'low',
      title: 'No "issued at" time set',
      description: 'Without an "iat" claim, the age of this token cannot be determined.',
      recommendation: 'Include "iat" to enable age-based validation and audit logging.'
    });
  } else if (iat > now + 60) {
    findings.push({
      id: 'future-issued',
      severity: 'medium',
      title: 'Token issued in the future',
      description: `The "iat" claim is ${formatRelativeTime(iat, now)} — this is suspicious and may indicate clock skew or tampering.`
    });
  }

  // Lifetime check (uses iat if present, otherwise falls back to current time)
  if (exp !== null) {
    const referenceTime = iat ?? now;
    const lifetimeSec = exp - referenceTime;
    const DAY = 86400;
    if (lifetimeSec > 30 * DAY) {
      findings.push({
        id: 'excessive-lifetime',
        severity: 'medium',
        title: 'Excessive token lifetime',
        description: `This token's lifetime is ${Math.floor(lifetimeSec / DAY)} days. Long-lived tokens increase the impact of credential compromise.`,
        recommendation: 'Use short-lived access tokens (minutes to hours) with separate refresh tokens. Reserve long lifetimes for refresh or specific machine-to-machine flows.'
      });
    } else if (lifetimeSec > DAY) {
      findings.push({
        id: 'long-lifetime',
        severity: 'low',
        title: 'Token lifetime exceeds 24 hours',
        description: `This token's lifetime is ${Math.floor(lifetimeSec / 3600)} hours. Consider whether this is appropriate for your use case.`,
        recommendation: 'For user session tokens, prefer shorter lifetimes with refresh tokens.'
      });
    }
  }

  if (isNotYetValid) {
    findings.push({
      id: 'not-yet-valid',
      severity: 'info',
      title: 'Token is not yet valid',
      description: `This token becomes valid ${formatRelativeTime(nbf!, now)} (at ${formatAbsoluteTime(nbf!)}). It will be rejected until then.`
    });
  }

  // ── Sensitive-data check ──
  const sensitiveKeys = findSensitiveKeys(payload);
  if (sensitiveKeys.length > 0) {
    findings.push({
      id: 'sensitive-data',
      severity: 'high',
      title: 'Possibly sensitive data in payload',
      description: `The payload contains keys that may hold sensitive data: ${sensitiveKeys.join(', ')}. JWT payloads are base64-encoded, not encrypted — anyone with the token can read them.`,
      recommendation: 'Never put passwords, secrets, API keys, or personal financial data in a JWT payload. If you need to transport secrets, use JWE (encrypted JWT) instead.'
    });
  }

  // ── Build claims info ──
  const claims: ClaimInfo[] = [];
  for (const claimName of STANDARD_CLAIMS) {
    const value = (payload as Record<string, unknown>)[claimName];
    if (value === undefined) continue;

    let status: ClaimInfo['status'] | undefined;
    let humanReadable: string | undefined;

    if ((claimName === 'exp' || claimName === 'nbf' || claimName === 'iat') && typeof value === 'number') {
      humanReadable = `${formatAbsoluteTime(value)}  (${formatRelativeTime(value, now)})`;
      if (claimName === 'exp' && value < now) status = 'expired';
      if (claimName === 'nbf' && value > now) status = 'not-yet-valid';
      if (claimName === 'iat' && value > now + 60) status = 'future-issued';
    }

    claims.push({
      name: claimName,
      value,
      description: STANDARD_CLAIM_DESCRIPTIONS[claimName],
      status,
      humanReadable
    });
  }

  // ── Summary ──
  const summary = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  };

  return {
    findings,
    summary,
    claims,
    algorithm: alg,
    isExpired,
    isNotYetValid
  };
}