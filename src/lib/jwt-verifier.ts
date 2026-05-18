/**
 * JWT Signature Verifier
 *
 * Verifies JWT signatures using the Web Crypto API.
 * Supports HS256/384/512 (HMAC), RS256/384/512 (RSASSA-PKCS1-v1_5),
 * and ES256/384/512 (ECDSA).
 *
 * Zero dependencies, 100% client-side.
 */

import { parseJWT } from './jwt-decoder';

export type VerifyResult =
  | { ok: true; valid: boolean; algorithm: string }
  | { ok: false; error: string };

interface AlgConfig {
  type: 'HMAC' | 'RSA' | 'ECDSA';
  hash: string;
  namedCurve?: string;
}

const ALG_CONFIG: Record<string, AlgConfig> = {
  'HS256': { type: 'HMAC', hash: 'SHA-256' },
  'HS384': { type: 'HMAC', hash: 'SHA-384' },
  'HS512': { type: 'HMAC', hash: 'SHA-512' },
  'RS256': { type: 'RSA', hash: 'SHA-256' },
  'RS384': { type: 'RSA', hash: 'SHA-384' },
  'RS512': { type: 'RSA', hash: 'SHA-512' },
  'ES256': { type: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },
  'ES384': { type: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' },
  'ES512': { type: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' },
};

// ─── Helpers ────────────────────────────────────────────────────

function base64UrlToBytes(input: string): Uint8Array {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(padLength);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64ToBytes(input: string): Uint8Array {
  const binary = atob(input);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function pemToBytes(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, '')
    .replace(/-----END [A-Z ]+-----/g, '')
    .replace(/\s+/g, '');
  if (!stripped) {
    throw new Error('Empty key body after stripping PEM headers.');
  }
  return base64ToBytes(stripped);
}

// ─── Public: algorithm support check ───────────────────────────

export function isAlgorithmSupported(alg: string): boolean {
  return alg in ALG_CONFIG;
}

export function getSupportedAlgorithms(): string[] {
  return Object.keys(ALG_CONFIG);
}

export function getKeyHint(alg: string): { hint: string; placeholder: string } {
  const config = ALG_CONFIG[alg];
  if (!config) {
    return {
      hint: 'Unsupported algorithm.',
      placeholder: ''
    };
  }
  if (config.type === 'HMAC') {
    return {
      hint: 'Paste the shared secret string used to sign this token. Same secret used by the issuer.',
      placeholder: 'your-256-bit-secret'
    };
  }
  return {
    hint: 'Paste the issuer\'s public key in PEM format (begins with -----BEGIN PUBLIC KEY-----).',
    placeholder: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----'
  };
}

// ─── Public: verify ─────────────────────────────────────────────

export async function verifyJWT(token: string, keyInput: string): Promise<VerifyResult> {
  const parsed = parseJWT(token);
  if (!parsed.ok) {
    return { ok: false, error: `Cannot parse token: ${parsed.error}` };
  }

  const { header, raw } = parsed.data;
  const alg = typeof header.alg === 'string' ? header.alg : null;

  if (!alg) {
    return { ok: false, error: 'Token has no "alg" header — cannot determine verification method.' };
  }

  if (alg.toLowerCase() === 'none') {
    return { ok: false, error: 'Cannot verify a token with alg=none — no signature to verify. This token is unsigned and should be rejected outright.' };
  }

  const config = ALG_CONFIG[alg];
  if (!config) {
    return {
      ok: false,
      error: `Unsupported algorithm: ${alg}. Verifier supports: ${Object.keys(ALG_CONFIG).join(', ')}.`
    };
  }

  const trimmedKey = keyInput.trim();
  if (!trimmedKey) {
    return { ok: false, error: 'Key is empty. Provide a secret (HMAC) or a public key in PEM format (RSA/ECDSA).' };
  }

  // Build signing input as bytes: "header.payload"
  const signingInput = `${raw.header}.${raw.payload}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);

  // Decode signature
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlToBytes(raw.signature);
  } catch {
    return { ok: false, error: 'Could not decode the signature segment.' };
  }

  if (signatureBytes.length === 0) {
    return { ok: false, error: 'Signature segment is empty.' };
  }

  try {
    if (config.type === 'HMAC') {
      const secretBytes = new TextEncoder().encode(trimmedKey);
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        secretBytes,
        { name: 'HMAC', hash: config.hash },
        false,
        ['verify']
      );
      const isValid = await crypto.subtle.verify('HMAC', cryptoKey, signatureBytes, signingInputBytes);
      return { ok: true, valid: isValid, algorithm: alg };
    }

    if (config.type === 'RSA') {
      let keyBytes: Uint8Array;
      try {
        keyBytes = pemToBytes(trimmedKey);
      } catch (err) {
        return { ok: false, error: 'Could not parse PEM-encoded key. Make sure it begins with "-----BEGIN PUBLIC KEY-----".' };
      }

      let cryptoKey: CryptoKey;
      try {
        cryptoKey = await crypto.subtle.importKey(
          'spki',
          keyBytes,
          { name: 'RSASSA-PKCS1-v1_5', hash: config.hash },
          false,
          ['verify']
        );
      } catch (err) {
        return { ok: false, error: 'Public key import failed. Expected an RSA key in SPKI/PEM format. If you have a private key, use the matching public key for verification.' };
      }

      const isValid = await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        cryptoKey,
        signatureBytes,
        signingInputBytes
      );
      return { ok: true, valid: isValid, algorithm: alg };
    }

    if (config.type === 'ECDSA') {
      let keyBytes: Uint8Array;
      try {
        keyBytes = pemToBytes(trimmedKey);
      } catch (err) {
        return { ok: false, error: 'Could not parse PEM-encoded key. Make sure it begins with "-----BEGIN PUBLIC KEY-----".' };
      }

      let cryptoKey: CryptoKey;
      try {
        cryptoKey = await crypto.subtle.importKey(
          'spki',
          keyBytes,
          { name: 'ECDSA', namedCurve: config.namedCurve! },
          false,
          ['verify']
        );
      } catch (err) {
        return { ok: false, error: `Public key import failed. Expected an ECDSA key on curve ${config.namedCurve} in SPKI/PEM format.` };
      }

      const isValid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: config.hash },
        cryptoKey,
        signatureBytes,
        signingInputBytes
      );
      return { ok: true, valid: isValid, algorithm: alg };
    }

    return { ok: false, error: 'Internal: algorithm type not handled.' };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error during verification';
    return { ok: false, error: `Verification failed: ${message}` };
  }
}