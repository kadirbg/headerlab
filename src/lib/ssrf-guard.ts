// SSRF guard for /api/check.
//
// HeaderLab's only server-side behavior is "fetch a URL the user gave us and
// read the response headers." That makes the Worker a generic HTTP proxy
// unless every request is checked against the internal network first — both
// the initial URL and every redirect hop, since a public URL can legally
// 302 to a private address.
//
// What this does NOT do: resolve DNS and check the resolved IP. The
// `fetch()` available in Cloudflare Workers doesn't expose a pre-connect
// hook, so a hostname that *currently* resolves to a public IP but is
// rebound to 169.254.169.254 after this check (DNS rebinding) is not
// covered here. That's an accepted gap for v1 — see SECURITY.md. Literal
// IPs and well-known internal/metadata hostnames are covered, which blocks
// the vast majority of realistic SSRF attempts against this endpoint.

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal', // GCP metadata
  '0.0.0.0',
]);

// IPv4 ranges that should never be reachable from a public-facing scanner.
const BLOCKED_IPV4_PATTERNS: RegExp[] = [
  /^127\./,                          // loopback
  /^10\./,                           // RFC1918 private
  /^192\.168\./,                     // RFC1918 private
  /^172\.(1[6-9]|2\d|3[01])\./,      // RFC1918 private (172.16.0.0/12)
  /^169\.254\./,                     // link-local + cloud metadata (AWS/Azure/GCP all use 169.254.169.254)
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // 100.64.0.0/10 (CGNAT, also used by some metadata services)
  /^0\./,                            // 0.0.0.0/8
  /^198\.18\./,                      // benchmarking range, sometimes used internally
  /^198\.19\./,
];

// IPv6 — covers loopback, unique local, and link-local.
function isBlockedIpv6(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === '::1' || h === '::') return true;
  if (h.startsWith('fc') || h.startsWith('fd')) return true; // fc00::/7 unique local
  if (h.startsWith('fe80')) return true; // link-local
  // IPv4-mapped IPv6, e.g. ::ffff:127.0.0.1 — re-check the embedded IPv4 part
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);
  if (mapped && isBlockedIpv4(mapped[1])) return true;
  return false;
}

function isBlockedIpv4(host: string): boolean {
  return BLOCKED_IPV4_PATTERNS.some((re) => re.test(host));
}

function looksLikeIpv4(host: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * Returns true if the hostname should be blocked from outbound fetch.
 * Hostname is expected exactly as it comes from `new URL(...).hostname`
 * (already lowercased, brackets stripped for IPv6 by the URL parser... no —
 * URL keeps brackets for IPv6, so we strip them in isBlockedIpv6).
 */
export function isBlockedHost(hostname: string): boolean {
  const host = hostname.toLowerCase();

  if (BLOCKED_HOSTNAMES.has(host)) return true;

  // Any hostname ending in .local or .internal is almost always intranet-only
  if (host.endsWith('.local') || host.endsWith('.internal')) return true;

  if (looksLikeIpv4(host)) return isBlockedIpv4(host);

  if (host.includes(':') || host.startsWith('[')) return isBlockedIpv6(host);

  return false;
}
