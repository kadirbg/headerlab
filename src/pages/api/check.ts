import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { analyzeHeaders } from '../../lib/headers';
import { isBlockedHost } from '../../lib/ssrf-guard';
import { checkRateLimit } from '../../lib/rate-limit';

export const prerender = false;

const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 10000;

// Browser-compatible UA pattern. Many WAFs (F5, Cloudflare, Akamai,
// Imperva) default-block anything that does not look like a real
// browser or a well-known identified bot. The "Mozilla/5.0 (compatible; ...)"
// prefix is the de-facto standard used by Googlebot, Bingbot, Yandex
// and other allowed scanners. We still identify as HeaderLab and point
// to our site, so site owners can trace requests back to us.
const USER_AGENT = 'Mozilla/5.0 (compatible; HeaderLab/1.0; +https://headerlab.dev)';

// Browser-plausible Accept headers further reduce bot-detection false
// positives. A missing Accept header is itself a bot signal for some WAFs.
const ACCEPT_HEADER = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
const ACCEPT_LANGUAGE_HEADER = 'en-US,en;q=0.9';

export const POST: APIRoute = async ({ request }) => {
  const json = (data: unknown, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' }
    });

  // --- Rate limiting: per-IP, cheap to bypass but raises the cost of abuse ---
  const clientIp = request.headers.get('CF-Connecting-IP')
    ?? request.headers.get('x-forwarded-for')
    ?? 'unknown';
  const rl = await checkRateLimit(env as unknown as Record<string, unknown>, clientIp);
  if (!rl.allowed) {
    return json({ error: 'Too many requests. Please slow down.' }, 429);
  }

  try {
    const body = await request.json() as { url?: string };
    let rawUrl = body.url?.trim();
    if (!rawUrl) return json({ error: 'URL is required' }, 400);

    // Auto-prepend https:// if no protocol was given. The client also
    // normalizes, this is defense in depth.
    if (!/^https?:\/\//i.test(rawUrl)) {
      rawUrl = 'https://' + rawUrl;
    }

    let targetUrl: URL;
    try {
      targetUrl = new URL(rawUrl);
    } catch {
      return json({ error: 'Invalid URL format' }, 400);
    }

    if (!['http:', 'https:'].includes(targetUrl.protocol)) {
      return json({ error: 'Only http and https URLs are allowed' }, 400);
    }

    // --- SSRF guard: reject loopback, private, link-local, and metadata hosts ---
    if (isBlockedHost(targetUrl.hostname)) {
      return json({ error: 'This URL points to a restricted network address and cannot be scanned.' }, 403);
    }

    // --- Fetch with timeout, manual redirect handling, and a hop limit ---
    // redirect: 'manual' is required so each hop can be re-validated against
    // the SSRF guard before being followed. Otherwise a public URL that
    // 302s to http://169.254.169.254/ would bypass the check above entirely.
    let currentUrl = targetUrl;
    let response: Response | undefined;
    let hops = 0;

    while (hops <= MAX_REDIRECTS) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      try {
        response = await fetch(currentUrl.toString(), {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': USER_AGENT,
            'Accept': ACCEPT_HEADER,
            'Accept-Language': ACCEPT_LANGUAGE_HEADER
          }
        });
      } catch (err: any) {
        clearTimeout(timeout);
        return json({
          error: err.name === 'AbortError' ? 'Request timed out (10s)' : 'Could not reach the URL'
        }, 502);
      }
      clearTimeout(timeout);

      const isRedirect = response.status >= 300 && response.status < 400;
      const location = response.headers.get('location');

      if (!isRedirect || !location) break;

      hops++;
      if (hops > MAX_REDIRECTS) {
        return json({ error: 'Too many redirects' }, 400);
      }

      let nextUrl: URL;
      try {
        nextUrl = new URL(location, currentUrl);
      } catch {
        return json({ error: 'Invalid redirect target' }, 502);
      }

      if (!['http:', 'https:'].includes(nextUrl.protocol)) {
        return json({ error: 'Redirect to a disallowed protocol was blocked' }, 403);
      }

      if (isBlockedHost(nextUrl.hostname)) {
        return json({ error: 'Redirect target points to a restricted network address and was blocked.' }, 403);
      }

      currentUrl = nextUrl;
    }

    if (!response) {
      return json({ error: 'Could not reach the URL' }, 502);
    }

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const analysis = analyzeHeaders(headers, currentUrl);

    // --- Status-aware advisory ---
    // 4xx/5xx responses rarely carry a site's real security headers. The
    // target server, or a WAF/edge in front of it, is returning an error
    // page instead of the real application. We still return the analysis
    // so the user can see what was actually sent back, but we attach an
    // advisory so the UI can surface it instead of showing a misleading
    // low grade as if the real site were missing every header.
    const advisory = buildAdvisory(response.status);

    return json({
      url: currentUrl.toString(),
      status: response.status,
      headers,
      analysis,
      advisory
    });
  } catch (err: any) {
    // Do not leak err.message to the client. Log it server-side instead.
    console.error('[api/check] unexpected error:', err);
    return json({ error: 'Unexpected error' }, 500);
  }
};

function buildAdvisory(status: number): { code: string; severity: 'info' | 'warning'; message: string } | undefined {
  if (status >= 200 && status < 300) return undefined;

  if (status === 401) {
    return {
      code: 'auth_required_401',
      severity: 'warning',
      message:
        'The server returned HTTP 401 Unauthorized. The headers below come from the auth challenge response and may differ from the authenticated page\'s headers.'
    };
  }

  if (status === 403) {
    return {
      code: 'blocked_403',
      severity: 'warning',
      message:
        'The server returned HTTP 403 Forbidden. This often means a WAF or edge security layer blocked the scan before it reached the real application. The headers below come from the error response and likely do not reflect the site\'s normal configuration. Try scanning a different path on the same origin, or ask the site owner to allow requests from HeaderLab/1.0.'
    };
  }

  if (status === 404) {
    return {
      code: 'not_found_404',
      severity: 'warning',
      message:
        'The server returned HTTP 404 Not Found. The headers below come from the error page and may differ from a valid page\'s configuration. Try scanning a known-good URL on the same origin.'
    };
  }

  if (status === 429) {
    return {
      code: 'rate_limited_429',
      severity: 'warning',
      message:
        'The server returned HTTP 429 Too Many Requests. The scan hit a rate limit before reaching the real application. Try again later.'
    };
  }

  if (status >= 500 && status < 600) {
    return {
      code: 'server_error_5xx',
      severity: 'warning',
      message: `The server returned HTTP ${status}. The headers below come from an error response and may not reflect the site's normal configuration.`
    };
  }

  if (status >= 400 && status < 500) {
    return {
      code: 'client_error_4xx',
      severity: 'warning',
      message: `The server returned HTTP ${status}. The headers below come from an error response and may not reflect the site's normal configuration.`
    };
  }

  return undefined;
}