import type { APIRoute } from 'astro';
import { env } from 'cloudflare:workers';
import { analyzeHeaders } from '../../lib/headers';
import { isBlockedHost } from '../../lib/ssrf-guard';
import { checkRateLimit } from '../../lib/rate-limit';

export const prerender = false;

const MAX_REDIRECTS = 5;

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

    // Auto-prepend https:// if no protocol — defense in depth, client also normalizes
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
    // the SSRF guard before being followed — otherwise a public URL that
    // 302s to http://169.254.169.254/ would bypass the check above entirely.
    let currentUrl = targetUrl;
    let response: Response | undefined;
    let hops = 0;

    while (hops <= MAX_REDIRECTS) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      try {
        response = await fetch(currentUrl.toString(), {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'HeaderLab/1.0 (+https://headerlab.dev)'
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

    return json({
      url: currentUrl.toString(),
      status: response.status,
      headers,
      analysis
    });
  } catch (err: any) {
    // Don't leak err.message to the client — log it server-side instead.
    console.error('[api/check] unexpected error:', err);
    return json({ error: 'Unexpected error' }, 500);
  }
};