import type { APIRoute } from 'astro';
import { analyzeHeaders } from '../../lib/headers';

export const POST: APIRoute = async ({ request }) => {
  const json = (data: unknown, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json' }
    });

  try {
    const body = await request.json() as { url?: string };
    const rawUrl = body.url?.trim();

    if (!rawUrl) return json({ error: 'URL is required' }, 400);

    let targetUrl: URL;
    try {
      targetUrl = new URL(rawUrl);
    } catch {
      return json({ error: 'Invalid URL format' }, 400);
    }

    if (!['http:', 'https:'].includes(targetUrl.protocol)) {
      return json({ error: 'Only http and https URLs are allowed' }, 400);
    }

    // Fetch with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    let response: Response;
    try {
      response = await fetch(targetUrl.toString(), {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
        headers: {
          'User-Agent': 'HeaderLab/1.0 (+https://headerlab.dev)'
        }
      });
    } catch (err: any) {
      clearTimeout(timeout);
      return json({
        error: err.name === 'AbortError' ? 'Request timed out (10s)' : 'Could not reach the URL',
        details: err.message
      }, 502);
    }
    clearTimeout(timeout);

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const analysis = analyzeHeaders(headers, new URL(response.url || targetUrl.toString()));

    return json({
      url: response.url || targetUrl.toString(),
      status: response.status,
      headers,
      analysis
    });
  } catch (err: any) {
    return json({ error: 'Unexpected error', details: err.message }, 500);
  }
};