// Security headers for HeaderLab itself.
// Applies to every response served by the Astro Cloudflare worker.

import { defineMiddleware } from 'astro:middleware';

const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  "connect-src 'self' https://cloudflareinsights.com",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'"
].join('; ');

// Comprehensive Permissions-Policy: disable every browser feature we don't use.
// Only exception: clipboard-write=(self) — Copy buttons rely on navigator.clipboard.writeText.
// Alphabetical order for ease of maintenance and review.
const PERMISSIONS_POLICY = [
  'accelerometer=()',
  'autoplay=()',
  'browsing-topics=()',
  'camera=()',
  'clipboard-read=()',
  'clipboard-write=(self)',
  'display-capture=()',
  'encrypted-media=()',
  'fullscreen=()',
  'gamepad=()',
  'geolocation=()',
  'gyroscope=()',
  'hid=()',
  'idle-detection=()',
  'interest-cohort=()',
  'magnetometer=()',
  'microphone=()',
  'midi=()',
  'payment=()',
  'picture-in-picture=()',
  'publickey-credentials-get=()',
  'screen-wake-lock=()',
  'serial=()',
  'sync-xhr=()',
  'usb=()',
  'web-share=()',
  'xr-spatial-tracking=()'
].join(', ');

export const onRequest = defineMiddleware(async (context, next) => {
  const response = await next();
  const headers = response.headers;

  // Apply to every response (safe everywhere)
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  // HTML-only headers (don't apply to JSON API responses)
  const contentType = headers.get('content-type') || '';
  if (contentType.includes('text/html')) {
    headers.set('Content-Security-Policy', CSP);
    headers.set('X-Frame-Options', 'DENY');
    headers.set('Permissions-Policy', PERMISSIONS_POLICY);
  }

  return response;
});