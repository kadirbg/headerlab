// Per-IP rate limiting for /api/check, backed by Cloudflare Workers KV.
//
// Design: fixed window, 60 seconds, 10 requests per IP. Not perfectly
// accurate at window boundaries (a client can do up to ~2x the limit by
// timing requests around the edge) but it's cheap, requires no Durable
// Objects, and fits the free tier. Good enough to stop casual abuse and
// keep this endpoint from being usable as a high-volume open proxy.
//
// IMPORTANT — deployment requirement:
// This expects a KV namespace bound as `RATE_LIMIT_KV` in the Cloudflare
// project's Settings → Bindings (Cloudflare dashboard) — add a "KV namespace"
// binding with variable name RATE_LIMIT_KV pointing at a namespace you create
// under Storage & Databases → KV. The caller (src/pages/api/check.ts) reads
// it via `import { env } from "cloudflare:workers"` — this is the Astro 6 /
// @astrojs/cloudflare 13.x way of reaching bindings. The older
// `Astro.locals.runtime.env` API was removed in Astro 6 and will throw
// `Cannot read properties of undefined (reading 'env')` if used. Until the
// RATE_LIMIT_KV binding exists, this fails OPEN (allows the request) rather
// than breaking the endpoint — see the comment below.

const WINDOW_SECONDS = 60;
const MAX_REQUESTS_PER_WINDOW = 10;

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
}

// Minimal shape of what we need from the KV binding — avoids pulling in
// @cloudflare/workers-types as a hard dependency just for this.
interface KVLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}

export async function checkRateLimit(
  env: Record<string, unknown> | undefined,
  clientIp: string
): Promise<RateLimitResult> {
  const kv = env?.RATE_LIMIT_KV as KVLike | undefined;

  // No KV binding configured yet — fail open. This means rate limiting is
  // not actually enforced until the binding is added in the Cloudflare
  // dashboard. We deliberately don't fail closed (i.e. block everything)
  // because that would take the whole feature down over a missing config
  // step, which is worse for users than temporarily-unlimited requests.
  if (!kv) {
    return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW };
  }

  if (!clientIp || clientIp === 'unknown') {
    // Can't attribute the request to an IP — don't let it bypass the limit
    // silently, but don't block legitimate traffic behind proxies that
    // strip the header either. Treat as a shared bucket.
    clientIp = 'unattributed';
  }

  const windowId = Math.floor(Date.now() / 1000 / WINDOW_SECONDS);
  const key = `rl:${clientIp}:${windowId}`;

  let count = 0;
  try {
    const existing = await kv.get(key);
    count = existing ? parseInt(existing, 10) || 0 : 0;
  } catch {
    // KV read failure — fail open rather than blocking real traffic on an
    // infrastructure blip.
    return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW };
  }

  if (count >= MAX_REQUESTS_PER_WINDOW) {
    return { allowed: false, remaining: 0 };
  }

  try {
    await kv.put(key, String(count + 1), { expirationTtl: WINDOW_SECONDS * 2 });
  } catch {
    // If the write fails we still allow this request through — losing a
    // single counter increment just means the limit is slightly looser
    // this window, not a security hole.
  }

  return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW - count - 1 };
}
