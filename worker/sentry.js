/**
 * Minimal Sentry error reporting for the Worker (https://develop.sentry.dev/sdk/envelopes/).
 * Inert until the SENTRY_DSN secret is set. No SDK: one fetch per error, and nothing about the request is sent
 * beyond the route pattern and method (no URL, query, headers, body, IP or user), with emails and token-like
 * strings scrubbed from the message and stack. Reporting never throws and never delays the response.
 */

const MAX_PER_MINUTE = 20 // per isolate: a failing dependency must not turn into a flood of events
const MAX_TEXT = 4000

let _window = { start: 0, count: 0 }

/** Test hook: forget how many events this isolate has sent this minute. */
export function resetThrottle() { _window = { start: 0, count: 0 } }

/** `https://<key>@<host>/<project>` -> the envelope URL and key, or null if it isn't a usable DSN. */
export function parseDsn(dsn) {
  try {
    const u = new URL(String(dsn || '').trim())
    const project = u.pathname.replace(/^\/+|\/+$/g, '')
    if (u.protocol !== 'https:' || !u.username || !/^\d+$/.test(project)) return null
    return { key: u.username, url: `https://${u.host}/api/${project}/envelope/` }
  } catch { return null }
}

/** Remove what must not leave the Worker: email addresses and long token-like runs (JWTs, hashes, ids, secrets). */
export function scrub(text) {
  return String(text ?? '')
    .replace(/[^\s@'"<>]+@[^\s@'"<>]+\.[^\s@'"<>]+/g, '[email]')
    .replace(/[A-Za-z0-9_+/=.-]{24,}/g, '[redacted]')
    .slice(0, MAX_TEXT)
}

export function buildEvent(err, { route = '', method = '', environment = 'production' } = {}) {
  const e = err instanceof Error ? err : new Error(String(err))
  return {
    event_id: crypto.randomUUID().replace(/-/g, ''),
    timestamp: Date.now() / 1000,
    platform: 'javascript',
    level: 'error',
    server_name: 'trainflow-worker',
    environment,
    tags: { route: String(route).slice(0, 100), method: String(method).slice(0, 10) },
    exception: { values: [{ type: String(e.name || 'Error').slice(0, 100), value: scrub(e.message) }] },
    extra: { stack: scrub(e.stack) },
  }
}

/** Send one error to Sentry. Resolves true when sent; false when disabled, throttled or failed. */
export async function captureException(env, err, context = {}) {
  const dsn = parseDsn(env.SENTRY_DSN)
  if (!dsn) return false
  const now = Date.now()
  if (now - _window.start > 60_000) _window = { start: now, count: 0 }
  if (++_window.count > MAX_PER_MINUTE) return false
  try {
    const event = buildEvent(err, { ...context, environment: env.SENTRY_ENVIRONMENT || 'production' })
    const body = [
      JSON.stringify({ event_id: event.event_id, sent_at: new Date().toISOString() }),
      JSON.stringify({ type: 'event' }),
      JSON.stringify(event),
    ].join('\n')
    const res = await fetch(dsn.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-sentry-envelope', 'X-Sentry-Auth': `Sentry sentry_version=7, sentry_key=${dsn.key}, sentry_client=pregame-worker/1` },
      body,
    })
    if (!res.ok) console.error(`Sentry report failed: HTTP ${res.status}`)
    return res.ok
  } catch (e) {
    console.error(`Sentry report failed: ${e.message}`)
    return false
  }
}
