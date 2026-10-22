import { describe, it, expect, vi, afterEach } from 'vitest'
import { parseDsn, scrub, buildEvent, captureException, resetThrottle } from '../sentry.js'
import { setupHarness } from './helpers.mjs'

const DSN = 'https://abc123@o1.ingest.sentry.io/4567'

afterEach(() => { vi.restoreAllMocks(); resetThrottle() })

describe('sentry reporter', () => {
  it('parses a DSN and rejects unusable ones', () => {
    expect(parseDsn(DSN)).toEqual({ key: 'abc123', url: 'https://o1.ingest.sentry.io/api/4567/envelope/' })
    for (const bad of ['', undefined, 'not a url', 'http://k@host/1', 'https://host/1', 'https://k@host/abc']) expect(parseDsn(bad)).toBeNull()
  })

  it('scrubs emails and token-like strings', () => {
    const out = scrub('failed for pat@example.com with eyJhbGciOiJIUzI1NiJ9.eyJpZCI6InUxIn0.abcdefghijklmnop and pbkdf2v1:salt:hash')
    expect(out).not.toContain('pat@example.com')
    expect(out).not.toContain('eyJhbGci')
    expect(out).toContain('[email]')
  })

  it('builds an event with the route and method only', () => {
    const ev = buildEvent(new TypeError('boom'), { route: '/api/courses/:id', method: 'GET' })
    expect(ev.exception.values[0]).toEqual({ type: 'TypeError', value: 'boom' })
    expect(ev.tags).toEqual({ route: '/api/courses/:id', method: 'GET' })
    expect(ev.event_id).toMatch(/^[0-9a-f]{32}$/)
    expect(JSON.stringify(ev)).not.toMatch(/authorization|password|cookie/i)
  })

  it('does nothing without a DSN', async () => {
    const f = vi.spyOn(globalThis, 'fetch')
    expect(await captureException({}, new Error('x'))).toBe(false)
    expect(f).not.toHaveBeenCalled()
  })

  it('posts an envelope to Sentry', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', { status: 200 }))
    expect(await captureException({ SENTRY_DSN: DSN, SENTRY_ENVIRONMENT: 'staging' }, new Error('oops'), { route: '/r', method: 'POST' })).toBe(true)
    const [url, init] = f.mock.calls[0]
    expect(url).toBe('https://o1.ingest.sentry.io/api/4567/envelope/')
    expect(init.headers['X-Sentry-Auth']).toContain('sentry_key=abc123')
    const lines = init.body.split('\n').map(l => JSON.parse(l))
    expect(lines[1]).toEqual({ type: 'event' })
    expect(lines[2]).toMatchObject({ environment: 'staging', exception: { values: [{ type: 'Error', value: 'oops' }] } })
  })

  it('never throws when Sentry is unreachable', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network'))
    expect(await captureException({ SENTRY_DSN: DSN }, new Error('x'))).toBe(false)
  })

  it('throttles a flood of errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', { status: 200 }))
    const results = []
    for (let i = 0; i < 30; i++) results.push(await captureException({ SENTRY_DSN: DSN }, new Error('x')))
    expect(results.filter(Boolean).length).toBeLessThanOrEqual(20)
  })
})

describe('unhandled route errors', () => {
  it('are reported with the route pattern but not the URL, token or body, and the client still gets a generic 500', async () => {
    const h = await setupHarness()
    h.env.SENTRY_DSN = DSN
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const f = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', { status: 200 }))
    const token = h.adminToken()
    await h.request('/api/sections', { token }) // first request creates the lazily-built tables
    await h.db.execute('DROP TABLE sections')
    f.mockClear()
    const res = await h.request('/api/sections?secret=1', { token })
    expect(res.status).toBe(500)
    expect(res.json).toEqual({ error: 'Internal server error' })
    const sent = f.mock.calls.find(([u]) => String(u).includes('sentry.io'))
    expect(sent).toBeTruthy()
    const event = JSON.parse(sent[1].body.split('\n')[2])
    expect(event.tags.route).toBe('/api/sections')
    expect(sent[1].body).not.toContain('secret=1')
    expect(sent[1].body).not.toContain(await token)
  })
})
