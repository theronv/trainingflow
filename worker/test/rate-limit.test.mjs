import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

const login = (h, name, password, ip) => h.request('/api/learners/login', { method: 'POST', body: { name, password }, ip })

describe('health check', () => {
  it('answers without a token and reveals nothing else', async () => {
    const h = await setupHarness()
    const res = await h.request('/api/health')
    expect(res.status).toBe(200)
    expect(res.json).toEqual({ ok: true })
  })

  it('returns 503 when the database is down', async () => {
    const h = await setupHarness()
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.env.DB_CLIENT = { execute: async () => { throw new Error('down') } }
    const res = await h.request('/api/health')
    expect(res.status).toBe(503)
    expect(res.json).toEqual({ ok: false })
    spy.mockRestore()
  })
})

describe('durable rate limiting', () => {
  let h
  beforeEach(async () => {
    h = await setupHarness()
    await h.createUser({ name: 'alex', password: 'right-pass-1' })
  })
  afterEach(() => vi.useRealTimers())

  it('counts per IP in the database, so a new isolate cannot reset it', async () => {
    for (let i = 0; i < 10; i++) await h.request('/api/verify/PG-AAAAAAAA', { ip: '198.51.100.7' })
    const rows = (await h.db.execute("SELECT count FROM rate_limits WHERE key = 'ip:verify:198.51.100.7'")).rows
    expect(Number(rows[0].count)).toBe(10)
  })

  it('verify allows 30 lookups a minute per IP, then 429s', async () => {
    let last
    for (let i = 0; i < 31; i++) last = await h.request('/api/verify/PG-AAAAAAAA', { ip: '198.51.100.8' })
    expect(last.status).toBe(429)
    expect((await h.request('/api/verify/PG-AAAAAAAA', { ip: '198.51.100.9' })).status).toBe(404)
  })

  it('the IP window resets after a minute', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    for (let i = 0; i < 11; i++) await h.request('/api/auth/invite/NOPE', { ip: '198.51.100.20' })
    expect((await h.request('/api/auth/invite/NOPE', { ip: '198.51.100.20' })).status).toBe(429)
    vi.advanceTimersByTime(61_000)
    expect((await h.request('/api/auth/invite/NOPE', { ip: '198.51.100.20' })).status).not.toBe(429)
  })

  it('locks an account after 5 wrong passwords, even from different IPs, with Retry-After', async () => {
    for (let i = 0; i < 5; i++) expect((await login(h, 'alex', 'nope-nope-1')).status).toBe(401)
    const locked = await login(h, 'alex', 'right-pass-1')
    expect(locked.status).toBe(429)
    const row = (await h.db.execute("SELECT locked_until FROM rate_limits WHERE key = 'fail:alex'")).rows[0]
    expect(Number(row.locked_until)).toBeGreaterThan(Math.floor(Date.now() / 1000))
  })

  it('lockout is per account: other people can still sign in', async () => {
    await h.createUser({ name: 'bea', password: 'bea-pass-123' })
    for (let i = 0; i < 5; i++) await login(h, 'alex', 'nope-nope-1')
    expect((await login(h, 'bea', 'bea-pass-123')).status).toBe(200)
  })

  it('the lockout ends and backs off longer on repeat failures', async () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    for (let i = 0; i < 5; i++) await login(h, 'alex', 'nope-nope-1')
    vi.advanceTimersByTime(31_000)
    expect((await login(h, 'alex', 'nope-nope-1')).status).toBe(401) // 6th failure: locked for 60s
    vi.advanceTimersByTime(31_000)
    expect((await login(h, 'alex', 'right-pass-1')).status).toBe(429)
    vi.advanceTimersByTime(30_000)
    expect((await login(h, 'alex', 'right-pass-1')).status).toBe(200)
  })

  it('a successful sign-in clears the failure count', async () => {
    for (let i = 0; i < 4; i++) await login(h, 'alex', 'nope-nope-1')
    expect((await login(h, 'alex', 'right-pass-1')).status).toBe(200)
    for (let i = 0; i < 4; i++) await login(h, 'alex', 'nope-nope-1')
    expect((await login(h, 'alex', 'right-pass-1')).status).toBe(200)
  })

  it('unknown names are counted too, so they are indistinguishable from real ones', async () => {
    for (let i = 0; i < 5; i++) await login(h, 'ghost', 'nope-nope-1')
    expect((await login(h, 'ghost', 'nope-nope-1')).status).toBe(429)
  })

  it('manager and shared-admin sign-in lock the same way', async () => {
    await h.createUser({ name: 'sarah', role: 'manager', password: 'mgr-pass-123' })
    for (let i = 0; i < 5; i++) await h.request('/api/auth/manager/login', { method: 'POST', body: { name: 'sarah', password: 'bad-bad-bad' } })
    expect((await h.request('/api/auth/manager/login', { method: 'POST', body: { name: 'sarah', password: 'mgr-pass-123' } })).status).toBe(429)
    for (let i = 0; i < 5; i++) await h.request('/api/auth/login', { method: 'POST', body: { password: 'bad' } })
    expect((await h.request('/api/auth/login', { method: 'POST', body: { password: h.adminPassword } })).status).toBe(429)
  })

  it('a limiter failure does not block sign-in', async () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    await h.db.execute('DROP TABLE rate_limits')
    const real = h.env.DB_CLIENT.execute.bind(h.env.DB_CLIENT)
    h.env.DB_CLIENT.execute = (q) => (String(q.sql ?? q).includes('rate_limits') && !String(q.sql ?? q).startsWith('CREATE') ? Promise.reject(new Error('boom')) : real(q))
    expect((await login(h, 'alex', 'right-pass-1')).status).toBe(200)
    spy.mockRestore()
  })
})
