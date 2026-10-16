import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

describe('access requests', () => {
  let h
  beforeEach(async () => { h = await setupHarness() })
  const submit = (body) => h.request('/api/access-requests', { method: 'POST', body })
  const pending = async () => (await h.request('/api/admin/access-requests', { token: h.adminToken() })).json

  it('stores a request, dedupes by email, and always answers 201', async () => {
    expect((await submit({ name: 'Pat Lee', email: 'Pat@Example.com', message: 'Team Alpha' })).status).toBe(201)
    expect((await submit({ name: 'Pat Lee', email: 'pat@example.com' })).status).toBe(201)
    const list = await pending()
    expect(list).toHaveLength(1)
    expect(list[0]).toMatchObject({ name: 'Pat Lee', email: 'pat@example.com' })
  })

  it('does not reveal or duplicate existing accounts', async () => {
    const u = await h.createUser({ name: 'Existing' })
    await h.request(`/api/learners/${u.id}`, { method: 'PATCH', token: h.adminToken(), body: { email: 'have@example.com' } })
    expect((await submit({ name: 'Someone', email: 'have@example.com' })).status).toBe(201)
    expect(await pending()).toHaveLength(0)
  })

  it('validates input and ignores honeypot bots', async () => {
    expect((await submit({ name: '', email: 'a@b.co' })).status).toBe(400)
    expect((await submit({ name: 'X', email: 'not-an-email' })).status).toBe(400)
    expect((await submit({ name: 'Bot', email: 'bot@example.com', website: 'http://spam' })).status).toBe(201)
    expect(await pending()).toHaveLength(0)
  })

  it('rate-limits a single IP', async () => {
    const codes = []
    for (let i = 0; i < 7; i++) codes.push((await h.request('/api/access-requests', { method: 'POST', ip: '9.9.9.9', body: { name: `N${i}`, email: `n${i}@example.com` } })).status)
    expect(codes.slice(-1)[0]).toBe(429)
  })

  it('only admins can list, approve or dismiss', async () => {
    await submit({ name: 'Pat', email: 'pat@example.com' })
    const id = (await pending())[0].id
    const team = await h.createTeam('T')
    const mgr = await h.createUser({ name: 'mgr', role: 'manager', team_id: team })
    expect((await h.request('/api/admin/access-requests', { token: h.managerToken(mgr) })).status).toBe(401)
    expect((await h.request(`/api/admin/access-requests/${id}/approve`, { method: 'POST', token: h.managerToken(mgr), body: {} })).status).toBe(401)
    expect((await h.request('/api/admin/access-requests')).status).toBe(401)
  })

  it('approve creates a learner with the email (and team); dismiss removes from the queue', async () => {
    const team = await h.createTeam('Alpha')
    await submit({ name: 'Pat Lee', email: 'pat@example.com' })
    await submit({ name: 'Sam', email: 'sam@example.com' })
    const [pat, sam] = await pending()
    const ok = await h.request(`/api/admin/access-requests/${pat.id}/approve`, { method: 'POST', token: h.adminToken(), body: { team_id: team } })
    expect(ok.status).toBe(201)
    const row = (await h.db.execute({ sql: 'SELECT role, team_id, email FROM users WHERE id = ?', args: [ok.json.user.id] })).rows[0]
    expect(row).toMatchObject({ role: 'learner', email: 'pat@example.com' })
    expect(Number(row.team_id)).toBe(team)
    expect((await h.request(`/api/admin/access-requests/${sam.id}`, { method: 'DELETE', token: h.adminToken() })).status).toBe(200)
    expect(await pending()).toHaveLength(0)
  })

  it('approve disambiguates a taken name', async () => {
    await h.createUser({ name: 'Pat Lee' })
    await submit({ name: 'Pat Lee', email: 'pat@example.com' })
    const id = (await pending())[0].id
    const ok = await h.request(`/api/admin/access-requests/${id}/approve`, { method: 'POST', token: h.adminToken(), body: {} })
    expect(ok.status).toBe(201)
    expect(ok.json.user.name).toBe('Pat Lee (pat)')
  })

  describe('Clerk invitation on approve', () => {
    afterEach(() => vi.unstubAllGlobals())
    it('emails an invitation when CLERK_SECRET_KEY is set, and still approves if Clerk fails', async () => {
      h.env.CLERK_SECRET_KEY = 'sk_test_x'
      await submit({ name: 'Pat', email: 'pat@example.com' })
      await submit({ name: 'Sam', email: 'sam@example.com' })
      const [pat, sam] = await pending()
      const calls = []
      vi.stubGlobal('fetch', async (url, init) => { calls.push({ url, init }); return { ok: true } })
      const ok = await h.request(`/api/admin/access-requests/${pat.id}/approve`, { method: 'POST', token: h.adminToken(), body: {} })
      expect(ok.json.invited).toBe(true)
      expect(calls[0].url).toBe('https://api.clerk.com/v1/invitations')
      expect(calls[0].init.headers.Authorization).toBe('Bearer sk_test_x')
      expect(JSON.parse(calls[0].init.body)).toMatchObject({ email_address: 'pat@example.com', notify: true, ignore_existing: true })
      vi.stubGlobal('fetch', async () => { throw new Error('network') })
      const ok2 = await h.request(`/api/admin/access-requests/${sam.id}/approve`, { method: 'POST', token: h.adminToken(), body: {} })
      expect(ok2.status).toBe(201)
      expect(ok2.json.invited).toBe(false)
    })
    it('skips Clerk entirely when no secret key is configured', async () => {
      delete h.env.CLERK_SECRET_KEY
      await submit({ name: 'Pat', email: 'pat@example.com' })
      const id = (await pending())[0].id
      const spy = vi.fn(); vi.stubGlobal('fetch', spy)
      const ok = await h.request(`/api/admin/access-requests/${id}/approve`, { method: 'POST', token: h.adminToken(), body: {} })
      expect(ok.json.invited).toBe(false)
      expect(spy).not.toHaveBeenCalled()
    })
  })
})
