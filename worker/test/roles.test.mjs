import { describe, it, expect, beforeEach } from 'vitest'
import { verify } from 'hono/jwt'
import { setupHarness } from './helpers.mjs'

const ISS = 'https://test-app.clerk.accounts.dev'
const b64u = (buf) => Buffer.from(buf).toString('base64url')
async function makeClerk(h) {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])
  const jwk = { ...(await crypto.subtle.exportKey('jwk', publicKey)), kid: 'k1' }
  h.env.CLERK_ISSUER = ISS
  h.env.CLERK_JWKS = JSON.stringify({ keys: [jwk] })
  return async (claims = {}) => {
    const now = Math.floor(Date.now() / 1000)
    const head = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'k1' }))
    const body = b64u(JSON.stringify({ iss: ISS, sub: 'user_1', iat: now, exp: now + 60, email: 'pat@example.com', ...claims }))
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(`${head}.${body}`))
    return `${head}.${body}.${b64u(sig)}`
  }
}

describe('multi-role accounts', () => {
  let h, team, mint
  beforeEach(async () => { h = await setupHarness(); team = await h.createTeam('T'); mint = await makeClerk(h) })
  const claims = (t) => verify(t, h.env.JWT_SECRET, 'HS256')

  describe('capabilities in the token', () => {
    it('a manager token with an id can use learner routes (take courses)', async () => {
      const mgr = await h.createUser({ name: 'mia', role: 'manager', team_id: team })
      const course = await h.createCourse()
      await h.assign(course.id, mgr.id)
      const res = await h.request('/api/assignments/me', { token: h.managerToken(mgr) })
      expect(res.status).toBe(200)
      expect(res.json).toHaveLength(1)
      const ans = await h.request('/api/quiz/answer', { method: 'POST', token: h.managerToken(mgr), body: { question_id: course.question_ids[0], selected_index: 0 } })
      expect(ans.status).toBe(200)
    })

    it('an admin token with an id can learn, but the id-less shared-password admin cannot', async () => {
      const boss = await h.createUser({ name: 'boss', is_admin: 1 })
      const withId = await h.mint({ id: boss.id, name: boss.name, role: 'admin', roles: ['learner', 'admin'] })
      expect((await h.request('/api/assignments/me', { token: withId })).status).toBe(200)
      expect((await h.request('/api/admin/teams', { method: 'POST', token: withId, body: { name: 'N' } })).status).toBeLessThan(300)
      expect((await h.request('/api/assignments/me', { token: h.adminToken() })).status).toBe(401)
    })

    it('a learner-only token still cannot reach manager or admin routes', async () => {
      const l = await h.createUser({ name: 'lee' })
      expect((await h.request('/api/assignments', { token: h.learnerToken(l) })).status).toBe(401)
      expect((await h.request('/api/admin/teams', { method: 'POST', token: h.learnerToken(l), body: { name: 'X' } })).status).toBe(401)
    })

    it('admin wins over manager: an admin who is also a manager is not team-scoped', async () => {
      const other = await h.createTeam('Other')
      await h.createUser({ name: 'inOther', team_id: other })
      const both = await h.createUser({ name: 'both', role: 'manager', team_id: team, is_admin: 1 })
      const t = await h.mint({ id: both.id, name: both.name, role: 'admin', roles: ['learner', 'manager', 'admin'], team_id: team })
      const res = await h.request('/api/learners', { token: t })
      expect(res.json.map(u => u.name)).toContain('inOther')
    })
  })

  describe('sessions', () => {
    it('name+password login reports roles; managers and admins can use the learner login too', async () => {
      const mgr = await h.createUser({ name: 'mia', role: 'manager', team_id: team, password: 'manager-pass-1' })
      const res = await h.request('/api/learners/login', { method: 'POST', body: { name: 'mia', password: 'manager-pass-1' } })
      expect(res.status).toBe(200)
      expect(res.json.user).toMatchObject({ id: mgr.id, role: 'manager', roles: ['learner', 'manager'], team_id: team })
      expect(await claims(res.json.token)).toMatchObject({ id: mgr.id, role: 'manager', roles: ['learner', 'manager'] })
    })

    it('an administrator can sign in through the manager login even with a learner role', async () => {
      const u = await h.createUser({ name: 'ada', password: 'admin-pass-99' })
      await h.request(`/api/learners/${u.id}`, { method: 'PATCH', token: h.adminToken(), body: { is_admin: true } })
      const res = await h.request('/api/auth/manager/login', { method: 'POST', body: { name: 'ada', password: 'admin-pass-99' } })
      expect(res.status).toBe(200)
      expect(res.json.user.roles).toEqual(['learner', 'admin'])
      expect((await h.request('/api/admin/teams', { token: res.json.token })).status).toBe(200)
    })

    it('ADMIN_EMAILS creates a learner-capable admin account with a users row, once', async () => {
      h.env.ADMIN_EMAILS = 'Boss@Example.com'
      const t = await mint({ email: 'boss@example.com', sub: 'user_boss' })
      const first = await h.request('/api/auth/clerk/login', { method: 'POST', body: { token: t } })
      expect(first.status).toBe(200)
      expect(first.json.user).toMatchObject({ role: 'admin', roles: ['learner', 'admin'] })
      expect(first.json.user.id).toBeTruthy()
      expect((await h.request('/api/assignments/me', { token: first.json.token })).status).toBe(200)
      const second = await h.request('/api/auth/clerk/login', { method: 'POST', body: { token: await mint({ email: 'boss@example.com', sub: 'user_boss' }) } })
      expect(second.json.user.id).toBe(first.json.user.id)
      const rows = (await h.db.execute({ sql: "SELECT is_admin FROM users WHERE lower(email) = 'boss@example.com'" })).rows
      expect(rows).toHaveLength(1)
      expect(Number(rows[0].is_admin)).toBe(1)
    })

    it('ADMIN_EMAILS promotes an existing learner row linked by email and keeps their courses', async () => {
      h.env.ADMIN_EMAILS = 'pat@example.com'
      const u = await h.createUser({ name: 'pat', team_id: team })
      const course = await h.createCourse()
      await h.assign(course.id, u.id)
      await h.request(`/api/learners/${u.id}`, { method: 'PATCH', token: h.adminToken(), body: { email: 'pat@example.com' } })
      const res = await h.request('/api/auth/clerk/login', { method: 'POST', body: { token: await mint() } })
      expect(res.json.user).toMatchObject({ id: u.id, roles: ['learner', 'admin'] })
      const mine = await h.request('/api/assignments/me', { token: res.json.token })
      expect(mine.json).toHaveLength(1)
    })
  })

  describe('managing roles', () => {
    it('an admin can grant and revoke admin, but not revoke their own', async () => {
      const u = await h.createUser({ name: 'ada' })
      const me = await h.createUser({ name: 'boss', is_admin: 1 })
      const boss = await h.mint({ id: me.id, name: me.name, role: 'admin', roles: ['learner', 'admin'] })
      expect((await h.request(`/api/learners/${u.id}`, { method: 'PATCH', token: boss, body: { is_admin: true } })).status).toBe(200)
      const list = await h.request('/api/learners', { token: boss })
      expect(list.json.find(x => x.id === u.id).is_admin).toBe(1)
      expect((await h.request(`/api/learners/${u.id}`, { method: 'PATCH', token: boss, body: { is_admin: false } })).status).toBe(200)
      const self = await h.request(`/api/learners/${me.id}`, { method: 'PATCH', token: boss, body: { is_admin: false } })
      expect(self.status).toBe(400)
    })

    it('managers cannot change anyone\'s admin flag', async () => {
      const mgr = await h.createUser({ name: 'mia', role: 'manager', team_id: team })
      const u = await h.createUser({ name: 'lee', team_id: team })
      const res = await h.request(`/api/learners/${u.id}`, { method: 'PATCH', token: h.managerToken(mgr), body: { is_admin: true } })
      expect(res.status).toBe(401)
    })
  })

  it('bulk: grant/revoke admin, reject bad roles, never self-revoke', async () => {
    const a = await h.createUser({ name: 'a' }), b = await h.createUser({ name: 'b' })
    const me = await h.createUser({ name: 'boss', is_admin: 1 })
    const boss = await h.mint({ id: me.id, name: me.name, role: 'admin', roles: ['learner', 'admin'] })
    const patch = (body) => h.request('/api/learners/bulk', { method: 'PATCH', token: boss, body })
    expect((await patch({ ids: [a.id, b.id], is_admin: true })).status).toBe(200)
    const flags = async () => (await h.db.execute('SELECT name, is_admin FROM users WHERE name IN (\'a\',\'b\')')).rows.map(r => Number(r.is_admin))
    expect(await flags()).toEqual([1, 1])
    expect((await patch({ ids: [a.id], is_admin: false })).status).toBe(200)
    expect(await flags()).toEqual([0, 1])
    expect((await patch({ ids: [me.id, a.id], is_admin: false })).status).toBe(400)
    expect((await patch({ ids: [a.id], role: 'admin' })).status).toBe(400)
  })
})
