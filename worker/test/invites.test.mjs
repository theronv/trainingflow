import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

describe('Manager invite flow', () => {
  let h, team
  beforeEach(async () => {
    h = await setupHarness()
    team = await h.createTeam('Patient Services')
  })

  const createInvite = (body) => h.request('/api/admin/invites', { method: 'POST', token: h.adminToken(), body })
  const register = (body, ip) => h.request('/api/auth/manager/register', { method: 'POST', body, ip })

  it('admin gets a server-generated, unambiguous 8-char code', async () => {
    const res = await createInvite({ team_id: team })
    expect(res.status).toBe(201)
    expect(res.json.code).toMatch(/^[A-HJ-NP-Z2-9]{8}$/)
  })

  it('only admins can create invites', async () => {
    const mgrTeam = await h.createTeam('Other')
    const mgr = await h.createUser({ name: 'sarah', role: 'manager', team_id: mgrTeam })
    const res = await h.request('/api/admin/invites', { method: 'POST', token: h.managerToken(mgr), body: { team_id: mgrTeam } })
    expect(res.status).toBe(401)
  })

  it('rejects an unknown team and a bad expiry', async () => {
    expect((await createInvite({ team_id: 9999 })).status).toBe(404)
    expect((await createInvite({ team_id: team, expires_at: 'not-a-date' })).status).toBe(400)
  })

  it('a manager registers with a valid code, joins the team, and the code is single-use', async () => {
    const { json: { code } } = await createInvite({ team_id: team })
    const ok = await register({ name: 'Jane Doe', password: 'correct-horse', code: code.toLowerCase() })
    expect(ok.status).toBe(200)
    expect(ok.json.user).toMatchObject({ name: 'Jane Doe', team_id: team, team_name: 'Patient Services' })
    expect(ok.json.token).toBeTruthy()

    const again = await register({ name: 'Someone Else', password: 'correct-horse', code })
    expect(again.status).toBe(400)
  })

  it('rejects an expired code', async () => {
    await h.db.execute({ sql: "INSERT INTO invite_codes (code, role, team_id, expires_at) VALUES ('OLDCODE9', 'manager', ?, ?)", args: [team, new Date(Date.now() - 60_000).toISOString()] })
    const res = await register({ name: 'Late Larry', password: 'correct-horse', code: 'OLDCODE9' })
    expect(res.status).toBe(400)
  })

  it('refuses past or >90-day expiries and defaults to 7 days', async () => {
    expect((await createInvite({ team_id: team, expires_at: new Date(Date.now() - 1000).toISOString() })).status).toBe(400)
    expect((await createInvite({ team_id: team, expires_in_days: 400 })).status).toBe(400)
    const def = await createInvite({ team_id: team })
    const days = (new Date(def.json.expires_at) - Date.now()) / 86400_000
    expect(days).toBeGreaterThan(6.9)
    expect(days).toBeLessThan(7.1)
  })

  it('validates input instead of crashing', async () => {
    const { json: { code } } = await createInvite({ team_id: team })
    expect((await register({ name: 'x', password: 'short', code })).status).toBe(400)
    expect((await register({ name: '', password: 'correct-horse', code })).status).toBe(400)
    expect((await register({ name: 'x', password: 'correct-horse' })).status).toBe(400)
  })

  it('rate-limits invite-code guessing per IP', async () => {
    let last
    for (let i = 0; i < 12; i++) last = await register({ name: 'x', password: 'correct-horse', code: 'AAAAAAAA' }, '203.0.113.9')
    expect(last.status).toBe(429)
  })

  it('creating a duplicate user returns a clear 409', async () => {
    const body = { name: 'Pat Learner', password: 'correct-horse', team_id: team }
    expect((await h.request('/api/learners', { method: 'POST', token: h.adminToken(), body })).status).toBe(201)
    const dup = await h.request('/api/learners', { method: 'POST', token: h.adminToken(), body })
    expect(dup.status).toBe(409)
    expect(dup.json.error).toMatch(/already exists/)
  })
})

describe('Learner invite links', () => {
  let h, team, other, mgr
  beforeEach(async () => {
    h = await setupHarness()
    team = await h.createTeam('Patient Services')
    other = await h.createTeam('Engineering')
    mgr = await h.createUser({ name: 'sarah', role: 'manager', team_id: team })
  })

  const adminInvite = (body) => h.request('/api/admin/invites', { method: 'POST', token: h.adminToken(), body })
  const mgrInvite = (body) => h.request('/api/invites', { method: 'POST', token: h.managerToken(mgr), body })
  const join = (body, ip) => h.request('/api/auth/register', { method: 'POST', body, ip })

  it('a team link admits several learners up to its cap, then stops', async () => {
    const { json: { code, max_uses } } = await adminInvite({ role: 'learner', team_id: team, max_uses: 2 })
    expect(max_uses).toBe(2)
    const a = await join({ name: 'Learner A', password: 'correct-horse', code })
    expect(a.status).toBe(200)
    expect(a.json.user).toMatchObject({ role: 'learner', team_id: team, team_name: 'Patient Services' })
    expect((await join({ name: 'Learner B', password: 'correct-horse', code })).status).toBe(200)
    expect((await join({ name: 'Learner C', password: 'correct-horse', code })).status).toBe(400)
  })

  it('the learner token works as a learner session', async () => {
    const { json: { code } } = await adminInvite({ role: 'learner', team_id: team })
    const { json: { token } } = await join({ name: 'New Learner', password: 'correct-horse', code })
    const me = await h.request('/api/learners/me', { token })
    expect(me.status).toBe(200)
  })

  it('a taken name does not burn a use', async () => {
    const { json: { code } } = await adminInvite({ role: 'learner', team_id: team, max_uses: 1 })
    await h.createUser({ name: 'Taken Name', role: 'learner' })
    expect((await join({ name: 'Taken Name', password: 'correct-horse', code })).status).toBe(409)
    expect((await join({ name: 'Free Name', password: 'correct-horse', code })).status).toBe(200)
  })

  it('managers can invite only learners, only to their own team', async () => {
    const res = await mgrInvite({ role: 'manager', team_id: other })
    expect(res.status).toBe(201)
    expect(res.json).toMatchObject({ role: 'learner', team_id: team })
    const list = await h.request('/api/invites', { token: h.managerToken(mgr) })
    expect(list.json.map(i => i.code)).toEqual([res.json.code])
  })

  it('managers cannot see or revoke invites outside their team', async () => {
    const foreign = await adminInvite({ role: 'learner', team_id: other })
    const list = await h.request('/api/invites', { token: h.managerToken(mgr) })
    expect(list.json).toEqual([])
    await h.request(`/api/invites/${foreign.json.id}`, { method: 'DELETE', token: h.managerToken(mgr) })
    const stillThere = await h.db.execute({ sql: 'SELECT COUNT(*) FROM invite_codes WHERE id = ?', args: [foreign.json.id] })
    expect(Number(stillThere.rows[0][0])).toBe(1)
  })

  it('a learner code cannot be used on the legacy manager endpoint', async () => {
    const { json: { code } } = await adminInvite({ role: 'learner', team_id: team })
    const res = await h.request('/api/auth/manager/register', { method: 'POST', body: { name: 'Sneaky', password: 'correct-horse', code } })
    expect(res.status).toBe(400)
  })

  it('preview reveals only role and team for a valid code', async () => {
    const { json: { code } } = await adminInvite({ role: 'learner', team_id: team })
    const ok = await h.request(`/api/auth/invite/${code}`)
    expect(ok.json).toEqual({ role: 'learner', team_name: 'Patient Services' })
    expect((await h.request('/api/auth/invite/NOPE1234')).status).toBe(404)
  })
})
