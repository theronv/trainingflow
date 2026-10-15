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
    const { json: { code } } = await createInvite({ team_id: team, expires_at: new Date(Date.now() - 60_000).toISOString() })
    const res = await register({ name: 'Late Larry', password: 'correct-horse', code })
    expect(res.status).toBe(400)
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
