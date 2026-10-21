import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

describe('session revocation', () => {
  let h, team, learner, manager, boss
  const mine = (token) => h.request('/api/assignments/me', { token })
  beforeEach(async () => {
    h = await setupHarness()
    team = await h.createTeam('Team A')
    learner = await h.createUser({ name: 'alex', team_id: team, password: 'old-password-1' })
    manager = await h.createUser({ name: 'sarah', role: 'manager', team_id: team, password: 'old-password-2' })
    boss = await h.createUser({ name: 'boss', is_admin: 1 })
  })

  it('a token minted without sv (issued before this feature) works until the first revocation', async () => {
    expect((await mine(h.learnerToken(learner))).status).toBe(200)
    await h.request(`/api/learners/${learner.id}/password`, { method: 'PUT', token: h.adminToken(), body: { password: 'new-password-1' } })
    expect((await mine(h.learnerToken(learner))).status).toBe(401)
  })

  it('a deleted account is signed out', async () => {
    const t = await h.sessionToken(learner)
    expect((await mine(t)).status).toBe(200)
    expect((await h.request(`/api/learners/${learner.id}`, { method: 'DELETE', token: h.adminToken() })).status).toBe(200)
    expect((await mine(t)).status).toBe(401)
  })

  it('bulk delete signs the accounts out', async () => {
    const t = await h.sessionToken(learner)
    await h.request('/api/learners/bulk/delete', { method: 'POST', token: h.adminToken(), body: { ids: [learner.id] } })
    expect((await mine(t)).status).toBe(401)
  })

  it('an admin or manager resetting a password signs the person out everywhere', async () => {
    const t = await h.sessionToken(learner)
    const res = await h.request(`/api/learners/${learner.id}/password`, { method: 'PUT', token: h.managerToken(manager), body: { password: 'new-password-1' } })
    expect(res.status).toBe(200)
    expect((await mine(t)).status).toBe(401)
    const login = await h.request('/api/learners/login', { method: 'POST', body: { name: 'alex', password: 'new-password-1' } })
    expect((await mine(login.json.token)).status).toBe(200)
  })

  it.each([
    ['learner', '/api/learners/me', () => learner],
    ['manager', '/api/managers/me', () => manager],
  ])('a %s changing their own password signs out other devices but keeps this one', async (_r, path, who) => {
    const u = who()
    const other = await h.sessionToken(u)
    const res = await h.request(path, { method: 'PATCH', token: other, body: { current_password: u.password, password: 'brand-new-pass' } })
    expect(res.status).toBe(200)
    expect(res.json.session.token).toBeTruthy()
    expect((await mine(other)).status).toBe(401)
    expect((await mine(res.json.session.token)).status).toBe(200)
  })

  it('a wrong current password revokes nothing', async () => {
    const t = await h.sessionToken(learner)
    const res = await h.request('/api/learners/me', { method: 'PATCH', token: t, body: { current_password: 'nope-nope-1', password: 'brand-new-pass' } })
    expect(res.status).toBe(400)
    expect((await mine(t)).status).toBe(200)
  })

  it('removing admin access signs the person out, and the old token never keeps admin', async () => {
    const t = await h.sessionToken(boss)
    expect((await h.request('/api/admin/teams', { token: t })).status).toBe(200)
    await h.request(`/api/learners/${boss.id}`, { method: 'PATCH', token: h.adminToken(), body: { is_admin: false } })
    expect((await h.request('/api/admin/teams', { token: t })).status).toBe(401)
    expect((await mine(t)).status).toBe(401)
  })

  it('demoting a manager takes effect on their next request', async () => {
    const t = await h.sessionToken(manager)
    expect((await h.request('/api/assignments', { token: t })).status).toBe(200)
    await h.request(`/api/learners/${manager.id}`, { method: 'PATCH', token: h.adminToken(), body: { role: 'learner' } })
    expect((await h.request('/api/assignments', { token: t })).status).toBe(401)
  })

  it('moving someone to another team (single, bulk, or by deleting their team) signs them out', async () => {
    const other = await h.createTeam('Team B')
    const t1 = await h.sessionToken(learner)
    await h.request(`/api/admin/learners/${learner.id}/team`, { method: 'PATCH', token: h.adminToken(), body: { team_id: other } })
    expect((await mine(t1)).status).toBe(401)

    const t2 = await h.sessionToken(manager)
    await h.request('/api/learners/bulk', { method: 'PATCH', token: h.adminToken(), body: { ids: [manager.id], team_id: other } })
    expect((await h.request('/api/assignments', { token: t2 })).status).toBe(401)

    const gone = await h.createUser({ name: 'gil', team_id: other })
    const t3 = await h.sessionToken(gone)
    await h.request(`/api/admin/teams/${other}`, { method: 'DELETE', token: h.adminToken() })
    expect((await mine(t3)).status).toBe(401)
  })

  it('renaming or emailing an account does not sign anyone out', async () => {
    const t = await h.sessionToken(learner)
    await h.request(`/api/learners/${learner.id}`, { method: 'PATCH', token: h.adminToken(), body: { name: 'alexa' } })
    expect((await mine(t)).status).toBe(200)
  })

  it('roles and team come from the account, not from claims in the token', async () => {
    const forged = h.mint({ id: learner.id, name: learner.name, role: 'admin', roles: ['learner', 'admin'], team_id: team })
    expect((await h.request('/api/admin/teams', { method: 'POST', token: forged, body: { name: 'X' } })).status).toBe(401)
    const wrongTeam = h.mint({ id: manager.id, name: manager.name, role: 'manager', team_id: 9999 })
    const other = await h.createUser({ name: 'zed', team_id: await h.createTeam('Team C') })
    await h.assign((await h.createCourse()).id, other.id)
    expect((await h.request('/api/assignments', { token: wrongTeam })).json).toEqual([])
  })

  it('the shared-password admin (no account) is unaffected', async () => {
    expect((await h.request('/api/admin/teams', { token: h.adminToken() })).status).toBe(200)
  })

  it('sign-in tokens carry the current session version', async () => {
    await h.request(`/api/learners/${learner.id}/password`, { method: 'PUT', token: h.adminToken(), body: { password: 'new-password-1' } })
    const login = await h.request('/api/learners/login', { method: 'POST', body: { name: 'alex', password: 'new-password-1' } })
    expect((await mine(login.json.token)).status).toBe(200)
  })
})
