import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

describe('RBAC — role gates', () => {
  let h, learner, manager, team
  beforeEach(async () => {
    h = await setupHarness()
    team = await h.createTeam('Team A')
    learner = await h.createUser({ name: 'alex', role: 'learner', team_id: team })
    manager = await h.createUser({ name: 'sarah', role: 'manager', team_id: team })
  })

  it('requireAdmin rejects a learner token (401)', async () => {
    const res = await h.request('/api/admin/teams', { method: 'POST', token: h.learnerToken(learner), body: { name: 'X' } })
    expect(res.status).toBe(401)
  })

  it('requireAdmin rejects a manager token (401)', async () => {
    const res = await h.request('/api/admin/teams', { method: 'POST', token: h.managerToken(manager), body: { name: 'X' } })
    expect(res.status).toBe(401)
  })

  it('requireAdmin accepts an admin token (201)', async () => {
    const res = await h.request('/api/admin/teams', { method: 'POST', token: h.adminToken(), body: { name: 'New Team' } })
    expect(res.status).toBe(201)
  })

  it('requireLearner rejects an admin token (role must be exactly learner)', async () => {
    const res = await h.request('/api/completions', { method: 'POST', token: h.adminToken(), body: { course_id: 'x', score: 100 } })
    expect(res.status).toBe(401)
  })

  it('requireManager rejects a learner token (401)', async () => {
    const res = await h.request('/api/assignments', { token: h.learnerToken(learner) })
    expect(res.status).toBe(401)
  })

  it('rejects requests with no token (401)', async () => {
    const res = await h.request('/api/assignments')
    expect(res.status).toBe(401)
  })

  it('rejects a token signed with the wrong secret (401)', async () => {
    const res = await h.request('/api/assignments', { token: 'not.a.valid.jwt' })
    expect(res.status).toBe(401)
  })
})

describe('RBAC — manager team scoping', () => {
  let h
  beforeEach(async () => { h = await setupHarness() })

  it('a manager only sees assignments for learners on their own team', async () => {
    const teamA = await h.createTeam('Team A')
    const teamB = await h.createTeam('Team B')
    const mgrA = await h.createUser({ name: 'mgrA', role: 'manager', team_id: teamA })
    const lrnA = await h.createUser({ name: 'lrnA', role: 'learner', team_id: teamA })
    const lrnB = await h.createUser({ name: 'lrnB', role: 'learner', team_id: teamB })
    const course = await h.createCourse()
    await h.assign(course.id, lrnA.id)
    await h.assign(course.id, lrnB.id)

    const res = await h.request('/api/assignments', { token: h.managerToken(mgrA) })
    expect(res.status).toBe(200)
    const learnerIds = res.json.map((a) => a.learner_id)
    expect(learnerIds).toContain(lrnA.id)
    expect(learnerIds).not.toContain(lrnB.id) // cross-team isolation
  })

  it('an admin sees assignments across all teams', async () => {
    const teamA = await h.createTeam('Team A')
    const teamB = await h.createTeam('Team B')
    const lrnA = await h.createUser({ name: 'lrnA', role: 'learner', team_id: teamA })
    const lrnB = await h.createUser({ name: 'lrnB', role: 'learner', team_id: teamB })
    const course = await h.createCourse()
    await h.assign(course.id, lrnA.id)
    await h.assign(course.id, lrnB.id)

    const res = await h.request('/api/assignments', { token: h.adminToken() })
    expect(res.status).toBe(200)
    expect(res.json.length).toBe(2)
  })
})

describe('Teams — admin delete', () => {
  it('deletes a team that has members and invite codes, unassigning the members', async () => {
    const h = await setupHarness()
    const keep = await h.createTeam('1st Level Support')
    const doomed = await h.createTeam('Patient Services')
    const learner = await h.createUser({ name: 'pat', role: 'learner', team_id: doomed })
    const manager = await h.createUser({ name: 'mgr', role: 'manager', team_id: doomed })
    await h.db.execute({ sql: "INSERT INTO invite_codes (code, team_id, used) VALUES ('ABC123', ?, 0)", args: [doomed] })

    const res = await h.request(`/api/admin/teams/${doomed}`, { method: 'DELETE', token: h.adminToken() })
    expect(res.status).toBe(200)

    const teams = await h.request('/api/admin/teams', { token: h.adminToken() })
    expect(teams.json.map(t => t.name)).toEqual(['1st Level Support'])
    const rows = await h.db.execute({ sql: 'SELECT team_id FROM users WHERE id IN (?, ?)', args: [learner.id, manager.id] })
    expect(rows.rows.every(r => r[0] === null)).toBe(true)
    expect(keep).toBeTruthy()
  })
})

describe('Learner self-service routes (/api/learners/me)', () => {
  it('a learner can read and update their own profile', async () => {
    const h = await setupHarness()
    const learner = await h.createUser({ name: 'alex', role: 'learner', password: 'old-password-1' })
    const me = await h.request('/api/learners/me', { token: h.learnerToken(learner) })
    expect(me.status).toBe(200)
    const patch = await h.request('/api/learners/me', { method: 'PATCH', token: h.learnerToken(learner), body: { name: 'alex-renamed' } })
    expect(patch.status).toBe(200)
  })
})
