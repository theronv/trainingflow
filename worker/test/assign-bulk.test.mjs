import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

describe('POST /api/assignments/bulk', () => {
  let h, teamA, teamB, mgrA, a1, a2, b1, course
  beforeEach(async () => {
    h = await setupHarness()
    teamA = await h.createTeam('Team A')
    teamB = await h.createTeam('Team B')
    mgrA = await h.createUser({ name: 'mgrA', role: 'manager', team_id: teamA })
    a1 = await h.createUser({ name: 'a1', team_id: teamA })
    a2 = await h.createUser({ name: 'a2', team_id: teamA })
    b1 = await h.createUser({ name: 'b1', team_id: teamB })
    course = await h.createCourse()
  })

  const count = async () => Number((await h.db.execute('SELECT COUNT(*) AS n FROM assignments')).rows[0].n)

  it('admin can assign a whole team plus an individual, skipping duplicates', async () => {
    await h.assign(course.id, a1.id)
    const res = await h.request('/api/assignments/bulk', {
      method: 'POST', token: h.adminToken(),
      body: { course_id: course.id, team_ids: [teamA], learner_ids: [b1.id], due_at: '2026-12-01' },
    })
    expect(res.status).toBe(201)
    expect(res.json).toMatchObject({ added: 2, skipped: 1 })
    expect(await count()).toBe(3)
  })

  it('never assigns to managers, even if their id or team is targeted', async () => {
    const res = await h.request('/api/assignments/bulk', {
      method: 'POST', token: h.adminToken(),
      body: { course_id: course.id, team_ids: [teamA], learner_ids: [mgrA.id] },
    })
    expect(res.json.added).toBe(2)
    const rows = (await h.db.execute('SELECT learner_id FROM assignments')).rows.map(r => r.learner_id)
    expect(rows).not.toContain(mgrA.id)
  })

  it('a manager cannot reach learners or teams outside their own team', async () => {
    const res = await h.request('/api/assignments/bulk', {
      method: 'POST', token: h.managerToken(mgrA),
      body: { course_id: course.id, team_ids: [teamB], learner_ids: [b1.id] },
    })
    expect(res.status).toBe(404)
    expect(await count()).toBe(0)
  })

  it('rejects learners, unknown courses and empty selections', async () => {
    expect((await h.request('/api/assignments/bulk', { method: 'POST', token: h.learnerToken(a1), body: { course_id: course.id, learner_ids: [a2.id] } })).status).toBe(401)
    expect((await h.request('/api/assignments/bulk', { method: 'POST', token: h.adminToken(), body: { course_id: 'nope', learner_ids: [a1.id] } })).status).toBe(404)
    expect((await h.request('/api/assignments/bulk', { method: 'POST', token: h.adminToken(), body: { course_id: course.id } })).status).toBe(400)
  })
})
