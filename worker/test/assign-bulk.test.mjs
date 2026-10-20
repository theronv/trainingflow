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

  it('a team selection assigns learners only; an admin can pick a manager individually', async () => {
    const team = await h.request('/api/assignments/bulk', {
      method: 'POST', token: h.adminToken(),
      body: { course_id: course.id, team_ids: [teamA] },
    })
    expect(team.json.added).toBe(2)
    let rows = (await h.db.execute('SELECT learner_id FROM assignments')).rows.map(r => r.learner_id)
    expect(rows).not.toContain(mgrA.id)
    const pick = await h.request('/api/assignments/bulk', {
      method: 'POST', token: h.adminToken(),
      body: { course_id: course.id, learner_ids: [mgrA.id] },
    })
    expect(pick.json.added).toBe(1)
    rows = (await h.db.execute('SELECT learner_id FROM assignments')).rows.map(r => r.learner_id)
    expect(rows).toContain(mgrA.id)
  })

  it('a team manager cannot assign to a manager, themselves included', async () => {
    const res = await h.request('/api/assignments/bulk', {
      method: 'POST', token: h.managerToken(mgrA),
      body: { course_id: course.id, learner_ids: [mgrA.id] },
    })
    expect(res.status).toBe(404)
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

  describe('several courses at once', () => {
    let course2, course3
    beforeEach(async () => {
      course2 = await h.createCourse()
      course3 = await h.createCourse()
    })
    const post = (token, body) => h.request('/api/assignments/bulk', { method: 'POST', token, body })

    it('assigns every selected course to a team and an individual, skipping existing pairs', async () => {
      await h.assign(course.id, a1.id)
      const res = await post(h.adminToken(), { course_ids: [course.id, course2.id], team_ids: [teamA], learner_ids: [b1.id], due_at: '2026-12-01' })
      expect(res.status).toBe(201)
      expect(res.json).toMatchObject({ added: 5, skipped: 1 })
      expect(await count()).toBe(6)
    })

    it('still accepts a single course_id, and de-duplicates repeated course ids', async () => {
      expect((await post(h.adminToken(), { course_id: course.id, learner_ids: [a1.id] })).json.added).toBe(1)
      const res = await post(h.adminToken(), { course_ids: [course2.id, course2.id], learner_ids: [a1.id] })
      expect(res.json).toMatchObject({ added: 1, skipped: 0 })
    })

    it('writes nothing when any course id is unknown', async () => {
      const res = await post(h.adminToken(), { course_ids: [course.id, 'nope'], learner_ids: [a1.id] })
      expect(res.status).toBe(404)
      expect(await count()).toBe(0)
    })

    it('rejects an empty or oversized course list', async () => {
      expect((await post(h.adminToken(), { course_ids: [], learner_ids: [a1.id] })).status).toBe(400)
      const many = Array.from({ length: 101 }, (_, i) => `c${i}`)
      expect((await post(h.adminToken(), { course_ids: many, learner_ids: [a1.id] })).status).toBe(400)
    })

    it('keeps a manager inside their own team across all courses', async () => {
      const ok = await post(h.managerToken(mgrA), { course_ids: [course.id, course2.id, course3.id], team_ids: [teamA] })
      expect(ok.json.added).toBe(6)
      const out = await post(h.managerToken(mgrA), { course_ids: [course.id, course2.id], learner_ids: [b1.id] })
      expect(out.status).toBe(404)
      expect(await count()).toBe(6)
    })
  })
})
