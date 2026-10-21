import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

const count = async (h, table, col, id) => Number((await h.db.execute({ sql: `SELECT COUNT(*) AS n FROM ${table} WHERE ${col} = ?`, args: [id] })).rows[0].n)

describe('self-service account deletion and export', () => {
  let h, team, me, other, course
  beforeEach(async () => {
    h = await setupHarness()
    team = await h.createTeam('Team A')
    me = await h.createUser({ name: 'alex', team_id: team, password: 'my-password-1' })
    other = await h.createUser({ name: 'bea', team_id: team })
    course = await h.createCourse({ answers: [0] })
    await h.assign(course.id, me.id)
    await h.assign(course.id, other.id)
  })

  const pass = async (u) => {
    const t = await h.sessionToken(u)
    for (const qid of course.question_ids) await h.request('/api/quiz/answer', { method: 'POST', token: t, body: { question_id: qid, selected_index: 0 } })
    return (await h.request('/api/completions', { method: 'POST', token: t, body: { course_id: course.id } })).json
  }
  const del = async (u, body) => h.request('/api/learners/me', { method: 'DELETE', token: await h.sessionToken(u), body })

  it('requires a password and rejects a wrong one', async () => {
    expect((await del(me, {})).status).toBe(400)
    expect((await del(me, { password: 'wrong-wrong-1' })).status).toBe(400)
    expect(await count(h, 'users', 'id', me.id)).toBe(1)
  })

  it('needs a signed-in account', async () => {
    expect((await h.request('/api/learners/me', { method: 'DELETE', body: { password: 'x' } })).status).toBe(401)
    expect((await h.request('/api/learners/me', { method: 'DELETE', token: h.adminToken(), body: { password: 'x' } })).status).toBe(401)
  })

  it('removes the account and all of its data, and leaves other people alone', async () => {
    await pass(me)
    await pass(other)
    expect(Number((await h.db.execute('SELECT COUNT(*) AS n FROM question_responses')).rows[0].n)).toBe(2)
    await h.request('/api/progress', { method: 'POST', token: await h.sessionToken(me), body: { course_id: course.id, module_idx: 0, modules: [] } })
    await h.db.execute({ sql: "INSERT INTO invite_codes (code, role, used_by) VALUES ('ABC', 'learner', ?)", args: [me.id] })

    const res = await del(me, { password: 'my-password-1' })
    expect(res.status).toBe(200)

    for (const [table, col] of [['users', 'id'], ['assignments', 'learner_id'], ['completions', 'learner_id'], ['module_progress', 'learner_id'], ['quiz_answers', 'learner_id'], ['course_progress', 'learner_id']]) {
      expect(await count(h, table, col, me.id), table).toBe(0)
    }
    expect(Number((await h.db.execute('SELECT COUNT(*) AS n FROM question_responses')).rows[0].n)).toBe(1)
    expect((await h.db.execute("SELECT used_by FROM invite_codes WHERE code = 'ABC'")).rows[0].used_by).toBeNull()
    expect(await count(h, 'users', 'id', other.id)).toBe(1)
    expect(await count(h, 'completions', 'learner_id', other.id)).toBe(1)
    expect(await count(h, 'assignments', 'learner_id', other.id)).toBe(1)
  })

  it('signs the person out and their certificate stops verifying', async () => {
    const done = await pass(me)
    const t = await h.sessionToken(me)
    expect((await h.request(`/api/verify/${done.cert_id}`)).status).toBe(200)
    await h.request('/api/learners/me', { method: 'DELETE', token: t, body: { password: 'my-password-1' } })
    expect((await h.request('/api/assignments/me', { token: t })).status).toBe(401)
    expect((await h.request(`/api/verify/${done.cert_id}`)).status).toBe(404)
    expect((await h.request('/api/learners/login', { method: 'POST', body: { name: 'alex', password: 'my-password-1' } })).status).toBe(401)
  })

  it('refuses to delete the only administrator, but lets one of several go', async () => {
    const boss = await h.createUser({ name: 'boss', is_admin: 1, password: 'boss-password-1' })
    const res = await del(boss, { password: 'boss-password-1' })
    expect(res.status).toBe(409)
    expect(await count(h, 'users', 'id', boss.id)).toBe(1)
    await h.createUser({ name: 'boss2', is_admin: 1 })
    expect((await del(boss, { password: 'boss-password-1' })).status).toBe(200)
  })

  it('repeated wrong passwords lock the confirmation, like a sign-in', async () => {
    for (let i = 0; i < 5; i++) await del(me, { password: 'wrong-wrong-1' })
    expect((await del(me, { password: 'my-password-1' })).status).toBe(429)
  })

  it('an admin deleting a user also clears their data', async () => {
    await pass(me)
    expect((await h.request(`/api/learners/${me.id}`, { method: 'DELETE', token: h.adminToken() })).status).toBe(200)
    expect(await count(h, 'quiz_answers', 'learner_id', me.id)).toBe(0)
    expect(await count(h, 'completions', 'learner_id', me.id)).toBe(0)
  })

  it('export returns only my own data and no password hash', async () => {
    const done = await pass(me)
    await pass(other)
    const res = await h.request('/api/learners/me/export', { token: await h.sessionToken(me) })
    expect(res.status).toBe(200)
    expect(res.json.profile).toMatchObject({ name: 'alex', team: 'Team A' })
    expect(res.json.completions).toHaveLength(1)
    expect(res.json.completions[0]).toMatchObject({ cert_id: done.cert_id, course: 'Safety 101', passed: true })
    expect(res.json.assignments).toHaveLength(1)
    const text = JSON.stringify(res.json)
    expect(text).not.toContain('pbkdf2')
    expect(text).not.toContain('bea')
    expect((await h.request('/api/learners/me/export')).status).toBe(401)
  })
})
