import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

describe('GET /api/verify/:certId (public)', () => {
  let h, learner, course
  beforeEach(async () => {
    h = await setupHarness()
    learner = await h.createUser({ name: 'Alex Rivera', role: 'learner' })
    course = await h.createCourse({ title: 'Safety 101' })
  })

  const complete = (certId, passed = 1) => h.db.execute({
    sql: 'INSERT INTO completions (id, learner_id, learner_name, course_id, score, passed, cert_id, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    args: [`r-${certId}`, learner.id, learner.name, course.id, 92, passed, certId, 1_700_000_000],
  })

  it('confirms a real certificate without a token, and reveals only name, course, organisation and date', async () => {
    await complete('PG-0A1B2C3D')
    const res = await h.request('/api/verify/PG-0A1B2C3D')
    expect(res.status).toBe(200)
    expect(res.json).toEqual({
      valid: true, name: 'Alex Rivera', course: 'Safety 101',
      org: 'Pregame Academy', completed_at: 1_700_000_000, cert_id: 'PG-0A1B2C3D',
    })
  })

  it('ignores case and surrounding spaces in the id', async () => {
    await complete('PG-0A1B2C3D')
    expect((await h.request('/api/verify/pg-0a1b2c3d')).json.valid).toBe(true)
  })

  it('rejects unknown ids and failed attempts', async () => {
    await complete('PG-DEADBEEF', 0)
    const failed = await h.request('/api/verify/PG-DEADBEEF')
    expect(failed.status).toBe(404)
    expect(failed.json).toEqual({ valid: false })
    expect((await h.request('/api/verify/PG-00000000')).status).toBe(404)
  })

  it('still verifies after the course is deleted', async () => {
    await complete('PG-0A1B2C3D')
    await h.db.execute('PRAGMA foreign_keys = OFF')
    await h.db.execute({ sql: 'DELETE FROM courses WHERE id = ?', args: [course.id] })
    const res = await h.request('/api/verify/PG-0A1B2C3D')
    expect(res.json.valid).toBe(true)
    expect(res.json.course).toBe('Course no longer available')
  })

  it('is rate limited per client', async () => {
    const ip = '203.0.113.9'
    let last
    for (let i = 0; i < 31; i++) last = await h.request('/api/verify/PG-00000000', { ip })
    expect(last.status).toBe(429)
  })
})

describe('certificate signatory in branding', () => {
  it('saves and returns the signatory name and title', async () => {
    const h = await setupHarness()
    const put = await h.request('/api/brand', {
      method: 'PUT', token: h.adminToken(),
      body: { org_name: 'Acme', signatory_name: 'Dana Cole', signatory_title: 'Head of Training' },
    })
    expect(put.status).toBe(200)
    const got = await h.request('/api/brand')
    expect(got.json).toMatchObject({ signatory_name: 'Dana Cole', signatory_title: 'Head of Training' })
  })
})
