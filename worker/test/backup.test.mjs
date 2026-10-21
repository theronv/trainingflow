import { describe, it, expect, beforeAll } from 'vitest'
import { setupHarness } from './helpers.mjs'

// ensureSetup() runs once per module, so a file shares one harness and wipes content between tests.
async function wipe(h) {
  for (const t of ['questions', 'modules', 'courses', 'sections']) await h.db.execute(`DELETE FROM ${t}`)
}

async function seed(h) {
  const admin = h.adminToken()
  const parent = (await h.request('/api/sections', { method: 'POST', token: admin, body: { name: 'Synergy Sports' } })).json
  const child = (await h.request('/api/sections', { method: 'POST', token: admin, body: { name: 'Editor', parent_id: parent.id } })).json
  const c = await h.createCourse({ title: 'Safety 101', answers: [2, 3] })
  await h.db.execute({ sql: 'UPDATE courses SET section_id = ?, icon = ?, reference_url = ? WHERE id = ?', args: [child.id, '🥎', 'https://example.com/ref', c.id] })
  await h.db.execute({ sql: 'UPDATE modules SET summary = ?, learning_objectives = ?, content = ? WHERE id = ?', args: ['Sum', JSON.stringify(['a', 'b']), '# Lesson', c.module_id] })
  return { admin, parent, child, course: c }
}

const h = await setupHarness()

describe('GET /api/admin/backup', () => {
  let s
  beforeAll(async () => { await h.request('/api/sections', { token: h.adminToken() }); await wipe(h); s = await seed(h) })

  it('is admin only', async () => {
    expect((await h.request('/api/admin/backup')).status).toBe(401)
    const learner = await h.createUser({ name: 'Lee' })
    expect((await h.request('/api/admin/backup', { token: h.learnerToken(learner) })).status).toBe(401)
    const mgr = await h.createUser({ name: 'Mo', role: 'manager', team_id: await h.createTeam('T') })
    expect((await h.request('/api/admin/backup', { token: h.managerToken(mgr) })).status).toBe(401)
  })

  it('exports versioned content with answer keys, sections and counts, and no people data', async () => {
    await h.createUser({ name: 'Someone' })
    const { status, json } = await h.request('/api/admin/backup', { token: s.admin })
    expect(status).toBe(200)
    expect(json.format).toBe('pregame-academy-content')
    expect(json.version).toBe(1)
    expect(json.counts).toEqual({ sections: 2, courses: 1, modules: 1, questions: 2 })
    expect(json.sections.find(x => x.id === s.child.id).parent_id).toBe(s.parent.id)
    const course = json.courses[0]
    expect(course).toMatchObject({ title: 'Safety 101', icon: '🥎', section_id: s.child.id, reference_url: 'https://example.com/ref' })
    expect(course.modules[0]).toMatchObject({ summary: 'Sum', content: '# Lesson' })
    expect(course.modules[0].questions.map(q => q.correct_index)).toEqual([2, 3])
    expect(json.learners).toBeUndefined()
    expect(json.completions).toBeUndefined()
  })
})

describe('POST /api/admin/backup/restore', () => {
  it('round-trips a backup into an empty database', async () => {
    await wipe(h)
    const s = await seed(h)
    const backup = (await h.request('/api/admin/backup', { token: s.admin })).json
    await wipe(h)

    const admin = h.adminToken()
    const dst = h
    const res = await dst.request('/api/admin/backup/restore', { method: 'POST', token: admin, body: backup })
    expect(res.status).toBe(200)
    expect(res.json).toMatchObject({ imported: 1, skipped: 0, sections: 2 })

    const again = (await dst.request('/api/admin/backup', { token: admin })).json
    expect({ ...again, exported_at: null }).toEqual({ ...backup, exported_at: null })
  })

  it('skips courses and sections that already exist and never overwrites', async () => {
    await wipe(h)
    const s = await seed(h)
    const backup = (await h.request('/api/admin/backup', { token: s.admin })).json
    backup.courses[0].title = 'Changed in file'
    const res = await h.request('/api/admin/backup/restore', { method: 'POST', token: s.admin, body: backup })
    expect(res.json).toMatchObject({ imported: 0, skipped: 1, sections: 0 })
    const after = (await h.request('/api/admin/backup', { token: s.admin })).json
    expect(after.courses[0].title).toBe('Safety 101')
  })

  it('accepts the older un-versioned format with options arrays and learning-objective arrays', async () => {
    await wipe(h)
    const admin = h.adminToken()
    const legacy = { courses: [{ id: 'old1', title: 'Old', modules: [{ id: 'om1', title: 'M', learning_objectives: ['x'], questions: [{ id: 'oq1', question: 'Q?', options: ['a', 'b', 'c', 'd'], correct_index: 1 }] }] }] }
    const res = await h.request('/api/admin/backup/restore', { method: 'POST', token: admin, body: legacy })
    expect(res.json.imported).toBe(1)
    const out = (await h.request('/api/admin/backup', { token: admin })).json
    expect(out.courses[0].modules[0].learning_objectives).toBe('["x"]')
    expect(out.courses[0].modules[0].questions[0]).toMatchObject({ option_b: 'b', correct_index: 1 })
  })

  it('rejects malformed files with a clear message and changes nothing', async () => {
    await wipe(h)
    const admin = h.adminToken()
    const post = (body) => h.request('/api/admin/backup/restore', { method: 'POST', token: admin, body })
    expect((await post({ nope: 1 })).json.error).toMatch(/no courses list/)
    expect((await post({ format: 'something-else', courses: [] })).json.error).toMatch(/not a Pregame Academy/)
    expect((await post({ version: 99, courses: [] })).json.error).toMatch(/newer version/)
    const bad = await post({ courses: [{ id: 'c1', title: 'Ok' }, { id: 'c2' }] })
    expect(bad.status).toBe(400)
    expect((await h.request('/api/admin/backup', { token: admin })).json.counts.courses).toBe(0)
  })

  it('is atomic: an id collision part-way through rolls the whole restore back', async () => {
    await wipe(h)
    const admin = h.adminToken()
    const existing = await h.createCourse({ title: 'Existing' })
    const file = { courses: [
      { id: 'new1', title: 'New', modules: [{ id: 'nm1', title: 'M' }] },
      // new course whose module id collides with an existing module
      { id: 'new2', title: 'Clash', modules: [{ id: existing.module_id, title: 'M' }] },
    ] }
    const res = await h.request('/api/admin/backup/restore', { method: 'POST', token: admin, body: file })
    expect(res.status).toBe(409)
    const out = (await h.request('/api/admin/backup', { token: admin })).json
    expect(out.courses.map(c => c.id)).toEqual([existing.id])
  })

  it('is admin only', async () => {
    const learner = await h.createUser({ name: 'Lee Restore' })
    const res = await h.request('/api/admin/backup/restore', { method: 'POST', token: h.learnerToken(learner), body: { courses: [] } })
    expect(res.status).toBe(401)
  })
})
