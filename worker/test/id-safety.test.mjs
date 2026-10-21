import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

/**
 * SEC-09: ids are interpolated into inline onclick="…('${id}')" handlers across the SPA. The Worker mints them
 * itself (hex), so the only way to plant a hostile one is the backup restore, which accepts ids from a file.
 */
describe('backup restore id safety', () => {
  let h
  beforeEach(async () => { h = await setupHarness() })
  const restore = (body) => h.request('/api/admin/backup/restore', { method: 'POST', token: h.adminToken(), body })

  const hostile = ["x'); alert(1);//", 'a"b', 'a b', '<img>', '', 'x'.repeat(65), 'é']
  for (const bad of hostile) {
    it(`rejects course id ${JSON.stringify(bad.slice(0, 20))}`, async () => {
      const res = await restore({ courses: [{ id: bad, title: 'T', modules: [] }] })
      expect(res.status).toBe(400)
      expect((await h.db.execute('SELECT COUNT(*) AS n FROM courses')).rows[0].n).toBe(0)
    })
  }

  it('rejects hostile section, module and question ids too', async () => {
    expect((await restore({ sections: [{ id: "s'x", name: 'S' }], courses: [] })).status).toBe(400)
    expect((await restore({ courses: [{ id: 'c1', title: 'T', modules: [{ id: "m'x", title: 'M', questions: [] }] }] })).status).toBe(400)
    expect((await restore({ courses: [{ id: 'c1', title: 'T', modules: [{ id: 'm1', title: 'M', questions: [{ id: 'q"x', question: 'Q' }] }] }] })).status).toBe(400)
  })

  it('still accepts the ids the Worker itself generates and ordinary slugs', async () => {
    const res = await restore({ courses: [{ id: 'a1b2c3d4e5f6', title: 'T', modules: [{ id: 'mod_1-A', title: 'M', questions: [] }] }] })
    expect(res.status).toBeLessThan(300)
  })
})
