import { describe, it, expect, beforeAll, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

describe('Sections — one level of sub-sections', () => {
  let h, admin
  const post = (body) => h.request('/api/sections', { method: 'POST', token: admin, body })
  beforeAll(async () => { h = await setupHarness(); admin = h.adminToken() })

  it('creates a sub-section under a top-level section and returns parent_id', async () => {
    const p = (await post({ name: 'Synergy Sports' })).json
    const c = await post({ name: 'Editor', parent_id: p.id })
    expect(c.status).toBe(201)
    const list = (await h.request('/api/sections', { token: admin })).json
    expect(list.find(s => s.name === 'Editor').parent_id).toBe(p.id)
  })

  it('rejects a third level and an unknown parent', async () => {
    const p = (await post({ name: 'A' })).json
    const c = (await post({ name: 'B', parent_id: p.id })).json
    expect((await post({ name: 'C', parent_id: c.id })).status).toBe(400)
    expect((await post({ name: 'D', parent_id: 'nope' })).status).toBe(400)
  })

  it('deleting a parent promotes its children to top-level', async () => {
    const p = (await post({ name: 'A' })).json
    const c = (await post({ name: 'B', parent_id: p.id })).json
    await h.request(`/api/sections/${p.id}`, { method: 'DELETE', token: admin })
    const list = (await h.request('/api/sections', { token: admin })).json
    expect(list.find(s => s.id === c.id).parent_id).toBeNull()
  })

  describe('PUT /api/sections/order', () => {
  const put = (body, token = admin) => h.request('/api/sections/order', { method: 'PUT', token, body })
    const names = async () => (await h.request('/api/sections', { token: admin })).json.map(s => s.name)
    // Share the file's harness (the sections table is created lazily once per process) and clear it per test.
    beforeEach(async () => { await h.db.execute('DELETE FROM sections') })

    it('requires an admin token', async () => {
      const team = await h.createTeam('T')
      const learner = await h.createUser({ name: 'l', role: 'learner', team_id: team })
      expect((await put({ ids: [] }, null)).status).toBe(401)
      expect((await put({ ids: [] }, h.learnerToken(learner))).status).toBe(401)
    })

    it('persists the new order, including across sub-sections', async () => {
      const a = (await post({ name: 'A' })).json.id
      const b = (await post({ name: 'B' })).json.id
      const c = (await post({ name: 'C' })).json.id
      const kid = (await post({ name: 'Kid', parent_id: a })).json.id
      expect(await names()).toEqual(['A', 'B', 'C', 'Kid'])
      expect((await put({ ids: [c, a, kid, b] })).status).toBe(200)
      expect(await names()).toEqual(['C', 'A', 'Kid', 'B'])
    })

    it('rejects malformed lists', async () => {
      const a = (await post({ name: 'A' })).json.id
      expect((await put({})).status).toBe(400)
      expect((await put({ ids: 'a' })).status).toBe(400)
      expect((await put({ ids: [1] })).status).toBe(400)
      expect((await put({ ids: [a, a] })).status).toBe(400)
    })

    it('refuses a list that is missing or adds sections, and changes nothing', async () => {
      const a = (await post({ name: 'A' })).json.id
      const b = (await post({ name: 'B' })).json.id
      expect((await put({ ids: [a] })).status).toBe(409)
      expect((await put({ ids: [a, b, 'ghost'] })).status).toBe(409)
      expect((await put({ ids: [a, 'ghost'] })).status).toBe(409)
      expect(await names()).toEqual(['A', 'B'])
    })

    it('accepts an empty list when there are no sections', async () => {
      expect((await put({ ids: [] })).status).toBe(200)
    })
  })
})
