import { describe, it, expect, beforeAll } from 'vitest'
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
})
