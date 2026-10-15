import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { setupHarness } from './helpers.mjs'

describe('GET /api/scrape', () => {
  let h
  beforeEach(async () => { h = await setupHarness() })
  afterEach(() => { vi.unstubAllGlobals() })

  const get = (url, token) =>
    h.request(`/api/scrape?url=${encodeURIComponent(url)}`, { token })

  it('requires an admin token', async () => {
    const team = await h.createTeam('T')
    const learner = await h.createUser({ name: 'l', role: 'learner', team_id: team })
    expect((await get('https://example.com/a')).status).toBe(401)
    expect((await get('https://example.com/a', h.learnerToken(learner))).status).toBe(401)
  })

  it.each([
    'ftp://example.com/a',
    'http://localhost:8787/x',
    'http://127.0.0.1/x',
    'http://169.254.169.254/latest',
    'https://intranet/page',
    'https://user:pw@example.com/a',
    'not a url',
  ])('rejects %s', async (bad) => {
    const res = await get(bad, h.adminToken())
    expect(res.status).toBe(400)
  })

  it('returns markdown from Jina for a public URL', async () => {
    const fetchMock = vi.fn(async () => new Response('Title: Hi\n\nMarkdown Content:\n# Hi', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    const res = await get('https://support.example.com/articles/getting-started', h.adminToken())
    expect(res.status).toBe(200)
    expect(res.json.markdown).toContain('# Hi')
    expect(fetchMock.mock.calls[0][0]).toBe('https://r.jina.ai/https://support.example.com/articles/getting-started')
  })

  it('maps an upstream failure to 502', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 403 })))
    const res = await get('https://example.com/a', h.adminToken())
    expect(res.status).toBe(502)
  })
})
