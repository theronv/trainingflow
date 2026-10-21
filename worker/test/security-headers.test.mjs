import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

/** SEC-01 / SEC-06: every API response carries hardening headers, and AI/brand inputs are bounded. */
describe('API security headers', () => {
  let h
  beforeEach(async () => { h = await setupHarness() })

  const headersOf = async (path, init = {}) => {
    const res = await (await import('../index.js')).default.request(path, { headers: { Origin: 'http://localhost', ...(init.headers || {}) }, method: init.method }, h.env)
    return res
  }

  it('sets hardening headers on success and error responses', async () => {
    for (const path of ['/api/brand', '/api/courses', '/api/verify/PG-NOPE']) {
      const res = await headersOf(path)
      expect(res.headers.get('x-content-type-options')).toBe('nosniff')
      expect(res.headers.get('x-frame-options')).toBe('DENY')
      expect(res.headers.get('referrer-policy')).toBe('no-referrer')
      expect(res.headers.get('strict-transport-security')).toMatch(/max-age=\d{7,}/)
      expect(res.headers.get('content-security-policy')).toContain("default-src 'none'")
      expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'")
      expect(res.headers.get('cache-control')).toBe('no-store')
    }
  })

  it('keeps cross-origin reads working for the SPA', async () => {
    const res = await headersOf('/api/brand')
    expect(res.headers.get('cross-origin-resource-policy')).toBe('cross-origin')
    expect(res.headers.get('access-control-allow-origin')).toBeTruthy()
  })

  it('answers CORS preflight with the allowed headers', async () => {
    const res = await (await import('../index.js')).default.request('/api/courses', {
      method: 'OPTIONS',
      headers: { Origin: 'http://localhost', 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization,content-type' },
    }, h.env)
    expect(res.status).toBeLessThan(300)
    expect(res.headers.get('access-control-allow-headers')).toMatch(/authorization/i)
  })
})

describe('AI proxy input bounds', () => {
  let h
  beforeEach(async () => { h = await setupHarness(); h.env.GEMINI_API_KEY = 'test-key' })

  it('rejects an oversized prompt before calling any provider', async () => {
    const res = await h.request('/api/ai/generate', { method: 'POST', token: h.adminToken(), body: { prompt: 'x'.repeat(200_001) } })
    expect(res.status).toBe(413)
  })

  it('clamps max_tokens before forwarding', async () => {
    h.env.CLAUDE_API_KEY = 'test-claude'
    let sent
    const realFetch = globalThis.fetch
    globalThis.fetch = async (url, init) => { sent = JSON.parse(init.body); return new Response(JSON.stringify({ content: [{ text: 'ok' }] }), { status: 200 }) }
    try {
      await h.request('/api/ai/generate', { method: 'POST', token: h.adminToken(), body: { prompt: 'hi', max_tokens: 9_999_999 } })
      expect(sent.max_tokens).toBe(8000)
      await h.request('/api/ai/generate', { method: 'POST', token: h.adminToken(), body: { prompt: 'hi', max_tokens: -5 } })
      expect(sent.max_tokens).toBe(1)
      await h.request('/api/ai/generate', { method: 'POST', token: h.adminToken(), body: { prompt: 'hi' } })
      expect(sent.max_tokens).toBe(1000)
    } finally { globalThis.fetch = realFetch }
  })
})

describe('brand save errors', () => {
  it('does not echo database error detail', async () => {
    const h = await setupHarness()
    await h.db.execute('DROP TABLE brand')
    const res = await h.request('/api/brand', { method: 'PUT', token: h.adminToken(), body: { org_name: 'X' } })
    expect(res.status).toBe(500)
    expect(JSON.stringify(res.json)).not.toMatch(/no such table|SQLITE|detail/i)
  })
})
