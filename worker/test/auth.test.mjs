import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'
import app from '../index.js'

describe('auth — admin login', () => {
  let h
  beforeEach(async () => { h = await setupHarness({ adminPassword: 'super-secret-1' }) })

  it('issues a JWT for the correct password', async () => {
    const res = await h.request('/api/auth/login', { method: 'POST', body: { password: 'super-secret-1' } })
    expect(res.status).toBe(200)
    expect(typeof res.json.token).toBe('string')
  })

  it('rejects a wrong password with 401', async () => {
    const res = await h.request('/api/auth/login', { method: 'POST', body: { password: 'wrong' } })
    expect(res.status).toBe(401)
  })

  it('rate-limits after 10 attempts from the same IP', async () => {
    let last
    for (let i = 0; i < 11; i++) {
      last = await h.request('/api/auth/login', { method: 'POST', body: { password: 'wrong' }, ip: '203.0.113.9' })
    }
    expect(last.status).toBe(429)
  })
})

describe('auth — learner & manager login', () => {
  let h
  beforeEach(async () => { h = await setupHarness() })

  it('learner logs in with correct credentials', async () => {
    await h.createUser({ name: 'alex', role: 'learner', password: 'learner-pw-1' })
    const res = await h.request('/api/learners/login', { method: 'POST', body: { name: 'alex', password: 'learner-pw-1' } })
    expect(res.status).toBe(200)
    expect(typeof res.json.token).toBe('string')
  })

  it('learner login rejects a wrong password', async () => {
    await h.createUser({ name: 'alex', role: 'learner', password: 'learner-pw-1' })
    const res = await h.request('/api/learners/login', { method: 'POST', body: { name: 'alex', password: 'nope' } })
    expect(res.status).toBe(401)
  })

  it('manager login rejects a learner account (role-gated query)', async () => {
    await h.createUser({ name: 'alex', role: 'learner', password: 'learner-pw-1' })
    const res = await h.request('/api/auth/manager/login', { method: 'POST', body: { name: 'alex', password: 'learner-pw-1' } })
    expect(res.status).toBe(401)
  })

  it('manager logs in and receives team_id context', async () => {
    const team = await h.createTeam('Engineering')
    await h.createUser({ name: 'sarah', role: 'manager', team_id: team, password: 'manager-pw-1' })
    const res = await h.request('/api/auth/manager/login', { method: 'POST', body: { name: 'sarah', password: 'manager-pw-1' } })
    expect(res.status).toBe(200)
    expect(res.json.user.team_name).toBe('Engineering')
  })
})

describe('CORS — ALLOWED_ORIGIN list', () => {
  it('echoes whichever allowed origin made the request and rejects others', async () => {
    const h = await setupHarness()
    const env = { ...h.env, ALLOWED_ORIGIN: 'https://theronv.github.io,https://pregame-academy.vickerydigital.com' }
    for (const origin of ['https://theronv.github.io', 'https://pregame-academy.vickerydigital.com']) {
      const res = await app.request('/api/brand', { headers: { Origin: origin } }, env)
      expect(res.headers.get('access-control-allow-origin')).toBe(origin)
    }
    const evil = await app.request('/api/brand', { headers: { Origin: 'https://evil.example' } }, env)
    expect(evil.headers.get('access-control-allow-origin')).not.toBe('https://evil.example')
  })
})
