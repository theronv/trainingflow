import { describe, it, expect, beforeEach } from 'vitest'
import { verify } from 'hono/jwt'
import { setupHarness } from './helpers.mjs'

const ISS = 'https://test-app.clerk.accounts.dev'
const b64u = (buf) => Buffer.from(buf).toString('base64url')

async function makeClerk(h) {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])
  const jwk = { ...(await crypto.subtle.exportKey('jwk', publicKey)), kid: 'k1' }
  h.env.CLERK_ISSUER = ISS
  h.env.CLERK_JWKS = JSON.stringify({ keys: [jwk] })
  return async (claims = {}, signKey = privateKey) => {
    const now = Math.floor(Date.now() / 1000)
    const head = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'k1' }))
    const body = b64u(JSON.stringify({ iss: ISS, sub: 'user_1', iat: now, exp: now + 60, email: 'pat@example.com', ...claims }))
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signKey, new TextEncoder().encode(`${head}.${body}`))
    return `${head}.${body}.${b64u(sig)}`
  }
}

describe('Clerk email sign-in', () => {
  let h, mint
  beforeEach(async () => { h = await setupHarness(); mint = await makeClerk(h) })
  const login = (token) => h.request('/api/auth/clerk/login', { method: 'POST', body: { token } })

  it('links an existing account by email and returns an app JWT', async () => {
    const team = await h.createTeam('T')
    const u = await h.createUser({ name: 'pat', team_id: team })
    await h.request(`/api/learners/${u.id}`, { method: 'PATCH', token: h.adminToken(), body: { email: 'Pat@Example.com' } })
    const res = await login(await mint())
    expect(res.status).toBe(200)
    const claims = await verify(res.json.token, h.env.JWT_SECRET, 'HS256')
    expect(claims).toMatchObject({ id: u.id, role: 'learner' })
    const row = (await h.db.execute({ sql: 'SELECT clerk_id FROM users WHERE id = ?', args: [u.id] })).rows[0]
    expect(row.clerk_id).toBe('user_1')
    expect((await login(await mint())).status).toBe(200) // now matched by clerk_id
  })

  it('404s when no account matches (no auto-provisioning)', async () => {
    const res = await login(await mint({ email: 'nobody@example.com', sub: 'user_x' }))
    expect(res.status).toBe(404)
    expect(res.json.code).toBe('no_account')
  })

  it('rejects forged, expired, wrong-issuer and unsigned tokens', async () => {
    const other = (await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])).privateKey
    expect((await login(await mint({}, other))).status).toBe(401)
    expect((await login(await mint({ exp: 1 }))).status).toBe(401)
    expect((await login(await mint({ iss: 'https://evil.example' }))).status).toBe(401)
    expect((await login('a.b.c')).status).toBe(401)
  })

  it('does not link an email that already belongs to another Clerk user', async () => {
    const u = await h.createUser({ name: 'pat' })
    await h.request(`/api/learners/${u.id}`, { method: 'PATCH', token: h.adminToken(), body: { email: 'pat@example.com' } })
    expect((await login(await mint())).status).toBe(200)
    expect((await login(await mint({ sub: 'user_attacker' }))).status).toBe(404)
  })

  it('invite sign-up via Clerk creates an account without a password', async () => {
    const team = await h.createTeam('T')
    const inv = await h.request('/api/admin/invites', { method: 'POST', token: h.adminToken(), body: { role: 'learner', team_id: team } })
    const code = inv.json.code
    const res = await h.request('/api/auth/register', { method: 'POST', body: { name: 'Pat Lee', code, clerk_token: await mint() } })
    expect(res.status).toBe(200)
    expect(res.json.user.role).toBe('learner')
    expect((await login(await mint())).status).toBe(200)
    // name+password login is impossible for a Clerk-created account
    const pw = await h.request('/api/learners/login', { method: 'POST', body: { name: 'Pat Lee', password: 'anything-123' } })
    expect(pw.status).toBe(401)
  })

  it('ADMIN_EMAILS signs the owner in as admin; others are unaffected', async () => {
    h.env.ADMIN_EMAILS = 'Boss@Example.com, other@example.com'
    const res = await login(await mint({ email: 'boss@example.com', sub: 'user_boss' }))
    expect(res.status).toBe(200)
    expect(res.json.user.role).toBe('admin')
    expect(await verify(res.json.token, h.env.JWT_SECRET, 'HS256')).toMatchObject({ role: 'admin' })
    expect((await h.request('/api/admin/stats', { token: res.json.token })).status).toBe(200)
    expect((await login(await mint({ email: 'pat@example.com' }))).status).toBe(404)
  })

  it('refuses everything when Clerk is not configured', async () => {
    delete h.env.CLERK_ISSUER
    expect((await login(await mint())).status).toBe(401)
  })
})
