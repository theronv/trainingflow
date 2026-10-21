/**
 * Pregame Academy — Cloudflare Worker (v1.5 Production Standard)
 */

import { Hono }           from 'hono'
import { cors }           from 'hono/cors'
import { sign, verify }   from 'hono/jwt'
import { createClient }   from '@libsql/client/web'

const CONSTANTS = {
  PBKDF2_ITERATIONS: 100000,
  ADMIN_JWT_EXP_SEC: 8 * 3600,
  LEARNER_JWT_EXP_SEC: 24 * 3600,
};

// ── Utilities ─────────────────────────────────────────────────────────────────

function uid() {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12)
}

function certId() {
  return 'PG-' + crypto.randomUUID().replace(/-/g, '').slice(0, 12).toUpperCase()
}

function getDb(env) {
  // Test hook: tests inject an in-memory libSQL client as env.DB_CLIENT.
  // Never set in production (Wrangler env has no DB_CLIENT), so this is a no-op there.
  if (env.DB_CLIENT) return env.DB_CLIENT
  return createClient({ url: env.TURSO_URL, authToken: env.TURSO_TOKEN })
}

function toObjs(res) {
  if (!res) return []
  const { columns, rows } = res
  return rows.map(r => Object.fromEntries(columns.map((col, i) => [col, r[i]])))
}

function toObj(res) {
  return toObjs(res)[0] ?? null
}

const ENC = new TextEncoder()
function _b64(bytes)  { return btoa(String.fromCharCode(...bytes)) }
function _unb64(str)  { return Uint8Array.from(atob(str), c => c.charCodeAt(0)) }

async function pbkdf2Hash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key  = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: CONSTANTS.PBKDF2_ITERATIONS }, 
    key, 256
  )
  return `pbkdf2v1:${_b64(salt)}:${_b64(new Uint8Array(bits))}`
}

async function pbkdf2Verify(password, stored) {
  if (typeof stored !== 'string') return false;
  const parts = stored.split(':')
  if (parts.length !== 3 || parts[0] !== 'pbkdf2v1') return false
  
  try {
    const salt = _unb64(parts[1])
    const key  = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: CONSTANTS.PBKDF2_ITERATIONS }, 
      key, 256
    )
    const computed = _b64(new Uint8Array(bits))
    return computed === parts[2]
  } catch (e) {
    console.error('PBKDF2 Verify Error:', e)
    return false
  }
}

async function getStoredHashes(db, env) {
  const hashes = []
  try {
    const res = await db.execute({ sql: 'SELECT password_hash FROM admin WHERE id = ?', args: ['default'] })
    if (res.rows.length && res.rows[0][0]) {
      const h = String(res.rows[0][0])
      if (h.startsWith('pbkdf2v1:')) hashes.push(h)
    }
  } catch { }
  if (env.ADMIN_PASSWORD_HASH && env.ADMIN_PASSWORD_HASH.startsWith('pbkdf2v1:')) {
    hashes.push(env.ADMIN_PASSWORD_HASH)
  }
  return [...new Set(hashes)] // Unique hashes only
}

// ── One-time setup (runs once per isolate) ────────────────────────────────────

let _setupComplete = false
async function ensureSetup(db) {
  if (_setupComplete) return
  await setupBrand(db)
  await setupSections(db)
  await setupTags(db)
  await setupClerk(db)
  await setupRoles(db)
  _setupComplete = true
}

// ── App & Middleware ──────────────────────────────────────────────────────────

const app = new Hono()

// ALLOWED_ORIGIN may be a single origin or a comma-separated list (e.g. during a domain move).
// The matching request origin is echoed back; unknown origins get the first entry (and are
// therefore rejected by the browser).
const DEFAULT_ORIGIN = 'https://theronv.github.io'
app.use('/api/*', async (c, next) => {
  const allowed = String(c.env.ALLOWED_ORIGIN || '').split(',').map(o => o.trim()).filter(Boolean)
  const reqOrigin = c.req.header('origin') || ''
  const isLocalDev = reqOrigin.startsWith('http://localhost') || reqOrigin.startsWith('http://127.0.0.1')
  const list = allowed.length ? allowed : [DEFAULT_ORIGIN]
  const origin = list.includes(reqOrigin) ? reqOrigin : (!allowed.length && isLocalDev ? reqOrigin : list[0])
  return cors({
    origin,
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400
  })(c, next)
})

app.onError((err, c) => {
  console.error('API Error:', err)
  return c.json({ error: 'Internal server error' }, 500)
})

// ── Auth Middlewares ──

/**
 * Capabilities carried by a token. New tokens list them in `roles`; legacy tokens only have `role`.
 * Any token with an account id can learn. The shared-password admin has no id, so it cannot.
 */
function rolesOf(p) {
  const r = new Set(Array.isArray(p.roles) ? p.roles : [])
  if (p.role) r.add(p.role)
  if (p.id) r.add('learner')
  return r
}

/** Build the app JWT + public user object for a users row (optionally with team_name). */
async function issueSession(env, user) {
  const roles = ['learner']
  if (user.role === 'manager') roles.push('manager')
  if (Number(user.is_admin) === 1) roles.push('admin')
  const primary = roles.includes('admin') ? 'admin' : roles.includes('manager') ? 'manager' : 'learner'
  const now = Math.floor(Date.now() / 1000)
  const exp = now + (primary === 'learner' ? CONSTANTS.LEARNER_JWT_EXP_SEC : CONSTANTS.ADMIN_JWT_EXP_SEC)
  const token = await sign({ id: user.id, name: user.name, role: primary, roles, team_id: user.team_id ?? null, iat: now, exp }, env.JWT_SECRET, 'HS256')
  return { token, user: { id: user.id, name: user.name, role: primary, roles, team_id: user.team_id ?? null, team_name: user.team_name || '' } }
}

async function bearer(c) {
  const auth = c.req.header('Authorization')
  if (!auth?.startsWith('Bearer ')) return null
  try { return await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256') } catch { return null }
}

async function requireAdmin(c, next) {
  const payload = await bearer(c)
  if (!payload || !rolesOf(payload).has('admin')) return c.json({ error: 'Unauthorized' }, 401)
  c.set('user', { ...payload, isAdmin: true, scopedToTeam: null })
  await next()
}

async function requireManager(c, next) {
  const payload = await bearer(c)
  if (!payload) return c.json({ error: 'Unauthorized' }, 401)
  const roles = rolesOf(payload)
  // Admin wins over manager: someone who is both is unscoped.
  if (roles.has('admin')) c.set('user', { ...payload, isAdmin: true, scopedToTeam: null })
  else if (roles.has('manager')) c.set('user', { ...payload, isAdmin: false, scopedToTeam: payload.team_id })
  else return c.json({ error: 'Unauthorized' }, 401)
  await next()
}

// Any signed-in account (learner, manager or admin) can take courses; the id-less shared-password admin cannot.
async function requireLearner(c, next) {
  const payload = await bearer(c)
  if (!payload || !payload.id || !rolesOf(payload).has('learner')) return c.json({ error: 'Unauthorized' }, 401)
  c.set('user', payload)
  await next()
}

async function requireAnyAuth(c, next) {
  const payload = await bearer(c)
  if (!payload) return c.json({ error: 'Unauthorized' }, 401)
  c.set('user', payload)
  await next()
}

// ── Routes: Core ──────────────────────────────────────────────────────────────

async function setupBrand(db) {
  // Nullable columns are universally safe for ALTER TABLE in SQLite/libSQL.
  // These are additive migrations — each is silently skipped if the column already exists.
  try { await db.execute("ALTER TABLE brand ADD COLUMN tagline TEXT DEFAULT 'Training & Certification Platform'") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN logo_url TEXT DEFAULT ''") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN primary_color TEXT DEFAULT '#1565ff'") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN secondary_color TEXT DEFAULT '#1b1a5c'") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN accent_color TEXT DEFAULT '#d99100'") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN font_family TEXT DEFAULT 'Inter'") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN font_url TEXT DEFAULT ''") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN signatory_name TEXT DEFAULT ''") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN signatory_title TEXT DEFAULT ''") } catch {}
}

// Email sign-in (Clerk): users may link an email and a Clerk user id. Both nullable.
async function setupClerk(db) {
  try { await db.execute('ALTER TABLE users ADD COLUMN email TEXT') } catch {}
  try { await db.execute('ALTER TABLE users ADD COLUMN clerk_id TEXT') } catch {}
  try { await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_clerk_id ON users(clerk_id)') } catch {}
  try { await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(lower(email))') } catch {}
}

// Multi-role accounts: every user can learn; users.role='manager' adds team management;
// users.is_admin adds full administration.
async function setupRoles(db) {
  try { await db.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0') } catch {}
}

async function setupTags(db) {
  try { await db.execute(`CREATE TABLE IF NOT EXISTS tags (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, created_at INTEGER DEFAULT (unixepoch()))`) } catch {}
  try { await db.execute(`CREATE TABLE IF NOT EXISTS user_tags (user_id TEXT NOT NULL, tag_id TEXT NOT NULL, PRIMARY KEY (user_id, tag_id))`) } catch {}
}

app.get('/api/brand', async (c) => {
  const db = getDb(c.env)
  try {
    await ensureSetup(db)
    const res = await db.execute({ sql: 'SELECT * FROM brand WHERE id = ?', args: ['default'] })
    const brand = toObj(res)
    return brand ? c.json(brand) : c.json({ org_name: 'Pregame Academy' })
  } catch {
    return c.json({ org_name: 'Pregame Academy' })
  }
})

// ── Simple in-process rate limiter (resets per isolate restart; best-effort) ──
const _loginAttempts = new Map()
function _rateCheck(key, limit = 10) {
  const now = Date.now()
  const entry = _loginAttempts.get(key) || { count: 0, reset: now + 60_000 }
  if (now > entry.reset) { entry.count = 0; entry.reset = now + 60_000 }
  entry.count++
  _loginAttempts.set(key, entry)
  return entry.count > limit // default: block after 10 attempts per minute per IP
}

app.post('/api/auth/login', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  if (_rateCheck(`admin:${ip}`)) return c.json({ error: 'Too many attempts. Try again in a minute.' }, 429)
  const db = getDb(c.env)

  const hashes = await getStoredHashes(db, c.env)
  if (!hashes.length) return c.json({ error: 'Admin not initialised' }, 503)
  if (!c.env.JWT_SECRET) return c.json({ error: 'JWT_SECRET not initialised' }, 503)

  let ok = false
  for (const h of hashes) {
    if (await pbkdf2Verify(body.password, h)) {
      ok = true; break
    }
  }

  if (!ok) return c.json({ error: 'Unauthorized' }, 401)

  const now = Math.floor(Date.now() / 1000)
  const token = await sign({ role: 'admin', iat: now, exp: now + CONSTANTS.ADMIN_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256')
  return c.json({ token })
})

// ── Routes: Admin/Manager ─────────────────────────────────────────────────────

app.get('/api/admin/trouble-spots', requireManager, async (c) => {
  const db = getDb(c.env)
  try {
    const res = await db.execute(`
      SELECT q.question, 
             ROUND(CAST(COUNT(CASE WHEN qr.is_correct = 0 THEN 1 END) AS FLOAT) / COUNT(*) * 100, 1) as failure_rate
      FROM questions q
      JOIN question_responses qr ON q.id = qr.question_id
      GROUP BY q.id HAVING COUNT(*) > 5
      ORDER BY failure_rate DESC LIMIT 5
    `)
    return c.json(toObjs(res))
  } catch { return c.json([]) }
})

app.post('/api/admin/teams', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  await db.execute({ sql: 'INSERT INTO teams (name) VALUES (?)', args: [body.name] })
  return c.json({ ok: true }, 201)
})


// ── Invites ───────────────────────────────────────────────────────────────────
// One invite model for both roles: a code carries a role (manager|learner), an optional team,
// an expiry (default 7 days, max 90) and a use cap (managers: 1; learner team links: up to 500).
// Redeemed at POST /api/auth/register; the invitee chooses their own name and password.

// Unambiguous alphabet (no 0/O/1/I) — codes are read aloud and typed by hand.
const INVITE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
const INVITE_DEFAULT_DAYS = 7
const INVITE_MAX_DAYS = 90
const INVITE_DEFAULT_LEARNER_USES = 25
const INVITE_MAX_USES = 500

function generateInviteCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(8))
  return Array.from(bytes, n => INVITE_ALPHABET[n % INVITE_ALPHABET.length]).join('')
}

let _inviteSchemaReady = false
async function ensureInviteSchema(db) {
  if (_inviteSchemaReady) return
  for (const ddl of [
    "ALTER TABLE invite_codes ADD COLUMN role TEXT NOT NULL DEFAULT 'manager'",
    "ALTER TABLE invite_codes ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE invite_codes ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0",
  ]) { try { await db.execute(ddl) } catch { /* column already exists */ } }
  try { await db.execute('UPDATE invite_codes SET use_count = 1 WHERE used = 1 AND use_count = 0') } catch {}
  _inviteSchemaReady = true
}

/** Create an invite. `actor` is the requireManager user ({isAdmin, scopedToTeam}). */
async function createInvite(c, actor, body) {
  const db = getDb(c.env)
  await ensureInviteSchema(db)

  // Managers can only invite learners to their own team; admins choose.
  const role = actor.isAdmin ? (body.role === 'learner' ? 'learner' : 'manager') : 'learner'
  const teamId = actor.isAdmin ? (body.team_id || null) : actor.scopedToTeam
  if (!actor.isAdmin && !teamId) return c.json({ error: 'You are not assigned to a team.' }, 400)
  if (teamId) {
    const team = toObj(await db.execute({ sql: 'SELECT id FROM teams WHERE id = ?', args: [teamId] }))
    if (!team) return c.json({ error: 'Team not found' }, 404)
  }

  const maxUses = role === 'manager'
    ? 1
    : Math.min(INVITE_MAX_USES, Math.max(1, parseInt(body.max_uses, 10) || INVITE_DEFAULT_LEARNER_USES))

  let expires
  if (body.expires_at) {
    expires = new Date(body.expires_at)
    if (isNaN(expires.getTime())) return c.json({ error: 'Invalid expiry date' }, 400)
  } else {
    const days = Number(body.expires_in_days) || INVITE_DEFAULT_DAYS
    expires = new Date(Date.now() + days * 86400_000)
  }
  if (expires.getTime() <= Date.now()) return c.json({ error: 'Expiry must be in the future' }, 400)
  if (expires.getTime() > Date.now() + INVITE_MAX_DAYS * 86400_000) return c.json({ error: `Expiry can be at most ${INVITE_MAX_DAYS} days away.` }, 400)
  const expiresAt = expires.toISOString()

  // The server picks the code; an admin-supplied one is still honoured for older clients.
  const supplied = actor.isAdmin && typeof body.code === 'string' && body.code.trim() ? body.code.trim().toUpperCase() : null
  for (let attempt = 0; attempt < 5; attempt++) {
    const code = supplied || generateInviteCode()
    try {
      const res = await db.execute({
        sql: 'INSERT INTO invite_codes (code, role, team_id, max_uses, expires_at) VALUES (?, ?, ?, ?, ?)',
        args: [code, role, teamId, maxUses, expiresAt]
      })
      return c.json({ ok: true, id: Number(res.lastInsertRowid), code, role, team_id: teamId, max_uses: maxUses, expires_at: expiresAt }, 201)
    } catch (e) {
      if (e.message && e.message.includes('UNIQUE')) {
        if (supplied) return c.json({ error: 'That code already exists.' }, 409)
        continue // random collision — try another
      }
      throw e
    }
  }
  return c.json({ error: 'Could not generate a unique code — please try again.' }, 500)
}

const INVITE_SELECT = `SELECT ic.*, t.name AS team_name FROM invite_codes ic LEFT JOIN teams t ON ic.team_id = t.id`

app.get('/api/admin/invites', requireAdmin, async (c) => {
  const db = getDb(c.env)
  try {
    await ensureInviteSchema(db)
    const res = await db.execute(`${INVITE_SELECT} ORDER BY ic.created_at DESC`)
    return c.json(toObjs(res))
  } catch { return c.json([]) }
})

app.post('/api/admin/invites', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => ({}))
  return createInvite(c, { isAdmin: true, scopedToTeam: null }, body)
})

app.delete('/api/admin/invites/:id', requireAdmin, async (c) => {
  const db = getDb(c.env)
  await db.execute({ sql: 'DELETE FROM invite_codes WHERE id = ? AND used = 0', args: [c.req.param('id')] })
  return c.json({ ok: true })
})

// Team-scoped invite management for managers (admins see everything).
app.get('/api/invites', requireManager, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  await ensureInviteSchema(db)
  const res = user.scopedToTeam
    ? await db.execute({ sql: `${INVITE_SELECT} WHERE ic.team_id = ? AND ic.role = 'learner' ORDER BY ic.created_at DESC`, args: [user.scopedToTeam] })
    : await db.execute(`${INVITE_SELECT} ORDER BY ic.created_at DESC`)
  return c.json(toObjs(res))
})

app.post('/api/invites', requireManager, async (c) => {
  const body = await c.req.json().catch(() => ({}))
  return createInvite(c, c.get('user'), body)
})

app.delete('/api/invites/:id', requireManager, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  if (user.scopedToTeam) {
    await db.execute({ sql: "DELETE FROM invite_codes WHERE id = ? AND used = 0 AND team_id = ? AND role = 'learner'", args: [c.req.param('id'), user.scopedToTeam] })
  } else {
    await db.execute({ sql: 'DELETE FROM invite_codes WHERE id = ? AND used = 0', args: [c.req.param('id')] })
  }
  return c.json({ ok: true })
})

// Public: lets the join page say "You're joining <team> as <role>" before the form is filled in.
app.get('/api/auth/invite/:code', async (c) => {
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  if (_rateCheck(`invite-preview:${ip}`)) return c.json({ error: 'Too many attempts. Try again in a minute.' }, 429)
  const db = getDb(c.env)
  await ensureInviteSchema(db)
  const inv = toObj(await db.execute({
    sql: `${INVITE_SELECT} WHERE ic.code = ? AND ic.used = 0`,
    args: [String(c.req.param('code') || '').trim().toUpperCase()]
  }))
  if (!inv || (inv.expires_at && new Date(inv.expires_at) < new Date())) return c.json({ error: 'Invalid or expired invite code' }, 404)
  return c.json({ role: inv.role || 'manager', team_name: inv.team_name || '' })
})

app.patch('/api/admin/teams/:id', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  await db.execute({ sql: 'UPDATE teams SET name = ? WHERE id = ?', args: [body.name, c.req.param('id')] })
  return c.json({ ok: true })
})

app.delete('/api/admin/teams/:id', requireAdmin, async (c) => {
  const db = getDb(c.env)
  const tid = c.req.param('id')
  try {
    await db.execute({ sql: 'UPDATE users SET team_id = NULL WHERE team_id = ?', args: [tid] })
    await db.execute({ sql: 'DELETE FROM invite_codes WHERE team_id = ?', args: [tid] })
    await db.execute({ sql: 'DELETE FROM teams WHERE id = ?', args: [tid] })
    return c.json({ ok: true })
  } catch(e) {
    return c.json({ error: e.message }, 500)
  }
})

app.patch('/api/admin/learners/:lid/team', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  await db.execute({ sql: 'UPDATE users SET team_id = ? WHERE id = ?', args: [body.team_id, c.req.param('lid')] })
  return c.json({ ok: true })
})

app.put('/api/brand', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  try {
    await ensureSetup(db)
    await db.execute({
      sql: `INSERT INTO brand (id, org_name, tagline, primary_color, secondary_color, accent_color, logo_url, pass_threshold, font_family, font_url, signatory_name, signatory_title)
            VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              org_name        = excluded.org_name,
              tagline         = excluded.tagline,
              primary_color   = excluded.primary_color,
              secondary_color = excluded.secondary_color,
              accent_color    = excluded.accent_color,
              logo_url        = excluded.logo_url,
              pass_threshold  = excluded.pass_threshold,
              font_family     = excluded.font_family,
              font_url        = excluded.font_url,
              signatory_name  = excluded.signatory_name,
              signatory_title = excluded.signatory_title`,
      args: [body.org_name, body.tagline || '', body.primary_color || '#2563eb', body.secondary_color || '#7c3aed', body.accent_color || '#0891b2', body.logo_url || '', body.pass_threshold ?? 80, body.font_family || 'Inter', body.font_url || '', String(body.signatory_name || '').slice(0, 80), String(body.signatory_title || '').slice(0, 80)]
    })
    return c.json({ ok: true })
  } catch (e) {
    console.error('PUT /api/brand error:', e)
    return c.json({ error: 'Failed to save branding', detail: e.message }, 500)
  }
})

app.put('/api/admin/password', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  if (!body.new_password || body.new_password.length < 8)
    return c.json({ error: 'Password must be at least 8 characters' }, 400)
  if (!body.current_password)
    return c.json({ error: 'Current password is required' }, 400)
  const hashes = await getStoredHashes(db, c.env)
  const stored = hashes[0]
  if (stored) {
    const ok = await pbkdf2Verify(body.current_password, stored)
    if (!ok) return c.json({ error: 'Current password is incorrect' }, 400)
  }
  const hash = await pbkdf2Hash(body.new_password)
  await db.execute({ sql: 'INSERT OR REPLACE INTO admin (id, password_hash) VALUES (?, ?)', args: ['default', hash] })
  return c.json({ ok: true })
})

app.put('/api/learners/:id/password', requireManager, async (c) => {
  const user = c.get('user')
  const body = await c.req.json()
  const db = getDb(c.env)
  if (!body.password || body.password.length < 8)
    return c.json({ error: 'Password must be at least 8 characters' }, 400)
  if (user.scopedToTeam) {
    const check = await db.execute({ sql: 'SELECT id FROM users WHERE id = ? AND team_id = ?', args: [c.req.param('id'), user.scopedToTeam] })
    if (!check.rows.length) return c.json({ error: 'Not found' }, 404)
  }
  const hash = await pbkdf2Hash(body.password)
  await db.execute({ sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [hash, c.req.param('id')] })
  return c.json({ ok: true })
})

app.post('/api/learners/bulk', requireManager, async (c) => {
  const user = c.get('user')
  const body = await c.req.json()
  const teamId = user.scopedToTeam || body.team_id || null
  const db = getDb(c.env)
  const created = [], errors = []

  for (const row of (body.learners || [])) {
    const name = (row.name || '').trim()
    const password = row.password || ''
    if (!name || !password) { errors.push({ name: name || '(blank)', error: 'Name and password are required' }); continue }
    if (password.length < 8)  { errors.push({ name, error: 'Password must be at least 8 characters' }); continue }
    try {
      const hash = await pbkdf2Hash(password)
      const id = uid()
      await db.execute({ sql: 'INSERT INTO users (id, name, password_hash, role, team_id) VALUES (?, ?, ?, ?, ?)', args: [id, name, hash, 'learner', teamId] })
      created.push({ id, name })
    } catch(e) {
      errors.push({ name, error: e.message.includes('UNIQUE') ? 'Name already exists' : e.message })
    }
  }
  return c.json({ created: created.length, created_learners: created, errors }, 201)
})

app.patch('/api/learners/bulk', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const ids = body.ids || []
  if (!ids.length) return c.json({ error: 'No ids provided' }, 400)
  const db = getDb(c.env)
  const fields = [], args = []
  if (body.team_id !== undefined) { fields.push('team_id = ?'); args.push(body.team_id || null) }
  if (body.role) {
    if (body.role !== 'manager' && body.role !== 'learner') return c.json({ error: 'role must be manager or learner' }, 400)
    fields.push('role = ?'); args.push(body.role)
  }
  if (body.is_admin !== undefined) {
    if (!body.is_admin && ids.includes(c.get('user').id)) return c.json({ error: 'You cannot remove your own admin access.' }, 400)
    await ensureSetup(db)
    fields.push('is_admin = ?'); args.push(body.is_admin ? 1 : 0)
  }
  if (!fields.length) return c.json({ error: 'Nothing to update' }, 400)
  args.push(...ids)
  await db.execute({
    sql: `UPDATE users SET ${fields.join(', ')} WHERE id IN (${ids.map(() => '?').join(',')})`,
    args
  })
  return c.json({ ok: true, updated: ids.length })
})

app.post('/api/learners/bulk/delete', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const ids = body.ids || []
  if (!ids.length) return c.json({ error: 'No ids provided' }, 400)
  const db = getDb(c.env)
  await db.execute({
    sql: `DELETE FROM users WHERE id IN (${ids.map(() => '?').join(',')})`,
    args: ids
  })
  return c.json({ ok: true, deleted: ids.length })
})

app.post('/api/learners', requireManager, async (c) => {
  const user = c.get('user')
  const body = await c.req.json()
  if (!body.name || !body.password) return c.json({ error: 'Name and password are required' }, 400)
  if (body.password.length < 8) return c.json({ error: 'Password must be at least 8 characters' }, 400)
  // Only admins can create manager accounts; scoped managers always create learners
  const role = (user.isAdmin && body.role === 'manager') ? 'manager' : 'learner'
  // Scoped managers are locked to their own team; admins can specify any team
  const teamId = user.isAdmin ? (body.team_id || null) : user.scopedToTeam
  const db = getDb(c.env)
  const name = String(body.name).trim()
  const hash = await pbkdf2Hash(body.password)
  const id = uid()
  const email = String(body.email || '').trim().toLowerCase()
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return c.json({ error: 'Enter a valid email address.' }, 400)
  await ensureSetup(db)
  try {
    await db.execute({
      sql: 'INSERT INTO users (id, name, password_hash, role, team_id, email, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)',
      args: [id, name, hash, role, teamId, email || null, user.isAdmin && body.is_admin ? 1 : 0]
    })
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) return c.json({ error: 'A user with that name or email already exists.' }, 409)
    throw e
  }
  return c.json({ id }, 201)
})

// NOTE: the /me routes must be registered before /:id, or 'me' is captured as an id.
app.get('/api/learners/me', requireLearner, async (c) => {
  const user = c.get('user')
  return c.json({ id: user.id, name: user.name })
})

app.patch('/api/learners/me', requireLearner, async (c) => {
  const user = c.get('user')
  const body = await c.req.json().catch(() => ({}))
  const db = getDb(c.env)
  if (body.password) {
    if (body.password.length < 8) return c.json({ error: 'Password must be at least 8 characters' }, 400)
    const row = toObj(await db.execute({ sql: 'SELECT password_hash FROM users WHERE id = ?', args: [user.id] }))
    if (!row || !(await pbkdf2Verify(body.current_password || '', row.password_hash))) return c.json({ error: 'Current password is incorrect' }, 400)
    const hash = await pbkdf2Hash(body.password)
    await db.execute({ sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [hash, user.id] })
  }
  if (body.name && body.name.trim()) {
    await db.execute({ sql: 'UPDATE users SET name = ? WHERE id = ?', args: [body.name.trim(), user.id] })
    return c.json({ ok: true, name: body.name.trim() })
  }
  return c.json({ ok: true })
})

app.get('/api/learners/:id', requireManager, async (c) => {
  const caller = c.get('user')
  const db = getDb(c.env)
  const lid = c.req.param('id')
  let sql = 'SELECT id, name, role, team_id, last_login_at, created_at FROM users WHERE id = ?'
  const args = [lid]
  if (caller.scopedToTeam) { sql += ' AND team_id = ?'; args.push(caller.scopedToTeam) }
  const res = await db.execute({ sql, args })
  const user = toObj(res)
  if (!user) return c.json({ error: 'Not found' }, 404)
  return c.json(user)
})

app.patch('/api/learners/:id', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  const fields = []
  const args = []
  if (body.is_admin !== undefined) {
    if (!body.is_admin && c.get('user').id === c.req.param('id')) return c.json({ error: 'You cannot remove your own admin access.' }, 400)
    await ensureSetup(db)
    fields.push('is_admin = ?'); args.push(body.is_admin ? 1 : 0)
  }
  if (body.name !== undefined)    { fields.push('name = ?');    args.push(body.name.trim()) }
  if (body.team_id !== undefined) { fields.push('team_id = ?'); args.push(body.team_id || null) }
  if (body.role !== undefined)    { fields.push('role = ?');    args.push(body.role === 'manager' ? 'manager' : 'learner') }
  if (body.email !== undefined) {
    const email = String(body.email || '').trim().toLowerCase()
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return c.json({ error: 'Enter a valid email address.' }, 400)
    await ensureSetup(db)
    fields.push('email = ?'); args.push(email || null)
    // Changing the email unlinks Clerk so the next sign-in re-links against the new address.
    fields.push('clerk_id = NULL')
  }
  if (!fields.length) return c.json({ error: 'Nothing to update' }, 400)
  args.push(c.req.param('id'))
  try {
    await db.execute({ sql: `UPDATE users SET ${fields.join(', ')} WHERE id = ?`, args })
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) return c.json({ error: 'That email or name is already in use.' }, 409)
    throw e
  }
  return c.json({ ok: true })
})

app.delete('/api/learners/:id', requireAdmin, async (c) => {
  const db = getDb(c.env)
  await db.execute({ sql: 'DELETE FROM users WHERE id = ?', args: [c.req.param('id')] })
  return c.json({ ok: true })
})

// Redeems an invite: the invitee picks their own name + password and is signed in.
// `requiredRole` pins the legacy manager endpoint to manager invites.
// ── Access requests (new learners ask to join; an admin approves) ─────────────
async function ensureAccessSchema(db) {
  await db.execute(`CREATE TABLE IF NOT EXISTS access_requests (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL,
    message    TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL DEFAULT 'pending',
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  )`)
}
const _requestAttempts = new Map()
function _requestRateLimited(ip) {
  const now = Date.now()
  const e = _requestAttempts.get(ip) || { count: 0, reset: now + 3600_000 }
  if (now > e.reset) { e.count = 0; e.reset = now + 3600_000 }
  e.count++
  _requestAttempts.set(ip, e)
  return e.count > 5 // 5 requests per hour per IP
}
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

// Public. Always answers the same way so it can't be used to discover who has an account.
app.post('/api/access-requests', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  if (body.website) return c.json({ ok: true }, 201) // honeypot: bots fill hidden fields
  if (_requestRateLimited(ip)) return c.json({ error: 'Too many requests. Please try again later.' }, 429)
  const name = typeof body.name === 'string' ? body.name.trim() : ''
  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : ''
  const message = typeof body.message === 'string' ? body.message.trim().slice(0, 500) : ''
  if (!name || name.length > 100) return c.json({ error: 'Please enter your full name.' }, 400)
  if (!EMAIL_RE.test(email) || email.length > 200) return c.json({ error: 'Please enter a valid email address.' }, 400)
  const db = getDb(c.env)
  await ensureSetup(db)
  await ensureAccessSchema(db)
  const existingUser = await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(email) = ?', args: [email] })
  const pending = await db.execute({ sql: "SELECT 1 FROM access_requests WHERE lower(email) = ? AND status = 'pending'", args: [email] })
  const total = toObj(await db.execute("SELECT COUNT(*) AS n FROM access_requests WHERE status = 'pending'"))?.n || 0
  if (!existingUser.rows.length && !pending.rows.length && Number(total) < 200) {
    await db.execute({ sql: 'INSERT INTO access_requests (id, name, email, message) VALUES (?, ?, ?, ?)', args: [uid(), name, email, message] })
  }
  return c.json({ ok: true }, 201)
})

app.get('/api/admin/access-requests', requireAdmin, async (c) => {
  const db = getDb(c.env)
  await ensureAccessSchema(db)
  const res = await db.execute("SELECT id, name, email, message, created_at FROM access_requests WHERE status = 'pending' ORDER BY created_at")
  return c.json(toObjs(res))
})

// Ask Clerk to email a sign-up invitation (needed once Clerk's Access mode is Restricted).
// Never blocks approval: returns false if Clerk isn't configured or the call fails.
async function sendClerkInvitation(env, email) {
  if (!env.CLERK_SECRET_KEY) return false
  try {
    const res = await fetch('https://api.clerk.com/v1/invitations', {
      method: 'POST',
      headers: { Authorization: `Bearer ${String(env.CLERK_SECRET_KEY).trim()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email_address: email, redirect_url: env.APP_URL || 'https://pregame-academy.vickerydigital.com', notify: true, ignore_existing: true }),
    })
    return res.ok
  } catch { return false }
}

// Approve: creates a learner with that email. They then sign in with their email (no password to hand over).
app.post('/api/admin/access-requests/:id/approve', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const db = getDb(c.env)
  await ensureSetup(db)
  await ensureAccessSchema(db)
  const reqRow = toObj(await db.execute({ sql: "SELECT * FROM access_requests WHERE id = ? AND status = 'pending'", args: [c.req.param('id')] }))
  if (!reqRow) return c.json({ error: 'Request not found' }, 404)
  if ((await db.execute({ sql: 'SELECT 1 FROM users WHERE lower(email) = ?', args: [reqRow.email] })).rows.length) {
    await db.execute({ sql: "UPDATE access_requests SET status = 'approved' WHERE id = ?", args: [reqRow.id] })
    return c.json({ error: 'That email already has an account.' }, 409)
  }
  let teamId = null
  if (body.team_id) {
    const t = await db.execute({ sql: 'SELECT id FROM teams WHERE id = ?', args: [body.team_id] })
    if (!t.rows.length) return c.json({ error: 'Team not found' }, 400)
    teamId = t.rows[0].id
  }
  const hash = await pbkdf2Hash(_b64(crypto.getRandomValues(new Uint8Array(32)))) // unusable; sign-in is by email
  const id = uid()
  let name = reqRow.name
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await db.execute({
        sql: 'INSERT INTO users (id, name, password_hash, role, team_id, email) VALUES (?, ?, ?, ?, ?, ?)',
        args: [id, name, hash, 'learner', teamId, reqRow.email]
      })
      await db.execute({ sql: "UPDATE access_requests SET status = 'approved' WHERE id = ?", args: [reqRow.id] })
      const invited = await sendClerkInvitation(c.env, reqRow.email)
      return c.json({ ok: true, invited, user: { id, name, email: reqRow.email, team_id: teamId } }, 201)
    } catch (e) {
      if (!(e.message || '').includes('UNIQUE') || attempt) return c.json({ error: 'Could not create the account (name already in use).' }, 409)
      name = `${reqRow.name} (${reqRow.email.split('@')[0]})` // name taken: disambiguate once
    }
  }
})

app.delete('/api/admin/access-requests/:id', requireAdmin, async (c) => {
  const db = getDb(c.env)
  await ensureAccessSchema(db)
  await db.execute({ sql: "UPDATE access_requests SET status = 'dismissed' WHERE id = ? AND status = 'pending'", args: [c.req.param('id')] })
  return c.json({ ok: true })
})

// ── Clerk email sign-in ───────────────────────────────────────────────────────
// The browser signs in with Clerk, then exchanges the Clerk session token here for the
// app's own JWT, so every existing role check, team scope and test keeps working unchanged.
// Setup: set CLERK_ISSUER (e.g. https://your-app.clerk.accounts.dev) and, in the Clerk
// dashboard (Sessions → Customize session token), add:  { "email": "{{user.primary_email_address}}" }
// CLERK_JWKS (JSON) may be set to pin the public keys instead of fetching them.
const _b64urlToBytes = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='
  return Uint8Array.from(atob(s), ch => ch.charCodeAt(0))
}
let _jwks = { at: 0, keys: null }
async function getClerkKeys(env) {
  if (env.CLERK_JWKS) return JSON.parse(env.CLERK_JWKS).keys || []
  env = { ...env, CLERK_ISSUER: String(env.CLERK_ISSUER).trim() }
  if (_jwks.keys && Date.now() - _jwks.at < 3600_000) return _jwks.keys
  const res = await fetch(`${env.CLERK_ISSUER.trim().replace(/\/$/, '')}/.well-known/jwks.json`)
  if (!res.ok) throw new Error('JWKS fetch failed')
  _jwks = { at: Date.now(), keys: (await res.json()).keys || [] }
  return _jwks.keys
}

/** Returns { sub, email } for a valid Clerk session token, otherwise null.
 *  `why` (optional object) receives a short, non-secret reason when verification fails. */
async function verifyClerkToken(env, token, why = {}) {
  const fail = (reason) => { why.reason = reason; return null }
  try {
    if (!env.CLERK_ISSUER) return fail('CLERK_ISSUER not set on the worker')
    if (typeof token !== 'string') return fail('no token')
    const [h, p, sig] = token.split('.')
    if (!h || !p || !sig) return fail('malformed token')
    const header = JSON.parse(new TextDecoder().decode(_b64urlToBytes(h)))
    if (header.alg !== 'RS256') return fail(`unexpected alg ${header.alg}`)
    const jwk = (await getClerkKeys(env)).find(k => k.kid === header.kid)
    if (!jwk) return fail('signing key not found for this token (kid mismatch)')
    const key = await crypto.subtle.importKey('jwk', { ...jwk, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, _b64urlToBytes(sig), ENC.encode(`${h}.${p}`))
    if (!ok) return fail('bad signature')
    const claims = JSON.parse(new TextDecoder().decode(_b64urlToBytes(p)))
    const now = Math.floor(Date.now() / 1000)
    const expected = env.CLERK_ISSUER.trim().replace(/\/$/, '')
    if (claims.iss !== expected) return fail(`issuer mismatch: token says "${claims.iss}", worker expects "${expected}"`)
    if (!claims.sub) return fail('no subject')
    if (claims.exp && claims.exp < now) return fail('token expired')
    if (claims.nbf && claims.nbf > now + 5) return fail('token not yet valid')
    const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : ''
    return { sub: claims.sub, email }
  } catch (e) { return fail(`error: ${e.message}`) }
}

app.post('/api/auth/clerk/login', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  if (_rateCheck(`clerk:${ip}`)) return c.json({ error: 'Too many attempts. Try again in a minute.' }, 429)
  const why = {}
  const clerk = await verifyClerkToken(c.env, body.token, why)
  if (!clerk) return c.json({ error: `Email sign-in could not be verified (${why.reason || 'unknown'}).` }, 401)
  // Owner/admin emails (comma-separated secret ADMIN_EMAILS) are admins. They get a normal users row
  // (so they can also take courses) with is_admin recorded, so it shows up in Users.
  const adminEmails = String(c.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean)
  const isOwner = !!clerk.email && adminEmails.includes(clerk.email)
  const db = getDb(c.env)
  await ensureSetup(db)
  const find = (sql, args) => db.execute({ sql: `SELECT u.*, t.name AS team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE ${sql}`, args }).then(toObj)
  let user = await find('u.clerk_id = ?', [clerk.sub])
  if (!user && clerk.email) {
    // First email sign-in for an existing account: link it by (case-insensitive) email.
    user = await find('lower(u.email) = ? AND u.clerk_id IS NULL', [clerk.email])
    if (user) await db.execute({ sql: 'UPDATE users SET clerk_id = ? WHERE id = ?', args: [clerk.sub, user.id] })
  }
  if (!user && !clerk.email) return c.json({ error: 'Signed in, but your sign-in token has no email. In Clerk (Sessions → Customize session token) add { "email": "{{user.primary_email_address}}" } and click Save.', code: 'no_email_claim' }, 401)
  if (!user && isOwner) {
    const hash = await pbkdf2Hash(_b64(crypto.getRandomValues(new Uint8Array(32)))) // never disclosed: email sign-in only
    const local = clerk.email.split('@')[0]
    for (const name of [local, clerk.email, `${local}-${uid().slice(0, 4)}`]) {
      const id = uid()
      try {
        await db.execute({ sql: "INSERT INTO users (id, name, password_hash, role, team_id, email, clerk_id, is_admin) VALUES (?, ?, ?, 'learner', NULL, ?, ?, 1)", args: [id, name, hash, clerk.email, clerk.sub] })
        user = await find('u.id = ?', [id]); break
      } catch (e) { if (!String(e.message).includes('UNIQUE')) throw e }
    }
  }
  if (!user) return c.json({ error: `No account found for ${clerk.email}. Ask for an invite or use Request access.`, code: 'no_account' }, 404)
  if (isOwner && Number(user.is_admin) !== 1) {
    await db.execute({ sql: 'UPDATE users SET is_admin = 1 WHERE id = ?', args: [user.id] })
    user.is_admin = 1
  }
  await db.execute({ sql: 'UPDATE users SET last_login_at = ? WHERE id = ?', args: [Math.floor(Date.now() / 1000), user.id] })
  return c.json(await issueSession(c.env, user))
})

async function registerWithInvite(c, requiredRole) {
  const body = await c.req.json().catch(() => ({}))
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  if (_rateCheck(`register:${ip}`)) return c.json({ error: 'Too many attempts. Try again in a minute.' }, 429)
  const name = typeof body.name === 'string' ? body.name.trim() : ''
  const code = typeof body.code === 'string' ? body.code.trim().toUpperCase() : ''
  if (!name) return c.json({ error: 'Please enter your full name.' }, 400)
  if (name.length > 100) return c.json({ error: 'That name is too long.' }, 400)
  // Email sign-up: a verified Clerk session replaces the password.
  let clerk = null
  if (body.clerk_token) {
    clerk = await verifyClerkToken(c.env, body.clerk_token)
    if (!clerk) return c.json({ error: 'Email sign-in could not be verified. Please try again.' }, 401)
  } else if (typeof body.password !== 'string' || body.password.length < 8) {
    return c.json({ error: 'Password must be at least 8 characters.' }, 400)
  }
  if (!code) return c.json({ error: 'Please enter your invite code.' }, 400)

  const db = getDb(c.env)
  await ensureSetup(db)
  await ensureInviteSchema(db)
  if (clerk) {
    const taken = await db.execute({ sql: 'SELECT id FROM users WHERE clerk_id = ? OR lower(email) = ?', args: [clerk.sub, clerk.email || ''] })
    if (taken.rows.length) return c.json({ error: 'That email already has an account. Sign in instead.' }, 409)
  }
  const inv = toObj(await db.execute({ sql: 'SELECT * FROM invite_codes WHERE code = ? AND used = 0', args: [code] }))
  const invalid = () => c.json({ error: 'Invalid or expired invite code' }, 400)
  if (!inv || (requiredRole && inv.role !== requiredRole)) return invalid()
  if (inv.expires_at && new Date(inv.expires_at) < new Date()) return c.json({ error: 'Invite code has expired' }, 400)
  const role = inv.role === 'learner' ? 'learner' : 'manager'

  // Claim a use atomically (guards the cap under concurrent redemptions), then create the user.
  const claim = await db.execute({
    sql: `UPDATE invite_codes
             SET use_count = use_count + 1, used = CASE WHEN use_count + 1 >= max_uses THEN 1 ELSE 0 END
           WHERE id = ? AND used = 0 AND use_count < max_uses`,
    args: [inv.id]
  })
  if (claim.rowsAffected !== 1) return invalid()

  // Clerk users get a random, never-disclosed password hash so name+password login can't be used.
  const hash = await pbkdf2Hash(clerk ? _b64(crypto.getRandomValues(new Uint8Array(32))) : body.password)
  const id = uid()
  try {
    await db.execute({
      sql: 'INSERT INTO users (id, name, password_hash, role, team_id, email, clerk_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
      args: [id, name, hash, role, inv.team_id, clerk?.email || null, clerk?.sub || null]
    })
    await db.execute({ sql: 'UPDATE invite_codes SET used_by = ? WHERE id = ?', args: [id, inv.id] })
  } catch (e) {
    // Give the use back so a typo'd name doesn't burn the invite.
    await db.execute({ sql: 'UPDATE invite_codes SET use_count = use_count - 1, used = 0 WHERE id = ?', args: [inv.id] })
    if (e.message && e.message.includes('UNIQUE')) {
      return c.json({ error: 'That name is already taken. Try adding a middle initial.' }, 409)
    }
    return c.json({ error: 'Failed to create account. Please try again.' }, 500)
  }

  const teamName = inv.team_id ? (toObj(await db.execute({ sql: 'SELECT name FROM teams WHERE id = ?', args: [inv.team_id] }))?.name || '') : ''
  return c.json(await issueSession(c.env, { id, name, role, team_id: inv.team_id, team_name: teamName }))
}

app.post('/api/auth/register', (c) => registerWithInvite(c, null))
app.post('/api/auth/manager/register', (c) => registerWithInvite(c, 'manager'))

app.delete('/api/completions', requireAdmin, async (c) => {
  const db = getDb(c.env)
  await db.execute("DELETE FROM completions")
  return c.json({ ok: true })
})

app.get('/api/admin/teams', requireManager, async (c) => {
  const db = getDb(c.env)
  try {
    const res = await db.execute(`
      SELECT t.*, 
             (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'learner') as learner_count,
             (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'manager') as manager_count
      FROM teams t ORDER BY t.name
    `)
    return c.json(toObjs(res))
  } catch {
    const res = await db.execute("SELECT * FROM teams ORDER BY name")
    return c.json(toObjs(res))
  }
})

app.get('/api/learners', requireManager, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  await ensureSetup(db) // selects users.email, which older databases only gain via setupClerk
  const tid = c.req.query('team_id')
  const roleFilter = c.req.query('role')
  const page = parseInt(c.req.query('page') || '0')
  const PAGE_SIZE = 50

  let where = []
  let args = []

  if (user.scopedToTeam) {
    // Managers only see their team's learners
    where.push("u.role = 'learner'")
    where.push('u.team_id = ?'); args.push(user.scopedToTeam)
  } else {
    // Admins see all users; optional role filter
    if (roleFilter) { where.push('u.role = ?'); args.push(roleFilter) }
    if (tid && tid !== 'null') {
      where.push('u.team_id = ?'); args.push(tid)
    } else if (tid === 'null') {
      where.push('u.team_id IS NULL')
    }
  }

  const baseWhere = where.length ? `WHERE ${where.join(' AND ')}` : ''

  // Per-learner stats computed via subqueries
  const stats = `,
    (SELECT COUNT(*) FROM assignments a WHERE a.learner_id = u.id) AS assignment_count,
    (SELECT COUNT(*) FROM completions c WHERE c.learner_id = u.id) AS completion_count,
    CASE WHEN (SELECT COUNT(*) FROM completions c WHERE c.learner_id = u.id) > 0
      THEN CAST(ROUND(100.0 *
        (SELECT COUNT(*) FROM completions c WHERE c.learner_id = u.id AND c.passed = 1) /
        (SELECT COUNT(*) FROM completions c WHERE c.learner_id = u.id)
      ) AS INTEGER)
      ELSE 0
    END AS pass_rate,
    (SELECT COUNT(*) FROM assignments a
      WHERE a.learner_id = u.id
        AND a.due_at IS NOT NULL
        AND a.due_at < strftime('%Y-%m-%d %H:%M:%S', 'now')
        AND NOT EXISTS (SELECT 1 FROM completions c WHERE c.learner_id = u.id AND c.course_id = a.course_id AND c.passed = 1)
    ) AS overdue_count`

  const safeColumns = 'u.id, u.name, u.email, u.role, u.is_admin, u.team_id, u.last_login_at, u.created_at'

  if (page > 0) {
    const [countRes, rowsRes] = await Promise.all([
      db.execute({ sql: `SELECT COUNT(*) AS n FROM users u ${baseWhere}`, args }),
      db.execute({ sql: `SELECT ${safeColumns}${stats} FROM users u ${baseWhere} ORDER BY u.name LIMIT ${PAGE_SIZE} OFFSET ${(page - 1) * PAGE_SIZE}`, args })
    ])
    const total = toObj(countRes)?.n || 0
    return c.json({ rows: toObjs(rowsRes), total, page, pages: Math.ceil(total / PAGE_SIZE) })
  }

  const res = await db.execute({ sql: `SELECT ${safeColumns}${stats} FROM users u ${baseWhere} ORDER BY u.name`, args })
  return c.json(toObjs(res))
})


app.get('/api/admin/stats', requireManager, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  const st = user.scopedToTeam
  const wa = st ? [st] : []

  try {
    const d = new Date(); d.setDate(1); d.setHours(0, 0, 0, 0)
    const monthStart = Math.floor(d.getTime() / 1000)
    const teamFilter = st ? ' AND c.learner_id IN (SELECT id FROM users WHERE team_id = ?)' : ''
    const [lc, cc, lr, cm, pr] = await Promise.all([
      db.execute({ sql: `SELECT COUNT(*) AS n FROM users WHERE role = 'learner'${st ? ' AND team_id = ?' : ''}`, args: wa }),
      db.execute('SELECT COUNT(*) AS n FROM courses'),
      db.execute({ sql: `SELECT id, name, role, team_id, last_login_at, created_at FROM users WHERE role = 'learner'${st ? ' AND team_id = ?' : ''} LIMIT 5`, args: wa }),
      db.execute({ sql: `SELECT COUNT(*) AS n FROM completions c WHERE c.completed_at >= ?${teamFilter}`, args: st ? [monthStart, st] : [monthStart] }),
      db.execute({ sql: `SELECT COUNT(*) AS total, SUM(CASE WHEN c.passed = 1 THEN 1 ELSE 0 END) AS passed FROM completions c WHERE 1=1${teamFilter}`, args: st ? [st] : [] }),
    ])
    const prRow = toObj(pr)
    const passRate = prRow?.total > 0 ? Math.round((prRow.passed / prRow.total) * 100) : 0
    return c.json({
      summary: {
        total_learners: toObj(lc)?.n || 0,
        total_courses: toObj(cc)?.n || 0,
        completions_this_month: toObj(cm)?.n || 0,
        pass_rate: passRate
      },
      learners: toObjs(lr)
    })
  } catch {
    return c.json({ summary: { total_learners: 0, total_courses: 0, completions_this_month: 0, pass_rate: 0 }, learners: [] })
  }
})

app.get('/api/courses', requireAnyAuth, async (c) => {
  const db = getDb(c.env)
  const res = await db.execute('SELECT * FROM courses ORDER BY created_at')
  return c.json(toObjs(res))
})

app.get('/api/courses/:id', requireAnyAuth, async (c) => {
  const db = getDb(c.env)
  try {
    const courseRes = await db.execute({ sql: 'SELECT * FROM courses WHERE id = ?', args: [c.req.param('id')] })
    const course = toObj(courseRes)
    if (!course) return c.json({ error: 'Not found' }, 404)
    const modRes = await db.execute({ sql: 'SELECT * FROM modules WHERE course_id = ? ORDER BY sort_order', args: [course.id] })
    const modules = toObjs(modRes)
    for (const mod of modules) {
      const qRes = await db.execute({ sql: 'SELECT * FROM questions WHERE module_id = ? ORDER BY sort_order', args: [mod.id] })
      mod.questions = toObjs(qRes)
    }
    // The answer key never leaves the server for learners/managers: answers are graded
    // via POST /api/quiz/answer, and scores are computed in POST /api/completions.
    if (c.get('user')?.role !== 'admin') {
      for (const mod of modules) {
        mod.questions = mod.questions.map(({ correct_index: _key, explanation: _why, ...safe }) => safe)
      }
    }
    return c.json({ ...course, modules })
  } catch { return c.json({ error: 'Not found' }, 404) }
})

app.get('/api/assignments', requireManager, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  let sql = 'SELECT * FROM assignments'
  const args = []
  if (user.scopedToTeam) {
    sql = 'SELECT a.* FROM assignments a JOIN users u ON a.learner_id = u.id WHERE u.team_id = ?'
    args.push(user.scopedToTeam)
  }
  const res = await db.execute({ sql, args })
  return c.json(toObjs(res))
})

// Per-learner latest answer for each question. Graded server-side; the final score is
// computed from these rows, never from anything the client reports.
const QUIZ_DDL = `CREATE TABLE IF NOT EXISTS quiz_answers (
  learner_id     TEXT NOT NULL,
  question_id    TEXT NOT NULL,
  selected_index INTEGER NOT NULL,
  is_correct     INTEGER NOT NULL,
  answered_at    INTEGER NOT NULL,
  PRIMARY KEY (learner_id, question_id)
)`

app.post('/api/quiz/answer', requireLearner, async (c) => {
  const user = c.get('user')
  const body = await c.req.json().catch(() => ({}))
  const qid = String(body.question_id || '')
  const sel = Number(body.selected_index)
  if (!qid || !Number.isInteger(sel) || sel < 0 || sel > 3) return c.json({ error: 'question_id and selected_index (0-3) are required' }, 400)
  const db = getDb(c.env)
  const q = toObj(await db.execute({ sql: 'SELECT correct_index, explanation FROM questions WHERE id = ?', args: [qid] }))
  if (!q) return c.json({ error: 'Question not found' }, 404)
  const correctIndex = Number(q.correct_index)
  const ok = sel === correctIndex ? 1 : 0
  await db.execute(QUIZ_DDL)
  await db.execute({
    sql: 'INSERT OR REPLACE INTO quiz_answers (learner_id, question_id, selected_index, is_correct, answered_at) VALUES (?, ?, ?, ?, ?)',
    args: [user.id, qid, sel, ok, Math.floor(Date.now() / 1000)]
  })
  return c.json({ correct: !!ok, correct_index: correctIndex, explanation: q.explanation || '' })
})

app.post('/api/completions', requireLearner, async (c) => {
  const user = c.get('user')
  const body = await c.req.json().catch(() => ({}))
  const courseId = String(body.course_id || '')
  const db = getDb(c.env)

  const course = toObj(await db.execute({ sql: 'SELECT id FROM courses WHERE id = ?', args: [courseId] }))
  if (!course) return c.json({ error: 'Course not found' }, 404)

  // Pass threshold is server-side; the client-supplied score/passed are ignored entirely.
  let passThreshold = 80
  try {
    const brandRow = toObj(await db.execute({ sql: 'SELECT pass_threshold FROM brand WHERE id = ?', args: ['default'] }))
    if (brandRow?.pass_threshold != null) passThreshold = Number(brandRow.pass_threshold)
  } catch {}

  await db.execute(QUIZ_DDL)
  const courseQuestions = 'SELECT q.id FROM questions q JOIN modules m ON q.module_id = m.id WHERE m.course_id = ?'
  const total = Number(toObj(await db.execute({ sql: `SELECT COUNT(*) AS n FROM (${courseQuestions})`, args: [courseId] })).n)
  const answers = toObjs(await db.execute({
    sql: `SELECT question_id, is_correct FROM quiz_answers WHERE learner_id = ? AND question_id IN (${courseQuestions})`,
    args: [user.id, courseId]
  }))

  if (total > 0 && answers.length < total) {
    return c.json({ error: 'Answer every question in the course before finishing.' }, 400)
  }
  const correct = answers.filter(a => Number(a.is_correct) === 1).length
  const score = total > 0 ? Math.round((correct / total) * 100) : 100
  const passed = score >= passThreshold ? 1 : 0

  // Per-module results and the attempt number feed the learner's result screen. Read before the answers are consumed.
  const [breakdownRes, earlierRes] = await Promise.all([
    db.execute({
      sql: `SELECT m.id AS module_id, m.title, SUM(a.is_correct) AS correct, COUNT(*) AS total
            FROM quiz_answers a JOIN questions q ON q.id = a.question_id JOIN modules m ON m.id = q.module_id
            WHERE a.learner_id = ? AND m.course_id = ? GROUP BY m.id ORDER BY m.sort_order`,
      args: [user.id, courseId]
    }),
    db.execute({ sql: 'SELECT COUNT(*) AS n FROM completions WHERE learner_id = ? AND course_id = ?', args: [user.id, courseId] })
  ])
  const breakdown = toObjs(breakdownRes).map(r => ({ module_id: r.module_id, title: r.title, correct: Number(r.correct), total: Number(r.total) }))
  const earlier = Number(toObj(earlierRes).n)

  const rid = uid()
  const cid = certId()
  const now = Math.floor(Date.now() / 1000)
  const stmts = [{
    sql: 'INSERT INTO completions (id, learner_id, learner_name, course_id, score, passed, cert_id, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    args: [rid, user.id, user.name, courseId, score, passed, cid, now]
  }]
  for (const a of answers) {
    stmts.push({
      sql: 'INSERT INTO question_responses (completion_id, question_id, is_correct) VALUES (?, ?, ?)',
      args: [rid, a.question_id, Number(a.is_correct)]
    })
  }
  // Consume the answers so a certificate can't be re-minted without taking the quiz again.
  stmts.push({
    sql: `DELETE FROM quiz_answers WHERE learner_id = ? AND question_id IN (${courseQuestions})`,
    args: [user.id, courseId]
  })
  await db.batch(stmts, 'write')
  return c.json({ cert_id: cid, score, passed: !!passed, pass_mark: passThreshold, attempt: earlier + 1, breakdown }, 201)
})

app.get('/api/admin/completions', requireManager, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  const cid = c.req.query('course_id')
  const from = c.req.query('from')
  const to = c.req.query('to')

  let sql = `SELECT c.*, co.title AS course_title, u.name AS user_name
             FROM completions c
             JOIN courses co ON c.course_id = co.id
             JOIN users u ON c.learner_id = u.id`
  let args = []
  let where = []

  if (cid) { where.push('c.course_id = ?'); args.push(cid) }
  if (user.scopedToTeam) { where.push('u.team_id = ?'); args.push(user.scopedToTeam) }
  if (from) {
    const ts = new Date(from).getTime()
    if (isNaN(ts)) return c.json({ error: 'Invalid from date' }, 400)
    where.push('c.completed_at >= ?'); args.push(Math.floor(ts / 1000))
  }
  if (to) {
    const ts = new Date(to + 'T23:59:59').getTime()
    if (isNaN(ts)) return c.json({ error: 'Invalid to date' }, 400)
    where.push('c.completed_at <= ?'); args.push(Math.floor(ts / 1000))
  }

  if (where.length) sql += ' WHERE ' + where.join(' AND ')

  try {
    const res = await db.execute({ sql: sql + ' ORDER BY c.completed_at DESC', args })
    return c.json(toObjs(res).map(r => ({ ...r, passed: !!r.passed })))
  } catch {
    return c.json([])
  }
})

const PROGRESS_DDL = `CREATE TABLE IF NOT EXISTS course_progress (
  learner_id TEXT NOT NULL,
  course_id  TEXT NOT NULL,
  module_idx INTEGER NOT NULL DEFAULT 0,
  modules    TEXT NOT NULL DEFAULT '[]',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (learner_id, course_id)
)`

app.get('/api/progress/me', requireLearner, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  try {
    await db.execute(PROGRESS_DDL)
    const res = await db.execute({ sql: 'SELECT * FROM course_progress WHERE learner_id = ?', args: [user.id] })
    return c.json(toObjs(res).map(r => ({ ...r, modules: JSON.parse(r.modules || '[]') })))
  } catch { return c.json([]) }
})

app.post('/api/progress', requireLearner, async (c) => {
  const user = c.get('user')
  const body = await c.req.json()
  const db = getDb(c.env)
  await db.execute(PROGRESS_DDL)
  await db.execute({
    sql: `INSERT OR REPLACE INTO course_progress (learner_id, course_id, module_idx, modules, updated_at) VALUES (?, ?, ?, ?, ?)`,
    args: [user.id, body.course_id, body.module_idx, JSON.stringify(body.modules || []), Math.floor(Date.now() / 1000)]
  })
  return c.json({ ok: true })
})

app.delete('/api/progress/:course_id', requireLearner, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  try {
    await db.execute({ sql: 'DELETE FROM course_progress WHERE learner_id = ? AND course_id = ?', args: [user.id, c.req.param('course_id')] })
  } catch {}
  return c.json({ ok: true })
})

// Public certificate check (the QR code on every certificate points here). Reveals only what is printed on the
// certificate itself: name, course, organisation and date. Failed attempts and unknown ids are indistinguishable.
app.get('/api/verify/:certId', async (c) => {
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  if (_rateCheck(`verify:${ip}`, 30)) return c.json({ error: 'Too many lookups. Try again in a minute.' }, 429)
  const certId = String(c.req.param('certId') || '').trim().toUpperCase()
  const db = getDb(c.env)
  const row = toObj(await db.execute({
    sql: `SELECT c.cert_id, c.learner_name, c.completed_at, co.title AS course_title
          FROM completions c LEFT JOIN courses co ON co.id = c.course_id
          WHERE c.cert_id = ? AND c.passed = 1`,
    args: [certId]
  }))
  if (!row) return c.json({ valid: false }, 404)
  let org = 'Pregame Academy'
  try {
    const brand = toObj(await db.execute({ sql: 'SELECT org_name FROM brand WHERE id = ?', args: ['default'] }))
    if (brand?.org_name) org = brand.org_name
  } catch {}
  return c.json({
    valid: true, cert_id: row.cert_id, name: row.learner_name,
    course: row.course_title || 'Course no longer available', org, completed_at: Number(row.completed_at)
  })
})

app.get('/api/completions/me', requireLearner, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  const res = await db.execute({ 
    sql: 'SELECT c.*, co.title AS course_title FROM completions c JOIN courses co ON c.course_id = co.id WHERE learner_id = ? ORDER BY completed_at DESC', 
    args: [user.id] 
  })
  return c.json(toObjs(res).map(r => ({ ...r, passed: !!r.passed })))
})

app.get('/api/assignments/me', requireLearner, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  const res = await db.execute({ 
    sql: 'SELECT a.*, co.title AS course_title FROM assignments a JOIN courses co ON a.course_id = co.id WHERE learner_id = ?', 
    args: [user.id] 
  })
  return c.json(toObjs(res))
})

// ── Sections ──────────────────────────────────────────────────────────────────

async function setupSections(db) {
  await db.execute('CREATE TABLE IF NOT EXISTS sections (id TEXT PRIMARY KEY, name TEXT NOT NULL, sort_order INTEGER DEFAULT 0, created_at INTEGER)')
  try { await db.execute('ALTER TABLE sections ADD COLUMN parent_id TEXT') } catch {}
  try { await db.execute('ALTER TABLE courses ADD COLUMN section_id TEXT') } catch {}
  try { await db.execute('ALTER TABLE courses ADD COLUMN reference_url TEXT') } catch {}
  try { await db.execute('ALTER TABLE modules ADD COLUMN summary TEXT') } catch {}
  try { await db.execute('ALTER TABLE modules ADD COLUMN reference_url TEXT') } catch {}
  try { await db.execute('ALTER TABLE modules ADD COLUMN learning_objectives TEXT') } catch {}
}

app.get('/api/sections', requireAnyAuth, async (c) => {
  const db = getDb(c.env)
  await ensureSetup(db)
  const res = await db.execute('SELECT * FROM sections ORDER BY sort_order, name')
  return c.json(toObjs(res))
})

app.post('/api/sections', requireAdmin, async (c) => {
  const body = await c.req.json()
  if (!body.name?.trim()) return c.json({ error: 'Name required' }, 400)
  const db = getDb(c.env)
  await ensureSetup(db)
  const parentId = body.parent_id || null
  if (parentId) {
    // One level of nesting: the parent must exist and must itself be top-level.
    const p = await db.execute({ sql: 'SELECT parent_id FROM sections WHERE id = ?', args: [parentId] })
    if (!p.rows.length) return c.json({ error: 'Parent section not found' }, 400)
    if (p.rows[0].parent_id) return c.json({ error: 'Sub-sections can only be one level deep' }, 400)
  }
  const id = uid()
  await db.execute({ sql: 'INSERT INTO sections (id, name, sort_order, created_at, parent_id) VALUES (?, ?, ?, ?, ?)', args: [id, body.name.trim(), body.sort_order ?? 0, Math.floor(Date.now() / 1000), parentId] })
  return c.json({ id }, 201)
})

app.patch('/api/sections/:id', requireAdmin, async (c) => {
  const body = await c.req.json()
  if (!body.name?.trim()) return c.json({ error: 'Name required' }, 400)
  const db = getDb(c.env)
  await db.execute({ sql: 'UPDATE sections SET name = ? WHERE id = ?', args: [body.name.trim(), c.req.param('id')] })
  return c.json({ ok: true })
})

// Persists the display order of every section. The list must contain each existing section
// exactly once; sort_order becomes the position. Sub-sections are grouped under their parent
// by the clients, so one flat order is enough.
app.put('/api/sections/order', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const ids = body.ids
  if (!Array.isArray(ids) || ids.some(i => typeof i !== 'string') || new Set(ids).size !== ids.length) {
    return c.json({ error: 'ids must be a list of unique section ids' }, 400)
  }
  const db = getDb(c.env)
  await ensureSetup(db)
  const existing = toObjs(await db.execute('SELECT id FROM sections')).map(r => r.id)
  if (existing.length !== ids.length || existing.some(i => !ids.includes(i))) {
    return c.json({ error: 'The section list has changed. Refresh the page and try again.' }, 409)
  }
  if (ids.length) await db.batch(ids.map((id, i) => ({ sql: 'UPDATE sections SET sort_order = ? WHERE id = ?', args: [i, id] })), 'write')
  return c.json({ ok: true })
})

app.delete('/api/sections/:id', requireAdmin, async (c) => {
  const db = getDb(c.env)
  try { await db.execute({ sql: 'UPDATE courses SET section_id = NULL WHERE section_id = ?', args: [c.req.param('id')] }) } catch {}
  // Children of a deleted section become top-level sections.
  try { await db.execute({ sql: 'UPDATE sections SET parent_id = NULL WHERE parent_id = ?', args: [c.req.param('id')] }) } catch {}
  await db.execute({ sql: 'DELETE FROM sections WHERE id = ?', args: [c.req.param('id')] })
  return c.json({ ok: true })
})

app.patch('/api/courses/:id', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  await ensureSetup(db)
  const fields = [], args = []
  if (body.section_id !== undefined)    { fields.push('section_id = ?');    args.push(body.section_id || null) }
  if (body.title !== undefined)         { fields.push('title = ?');         args.push(body.title.trim()) }
  if (body.reference_url !== undefined) { fields.push('reference_url = ?'); args.push(body.reference_url || null) }
  if (!fields.length) return c.json({ error: 'Nothing to update' }, 400)
  args.push(c.req.param('id'))
  await db.execute({ sql: `UPDATE courses SET ${fields.join(', ')} WHERE id = ?`, args })
  return c.json({ ok: true })
})

// ── AI Generation ─────────────────────────────────────────────────────────────

async function callClaudeGeneric(prompt, systemPrompt, maxTokens, apiKey) {
  const body = {
    model: 'claude-sonnet-4-6',
    max_tokens: maxTokens,
    messages: [{ role: 'user', content: prompt }]
  }
  if (systemPrompt) body.system = systemPrompt
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error?.message || `Claude API error ${res.status}`)
  }
  const data = await res.json()
  return { text: data.content[0].text, _provider: 'Claude' }
}

async function callGeminiGeneric(prompt, systemPrompt, maxTokens, apiKey) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`
  const fullPrompt = systemPrompt ? systemPrompt + '\n\n' + prompt : prompt
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: fullPrompt }] }] })
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error?.message || `Gemini API error ${res.status}`)
  }
  const data = await res.json()
  return { text: data.candidates[0].content.parts[0].text, _provider: 'Gemini' }
}

// ── URL scrape (AI Importer) ──
// Fetches a public web page as Markdown via Jina Reader. Admin-only; only public
// http(s) hostnames are accepted so this can't be pointed at internal addresses.
const SCRAPE_MAX_CHARS = 2 * 1024 * 1024

function parseScrapeUrl(raw) {
  let u
  try { u = new URL(String(raw || '').trim()) } catch { return null }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
  if (u.username || u.password) return null
  const h = u.hostname.toLowerCase()
  const internal = h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')
  if (internal || !h.includes('.') || h.startsWith('[') || /^\d+\.\d+\.\d+\.\d+$/.test(h)) return null
  return u
}

app.get('/api/scrape', requireAdmin, async (c) => {
  const u = parseScrapeUrl(c.req.query('url'))
  if (!u) return c.json({ error: 'A public http(s) URL is required' }, 400)
  let res
  try {
    res = await fetch(`https://r.jina.ai/${u.href}`, {
      headers: {
        Accept: 'text/plain', 'X-Return-Format': 'markdown', 'User-Agent': 'PregameAcademy-Importer',
        // Optional: a Jina API key lifts the shared-IP rate limit (wrangler secret put JINA_API_KEY)
        ...(c.env.JINA_API_KEY ? { Authorization: `Bearer ${c.env.JINA_API_KEY}` } : {}),
      },
      signal: AbortSignal.timeout(25000),
    })
  } catch {
    return c.json({ error: 'Could not reach the page (timed out or blocked)' }, 502)
  }
  if (res.status === 429) return c.json({ error: 'The page reader is rate-limiting requests — wait a minute and try again' }, 429)
  if (!res.ok) return c.json({ error: `Page fetch failed (${res.status})` }, 502)
  const markdown = await res.text()
  if (!markdown.trim()) return c.json({ error: 'The page returned no readable content' }, 422)
  if (markdown.length > SCRAPE_MAX_CHARS) return c.json({ error: 'Page is too large to import (max 2MB)' }, 413)
  return c.json({ markdown, url: u.href })
})

// Generic AI proxy — reads keys from env secrets; falls back to request body for self-hosted/dev
app.post('/api/ai/generate', requireAdmin, async (c) => {
  const body = await c.req.json()
  const { prompt, system_prompt = '', max_tokens = 1000, claude_key, gemini_key } = body
  if (!prompt) return c.json({ error: 'prompt is required' }, 400)

  const claudeKey = c.env.CLAUDE_API_KEY || claude_key
  const geminiKey = c.env.GEMINI_API_KEY || gemini_key
  if (!claudeKey && !geminiKey) return c.json({ error: 'No AI keys configured. Set CLAUDE_API_KEY or GEMINI_API_KEY env secrets.' }, 400)

  let lastError = null
  if (claudeKey) {
    try { return c.json(await callClaudeGeneric(prompt, system_prompt, max_tokens, claudeKey)) }
    catch (e) { lastError = e; console.error('Claude failed:', e.message) }
  }
  if (geminiKey) {
    try { return c.json(await callGeminiGeneric(prompt, system_prompt, max_tokens, geminiKey)) }
    catch (e) { lastError = e; console.error('Gemini failed:', e.message) }
  }
  return c.json({ error: lastError?.message || 'All AI providers failed' }, 502)
})

// ── NEW ROUTES ──────────────────────────────────────────────────────────────

app.post('/api/courses', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  const cid = uid()

  await ensureSetup(db)

  // Build all INSERT statements and fire them as a single batch request to Turso.
  // Sequential db.execute() calls make one HTTP round-trip per statement — for a
  // large course (e.g. 10 modules × 8 questions) that is 90+ round-trips and will
  // time out. db.batch() sends everything in one HTTP request.
  const stmts = []

  stmts.push({
    sql: 'INSERT INTO courses (id, title, icon, description, reference_url) VALUES (?, ?, ?, ?, ?)',
    args: [cid, body.title, body.icon || '📋', body.description || '', body.reference_url || null]
  })

  if (body.modules) {
    for (let i = 0; i < body.modules.length; i++) {
      const m = body.modules[i]
      const mid = uid()
      stmts.push({
        sql: 'INSERT INTO modules (id, course_id, title, content, summary, reference_url, learning_objectives, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        args: [mid, cid, m.title, m.content || '', m.summary || null, m.reference_url || null, m.learning_objectives ? JSON.stringify(m.learning_objectives) : null, i]
      })
      if (m.questions) {
        for (let j = 0; j < m.questions.length; j++) {
          const q = m.questions[j]
          const opts = q.options || q.opts || []
          stmts.push({
            sql: 'INSERT INTO questions (id, module_id, question, option_a, option_b, option_c, option_d, correct_index, explanation, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            args: [
              uid(), mid,
              q.question || q.q || '',
              opts[0] || q.option_a || '',
              opts[1] || q.option_b || '',
              opts[2] || q.option_c || '',
              opts[3] || q.option_d || '',
              q.correct_index ?? q.correct ?? 0,
              q.explanation || q.exp || '',
              j
            ]
          })
        }
      }
    }
  }

  try {
    await db.batch(stmts, 'write')
  } catch (e) {
    console.error('POST /api/courses batch error:', e.message)
    return c.json({ error: e.message || 'Failed to save course' }, 500)
  }

  return c.json({ id: cid }, 201)
})

app.put('/api/courses/:id', requireAdmin, async (c) => {
  const cid = c.req.param('id')
  const body = await c.req.json()
  const db = getDb(c.env)
  try {
    await ensureSetup(db)

    // Fetch old module IDs in one read so we can delete their questions.
    const oldMods = await db.execute({ sql: 'SELECT id FROM modules WHERE course_id = ?', args: [cid] })
    const oldModIds = toObjs(oldMods).map(r => r.id)

    // Build all writes as a single batch — one HTTP round-trip to Turso.
    const stmts = []

    stmts.push({
      sql: 'UPDATE courses SET title = ?, icon = ?, description = ?, reference_url = ? WHERE id = ?',
      args: [body.title, body.icon || '📋', body.description || '', body.reference_url || null, cid]
    })

    // Delete old questions and modules
    for (const mid of oldModIds) {
      stmts.push({ sql: 'DELETE FROM questions WHERE module_id = ?', args: [mid] })
    }
    stmts.push({ sql: 'DELETE FROM modules WHERE course_id = ?', args: [cid] })

    // Insert new modules and questions
    if (body.modules) {
      for (let i = 0; i < body.modules.length; i++) {
        const m = body.modules[i]
        const mid = uid()
        stmts.push({
          sql: 'INSERT INTO modules (id, course_id, title, content, summary, reference_url, learning_objectives, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          args: [mid, cid, m.title, m.content || '', m.summary || null, m.reference_url || null, m.learning_objectives ? JSON.stringify(m.learning_objectives) : null, i]
        })
        if (m.questions) {
          for (let j = 0; j < m.questions.length; j++) {
            const q = m.questions[j]
            // Handle both raw DB format (option_a/b/c/d) and normalized frontend format (options[])
            const opts = q.opts || q.options || []
            stmts.push({
              sql: 'INSERT INTO questions (id, module_id, question, option_a, option_b, option_c, option_d, correct_index, explanation, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
              args: [
                uid(), mid,
                q.question || q.q || '',
                opts[0] || q.option_a || '',
                opts[1] || q.option_b || '',
                opts[2] || q.option_c || '',
                opts[3] || q.option_d || '',
                q.correct_index ?? q.correct ?? 0,
                q.explanation || q.exp || '',
                j
              ]
            })
          }
        }
      }
    }

    await db.batch(stmts, 'write')
    return c.json({ ok: true })
  } catch (e) {
    console.error('PUT /api/courses/:id error:', e.message)
    return c.json({ error: e.message || 'Failed to save course' }, 500)
  }
})

app.delete('/api/courses/:id', requireAdmin, async (c) => {
  const db = getDb(c.env)
  const cid = c.req.param('id')
  try {
    const modRes = await db.execute({ sql: 'SELECT id FROM modules WHERE course_id = ?', args: [cid] })
    const modIds = modRes.rows.map(r => String(r[0]))
    const stmts = []
    modIds.forEach(mid => stmts.push({ sql: 'DELETE FROM questions WHERE module_id = ?', args: [mid] }))
    stmts.push({ sql: 'DELETE FROM modules WHERE course_id = ?',        args: [cid] })
    stmts.push({ sql: 'DELETE FROM assignments WHERE course_id = ?',    args: [cid] })
    stmts.push({ sql: 'DELETE FROM course_progress WHERE course_id = ?', args: [cid] })
    stmts.push({ sql: 'DELETE FROM completions WHERE course_id = ?',    args: [cid] })
    stmts.push({ sql: 'DELETE FROM courses WHERE id = ?',               args: [cid] })
    await db.batch(stmts, 'write')
    return c.json({ ok: true })
  } catch(e) {
    return c.json({ error: e.message || 'Failed to delete course' }, 500)
  }
})

app.post('/api/assignments', requireManager, async (c) => {
  const caller = c.get('user')
  const body = await c.req.json()
  const db = getDb(c.env)
  if (caller.scopedToTeam) {
    const check = await db.execute({ sql: 'SELECT id FROM users WHERE id = ? AND team_id = ?', args: [body.learner_id, caller.scopedToTeam] })
    if (!check.rows.length) return c.json({ error: 'Not found' }, 404)
  }
  try {
    await db.execute({
      sql: 'INSERT INTO assignments (course_id, learner_id, due_at) VALUES (?, ?, ?)',
      args: [body.course_id, body.learner_id, body.due_at || null]
    })
    return c.json({ ok: true }, 201)
  } catch (e) {
    if (e.message.includes('UNIQUE')) return c.json({ error: 'Already assigned' }, 409)
    return c.json({ error: e.message }, 500)
  }
})

// Assign one course to many learners and/or whole teams in a single batch.
// Body: { course_id, learner_ids?: string[], team_ids?: (number|string)[], due_at? }
const MAX_BULK_COURSES = 100
app.post('/api/assignments/bulk', requireManager, async (c) => {
  const caller = c.get('user')
  const body = await c.req.json().catch(() => ({}))
  const db = getDb(c.env)
  // One course (`course_id`) or several (`course_ids`); each selected learner is assigned every course.
  const rawCourseIds = Array.isArray(body.course_ids) ? body.course_ids : (body.course_id ? [body.course_id] : [])
  const courseIds = [...new Set(rawCourseIds)]
  if (!courseIds.length) return c.json({ error: 'course_id or course_ids required' }, 400)
  if (courseIds.length > MAX_BULK_COURSES) return c.json({ error: `Select at most ${MAX_BULK_COURSES} courses at a time` }, 400)
  const learnerIds = Array.isArray(body.learner_ids) ? body.learner_ids : []
  const teamIds = Array.isArray(body.team_ids) ? body.team_ids : []
  if (!learnerIds.length && !teamIds.length) return c.json({ error: 'Select at least one learner or team' }, 400)

  const marks = courseIds.map(() => '?').join(',')
  const found = await db.execute({ sql: `SELECT id FROM courses WHERE id IN (${marks})`, args: courseIds })
  if (found.rows.length !== courseIds.length) return c.json({ error: 'Course not found' }, 404)

  // Resolve every target to a real learner row; managers are limited to their own team.
  const ids = new Set()
  const scope = caller.scopedToTeam ? ' AND team_id = ?' : ''
  const scopeArg = caller.scopedToTeam ? [caller.scopedToTeam] : []
  for (const lid of learnerIds) {
    // Admins may also pick managers individually; team managers only ever assign learners on their team.
    const roleOk = caller.scopedToTeam ? "role = 'learner'" : "role IN ('learner', 'manager')"
    const r = await db.execute({ sql: `SELECT id FROM users WHERE id = ? AND ${roleOk}${scope}`, args: [lid, ...scopeArg] })
    if (r.rows.length) ids.add(r.rows[0].id)
  }
  for (const tid of teamIds) {
    const r = await db.execute({ sql: `SELECT id FROM users WHERE team_id = ? AND role = 'learner'${scope}`, args: [tid, ...scopeArg] })
    r.rows.forEach(row => ids.add(row.id))
  }
  if (!ids.size) return c.json({ error: 'No matching learners' }, 404)

  const countSql = `SELECT COUNT(*) AS n FROM assignments WHERE course_id IN (${marks})`
  const before = await db.execute({ sql: countSql, args: courseIds })
  await db.batch(courseIds.flatMap(cid => [...ids].map(lid => ({
    sql: 'INSERT OR IGNORE INTO assignments (course_id, learner_id, due_at) VALUES (?, ?, ?)',
    args: [cid, lid, body.due_at || null]
  }))), 'write')
  const after = await db.execute({ sql: countSql, args: courseIds })
  const added = Number(after.rows[0].n) - Number(before.rows[0].n)
  return c.json({ ok: true, added, skipped: ids.size * courseIds.length - added }, 201)
})

app.delete('/api/assignments', requireManager, async (c) => {
  const caller = c.get('user')
  const body = await c.req.json()
  const db = getDb(c.env)
  if (caller.scopedToTeam) {
    const check = await db.execute({ sql: 'SELECT id FROM users WHERE id = ? AND team_id = ?', args: [body.learner_id, caller.scopedToTeam] })
    if (!check.rows.length) return c.json({ error: 'Not found' }, 404)
  }
  await db.execute({
    sql: 'DELETE FROM assignments WHERE course_id = ? AND learner_id = ?',
    args: [body.course_id, body.learner_id]
  })
  return c.json({ ok: true })
})

app.post('/api/auth/manager/login', async (c) => {
  const body = await c.req.json()
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  if (_rateCheck(`manager:${ip}`)) return c.json({ error: 'Too many attempts. Try again in a minute.' }, 429)
  const db = getDb(c.env)
  await ensureSetup(db)
  const res = await db.execute({
    sql: "SELECT u.*, t.name AS team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.name = ? AND (u.role = 'manager' OR u.is_admin = 1)",
    args: [body.name]
  })
  const user = toObj(res)
  if (!user || !(await pbkdf2Verify(body.password, user.password_hash))) return c.json({ error: 'Unauthorized' }, 401)
  await db.execute({ sql: 'UPDATE users SET last_login_at = ? WHERE id = ?', args: [Math.floor(Date.now() / 1000), user.id] })
  return c.json(await issueSession(c.env, user))
})

// Any account can sign in here; managers and admins land in their own portal and can switch to learning.
app.post('/api/learners/login', async (c) => {
  const body = await c.req.json()
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  if (_rateCheck(`learner:${ip}`)) return c.json({ error: 'Too many attempts. Try again in a minute.' }, 429)
  const db = getDb(c.env)
  await ensureSetup(db)
  const res = await db.execute({ sql: 'SELECT u.*, t.name AS team_name FROM users u LEFT JOIN teams t ON u.team_id = t.id WHERE u.name = ?', args: [body.name] })
  const user = toObj(res)
  if (!user || !(await pbkdf2Verify(body.password, user.password_hash))) return c.json({ error: 'Unauthorized' }, 401)
  return c.json(await issueSession(c.env, user))
})

app.patch('/api/managers/me', requireManager, async (c) => {
  const user = c.get('user')
  const body = await c.req.json().catch(() => ({}))
  const db = getDb(c.env)
  if (body.password) {
    if (body.password.length < 8) return c.json({ error: 'Password must be at least 8 characters' }, 400)
    const row = toObj(await db.execute({ sql: 'SELECT password_hash FROM users WHERE id = ?', args: [user.id] }))
    if (!row || !(await pbkdf2Verify(body.current_password || '', row.password_hash))) return c.json({ error: 'Current password is incorrect' }, 400)
    const hash = await pbkdf2Hash(body.password)
    await db.execute({ sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [hash, user.id] })
  }
  if (body.name && body.name.trim()) {
    await db.execute({ sql: 'UPDATE users SET name = ? WHERE id = ?', args: [body.name.trim(), user.id] })
  }
  return c.json({ ok: true })
})


// ── Content backup ───────────────────────────────────────────────────────────
// One self-contained JSON file of the training content: sections, courses, modules and
// questions (answer keys included, so admin only). Learner accounts, assignments and
// completions are deliberately not part of it.

const BACKUP_FORMAT = 'pregame-academy-content'
const BACKUP_VERSION = 1
const BACKUP_MAX_COURSES = 500

app.get('/api/admin/backup', requireAdmin, async (c) => {
  const db = getDb(c.env)
  await ensureSetup(db)
  const [sections, courses, modules, questions] = await Promise.all([
    db.execute('SELECT id, name, parent_id, sort_order FROM sections ORDER BY sort_order, name'),
    db.execute('SELECT id, icon, title, description, reference_url, section_id FROM courses ORDER BY title'),
    db.execute('SELECT id, course_id, title, content, summary, reference_url, learning_objectives, sort_order FROM modules ORDER BY course_id, sort_order'),
    db.execute('SELECT id, module_id, question, option_a, option_b, option_c, option_d, correct_index, explanation, sort_order FROM questions ORDER BY module_id, sort_order'),
  ])
  const qByModule = new Map()
  for (const q of toObjs(questions)) {
    const { module_id, ...rest } = q
    if (!qByModule.has(module_id)) qByModule.set(module_id, [])
    qByModule.get(module_id).push(rest)
  }
  const mByCourse = new Map()
  for (const m of toObjs(modules)) {
    const { course_id, ...rest } = m
    if (!mByCourse.has(course_id)) mByCourse.set(course_id, [])
    mByCourse.get(course_id).push({ ...rest, questions: qByModule.get(m.id) || [] })
  }
  const courseList = toObjs(courses).map(co => ({ ...co, modules: mByCourse.get(co.id) || [] }))
  return c.json({
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    exported_at: new Date().toISOString(),
    counts: {
      sections: sections.rows.length,
      courses: courseList.length,
      modules: modules.rows.length,
      questions: questions.rows.length,
    },
    sections: toObjs(sections),
    courses: courseList,
  })
})

const isText = (v) => typeof v === 'string' && v.trim().length > 0

// Returns an error message for the first structural problem, or null. Accepts files from
// before versioning (just { courses: [...] }) as long as the courses are well-formed.
function validateBackup(body) {
  if (!body || typeof body !== 'object') return 'Backup file is not valid JSON.'
  if (body.format !== undefined && body.format !== BACKUP_FORMAT) return 'This file is not a Pregame Academy content backup.'
  if (body.version !== undefined && body.version > BACKUP_VERSION) return 'This backup was made by a newer version of the app.'
  if (!Array.isArray(body.courses)) return 'Invalid backup file: no courses list found.'
  if (body.courses.length > BACKUP_MAX_COURSES) return `Backup has more than ${BACKUP_MAX_COURSES} courses.`
  if (body.sections !== undefined && !Array.isArray(body.sections)) return 'Invalid backup file: sections must be a list.'
  for (const s of body.sections || []) if (!isText(s?.id) || !isText(s?.name)) return 'Invalid backup file: every section needs an id and name.'
  for (const co of body.courses) {
    if (!isText(co?.id) || !isText(co?.title)) return 'Invalid backup file: every course needs an id and title.'
    for (const m of co.modules || []) {
      if (!isText(m?.id) || !isText(m?.title)) return `Invalid backup file: a module in "${co.title}" is missing its id or title.`
      for (const q of m.questions || []) {
        if (!isText(q?.id) || !isText(q?.question)) return `Invalid backup file: a question in "${co.title}" is missing its id or text.`
      }
    }
  }
  return null
}

// Restore adds what is missing and never overwrites: courses and sections whose id already
// exists are skipped. Everything is written in one batch, so a bad file changes nothing.
app.post('/api/admin/backup/restore', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null)
  const problem = validateBackup(body)
  if (problem) return c.json({ error: problem }, 400)
  const db = getDb(c.env)
  await ensureSetup(db)

  const existingSections = new Set(toObjs(await db.execute('SELECT id FROM sections')).map(r => r.id))
  const existingCourses = new Set(toObjs(await db.execute('SELECT id FROM courses')).map(r => r.id))
  const stmts = []
  let sectionsAdded = 0, imported = 0, skipped = 0

  // Parents before children, so a sub-section never points at a missing parent.
  const sections = [...(body.sections || [])].sort((a, b) => (a.parent_id ? 1 : 0) - (b.parent_id ? 1 : 0))
  for (const s of sections) {
    if (existingSections.has(s.id)) continue
    const parent = s.parent_id && existingSections.has(s.parent_id) ? s.parent_id : null
    stmts.push({ sql: 'INSERT INTO sections (id, name, sort_order, created_at, parent_id) VALUES (?, ?, ?, ?, ?)', args: [s.id, s.name.trim(), Number(s.sort_order) || 0, Math.floor(Date.now() / 1000), parent] })
    existingSections.add(s.id)
    sectionsAdded++
  }

  for (const course of body.courses) {
    if (existingCourses.has(course.id)) { skipped++; continue }
    const sectionId = course.section_id && existingSections.has(course.section_id) ? course.section_id : null
    stmts.push({
      sql: 'INSERT INTO courses (id, title, description, icon, reference_url, section_id) VALUES (?, ?, ?, ?, ?, ?)',
      args: [course.id, course.title, course.description || '', course.icon || '📋', course.reference_url || null, sectionId],
    })
    ;(course.modules || []).forEach((mod, mi) => {
      const objectives = Array.isArray(mod.learning_objectives) ? JSON.stringify(mod.learning_objectives) : (mod.learning_objectives || null)
      stmts.push({
        sql: 'INSERT INTO modules (id, course_id, title, content, summary, reference_url, learning_objectives, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        args: [mod.id, course.id, mod.title, mod.content || '', mod.summary || '', mod.reference_url || null, objectives, mi],
      })
      ;(mod.questions || []).forEach((q, qi) => {
        const opts = q.options || []
        stmts.push({
          sql: 'INSERT INTO questions (id, module_id, question, option_a, option_b, option_c, option_d, correct_index, explanation, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          args: [q.id, mod.id, q.question, q.option_a || opts[0] || '', q.option_b || opts[1] || '', q.option_c || opts[2] || '', q.option_d || opts[3] || '', q.correct_index || 0, q.explanation || '', qi],
        })
      })
    })
    imported++
  }

  try {
    if (stmts.length) await db.batch(stmts, 'write')
  } catch {
    return c.json({ error: 'Restore failed and nothing was changed. The file may reuse ids that already exist in another course.' }, 409)
  }
  return c.json({ ok: true, imported, skipped, sections: sectionsAdded })
})

// ── Tags ─────────────────────────────────────────────────────────────────────

app.get('/api/admin/tags', requireManager, async (c) => {
  const db = getDb(c.env)
  await ensureSetup(db)
  const res = await db.execute('SELECT * FROM tags ORDER BY name')
  return c.json(toObjs(res))
})

app.post('/api/admin/tags', requireAdmin, async (c) => {
  const body = await c.req.json()
  if (!body.name?.trim()) return c.json({ error: 'Name required' }, 400)
  const db = getDb(c.env)
  await ensureSetup(db)
  const id = uid()
  await db.execute({ sql: 'INSERT INTO tags (id, name) VALUES (?, ?)', args: [id, body.name.trim()] })
  return c.json({ id, name: body.name.trim() }, 201)
})

app.delete('/api/admin/tags/:id', requireAdmin, async (c) => {
  const db = getDb(c.env)
  const id = c.req.param('id')
  await db.execute({ sql: 'DELETE FROM user_tags WHERE tag_id = ?', args: [id] })
  await db.execute({ sql: 'DELETE FROM tags WHERE id = ?', args: [id] })
  return c.json({ ok: true })
})

app.get('/api/admin/learners/:id/tags', requireManager, async (c) => {
  const caller = c.get('user')
  const db = getDb(c.env)
  const lid = c.req.param('id')
  if (caller.scopedToTeam) {
    const check = await db.execute({ sql: 'SELECT id FROM users WHERE id = ? AND team_id = ?', args: [lid, caller.scopedToTeam] })
    if (!check.rows.length) return c.json({ error: 'Not found' }, 404)
  }
  await ensureSetup(db)
  const res = await db.execute({
    sql: `SELECT t.* FROM tags t JOIN user_tags ut ON t.id = ut.tag_id WHERE ut.user_id = ? ORDER BY t.name`,
    args: [lid]
  })
  return c.json(toObjs(res))
})

app.post('/api/admin/learners/:id/tags', requireManager, async (c) => {
  const caller = c.get('user')
  const body = await c.req.json()
  const db = getDb(c.env)
  const lid = c.req.param('id')
  if (caller.scopedToTeam) {
    const check = await db.execute({ sql: 'SELECT id FROM users WHERE id = ? AND team_id = ?', args: [lid, caller.scopedToTeam] })
    if (!check.rows.length) return c.json({ error: 'Not found' }, 404)
  }
  try {
    await db.execute({ sql: 'INSERT INTO user_tags (user_id, tag_id) VALUES (?, ?)', args: [lid, body.tag_id] })
  } catch {}
  return c.json({ ok: true })
})

app.delete('/api/admin/learners/:id/tags/:tagId', requireManager, async (c) => {
  const caller = c.get('user')
  const db = getDb(c.env)
  const lid = c.req.param('id')
  if (caller.scopedToTeam) {
    const check = await db.execute({ sql: 'SELECT id FROM users WHERE id = ? AND team_id = ?', args: [lid, caller.scopedToTeam] })
    if (!check.rows.length) return c.json({ error: 'Not found' }, 404)
  }
  await db.execute({ sql: 'DELETE FROM user_tags WHERE user_id = ? AND tag_id = ?', args: [lid, c.req.param('tagId')] })
  return c.json({ ok: true })
})

export default app

