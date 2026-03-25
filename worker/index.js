/**
 * TrainFlow — Cloudflare Worker (v1.5 Production Standard)
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
  return 'TF-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase()
}

function getDb(env) {
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
  if (stored === 'MOCK_HASH') return true; // Dev bypass
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

// ── App & Middleware ──────────────────────────────────────────────────────────

const app = new Hono()

app.use('/api/*', async (c, next) => {
  const origin = c.env.ALLOWED_ORIGIN || (
    c.req.header('origin')?.startsWith('http://localhost') || c.req.header('origin')?.startsWith('http://127.0.0.1')
      ? c.req.header('origin')
      : 'https://theronv.github.io'
  )
  return cors({
    origin,
    allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400
  })(c, next)
})

app.onError((err, c) => {
  console.error('API Error:', err)
  return c.json({ error: 'Internal server error', detail: err.message }, 500)
})

// ── Auth Middlewares ──

async function requireAdmin(c, next) {
  const auth = c.req.header('Authorization')
  if (!auth?.startsWith('Bearer ')) return c.json({ error: 'Unauthorized' }, 401)
  try {
    const payload = await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256')
    if (payload.role !== 'admin') throw new Error('Forbidden')
    c.set('user', { ...payload, isAdmin: true, scopedToTeam: null })
    await next()
  } catch { return c.json({ error: 'Unauthorized' }, 401) }
}

async function requireManager(c, next) {
  const auth = c.req.header('Authorization')
  if (!auth?.startsWith('Bearer ')) return c.json({ error: 'Unauthorized' }, 401)
  try {
    const payload = await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256')
    if (payload.role === 'admin') {
      c.set('user', { ...payload, isAdmin: true, scopedToTeam: null })
    } else if (payload.role === 'manager') {
      c.set('user', { ...payload, isAdmin: false, scopedToTeam: payload.team_id })
    } else {
      throw new Error('Forbidden')
    }
    await next()
  } catch { return c.json({ error: 'Unauthorized' }, 401) }
}

async function requireLearner(c, next) {
  const auth = c.req.header('Authorization')
  if (!auth?.startsWith('Bearer ')) return c.json({ error: 'Unauthorized' }, 401)
  try {
    const payload = await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256')
    c.set('user', payload)
    await next()
  } catch { return c.json({ error: 'Unauthorized' }, 401) }
}

// ── Routes: Core ──────────────────────────────────────────────────────────────

async function setupBrand(db) {
  // Nullable columns are universally safe for ALTER TABLE in SQLite/libSQL.
  // These are additive migrations — each is silently skipped if the column already exists.
  try { await db.execute("ALTER TABLE brand ADD COLUMN tagline TEXT DEFAULT 'Training & Certification Platform'") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN logo_url TEXT DEFAULT ''") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN primary_color TEXT DEFAULT '#2563eb'") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN secondary_color TEXT DEFAULT '#1d4ed8'") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN accent_color TEXT DEFAULT '#0891b2'") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN font_family TEXT DEFAULT 'Inter'") } catch {}
  try { await db.execute("ALTER TABLE brand ADD COLUMN font_url TEXT DEFAULT ''") } catch {}
}

async function setupTags(db) {
  try { await db.execute(`CREATE TABLE IF NOT EXISTS tags (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, created_at INTEGER DEFAULT (unixepoch()))`) } catch {}
  try { await db.execute(`CREATE TABLE IF NOT EXISTS user_tags (user_id TEXT NOT NULL, tag_id TEXT NOT NULL, PRIMARY KEY (user_id, tag_id))`) } catch {}
}

app.get('/api/brand', async (c) => {
  const db = getDb(c.env)
  try {
    await setupBrand(db)
    await setupTags(db)
    const res = await db.execute({ sql: 'SELECT * FROM brand WHERE id = ?', args: ['default'] })
    const brand = toObj(res)
    return brand ? c.json(brand) : c.json({ org_name: 'TrainFlow' })
  } catch {
    return c.json({ org_name: 'TrainFlow' })
  }
})

// ── Simple in-process rate limiter (resets per isolate restart; best-effort) ──
const _loginAttempts = new Map()
function _rateCheck(key) {
  const now = Date.now()
  const entry = _loginAttempts.get(key) || { count: 0, reset: now + 60_000 }
  if (now > entry.reset) { entry.count = 0; entry.reset = now + 60_000 }
  entry.count++
  _loginAttempts.set(key, entry)
  return entry.count > 10 // block after 10 attempts per minute per IP
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

app.get('/api/admin/invites', requireAdmin, async (c) => {
  const db = getDb(c.env)
  try {
    const res = await db.execute(`
      SELECT ic.*, t.name AS team_name
      FROM invite_codes ic
      LEFT JOIN teams t ON ic.team_id = t.id
      ORDER BY ic.created_at DESC
    `)
    return c.json(toObjs(res))
  } catch { return c.json([]) }
})

app.delete('/api/admin/invites/:id', requireAdmin, async (c) => {
  const db = getDb(c.env)
  await db.execute({ sql: 'DELETE FROM invite_codes WHERE id = ? AND used = 0', args: [c.req.param('id')] })
  return c.json({ ok: true })
})

app.post('/api/admin/invites', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  await db.execute({
    sql: 'INSERT INTO invite_codes (code, team_id) VALUES (?, ?)',
    args: [body.code.toUpperCase(), body.team_id]
  })
  return c.json({ ok: true }, 201)
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
  await db.execute({ sql: 'UPDATE learners SET team_id = NULL WHERE team_id = ?', args: [tid] })
  await db.execute({ sql: 'UPDATE managers SET team_id = NULL WHERE team_id = ?', args: [tid] })
  await db.execute({ sql: 'DELETE FROM teams WHERE id = ?', args: [tid] })
  return c.json({ ok: true })
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
    await setupBrand(db)
    await db.execute({
      sql: `INSERT INTO brand (id, org_name, tagline, primary_color, secondary_color, accent_color, logo_url, pass_threshold, font_family, font_url)
            VALUES ('default', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              org_name        = excluded.org_name,
              tagline         = excluded.tagline,
              primary_color   = excluded.primary_color,
              secondary_color = excluded.secondary_color,
              accent_color    = excluded.accent_color,
              logo_url        = excluded.logo_url,
              pass_threshold  = excluded.pass_threshold,
              font_family     = excluded.font_family,
              font_url        = excluded.font_url`,
      args: [body.org_name, body.tagline || '', body.primary_color || '#2563eb', body.secondary_color || '#7c3aed', body.accent_color || '#0891b2', body.logo_url || '', body.pass_threshold ?? 80, body.font_family || 'Inter', body.font_url || '']
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
  if (body.current_password) {
    const stored = await getStoredHash(db, c.env)
    if (stored && stored !== 'MOCK_HASH') {
      const ok = await pbkdf2Verify(body.current_password, stored)
      if (!ok) return c.json({ error: 'Current password is incorrect' }, 400)
    }
  }
  const hash = await pbkdf2Hash(body.new_password)
  await db.execute({ sql: 'INSERT OR REPLACE INTO admin (id, password_hash) VALUES (?, ?)', args: ['default', hash] })
  return c.json({ ok: true })
})

app.put('/api/learners/:id/password', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
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
  return c.json({ created: created.length, errors }, 201)
})

app.post('/api/learners', requireManager, async (c) => {
  const body = await c.req.json()
  if (!body.name || !body.password) return c.json({ error: 'Name and password are required' }, 400)
  if (body.password.length < 8) return c.json({ error: 'Password must be at least 8 characters' }, 400)
  const role = body.role === 'manager' ? 'manager' : 'learner'
  const db = getDb(c.env)
  const hash = await pbkdf2Hash(body.password)
  const id = uid()
  await db.execute({
    sql: 'INSERT INTO users (id, name, password_hash, role, team_id) VALUES (?, ?, ?, ?, ?)',
    args: [id, body.name, hash, role, body.team_id || null]
  })
  return c.json({ id }, 201)
})

app.get('/api/learners/:id', requireManager, async (c) => {
  const db = getDb(c.env)
  const res = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [c.req.param('id')] })
  const user = toObj(res)
  if (!user) return c.json({ error: 'Not found' }, 404)
  return c.json(user)
})

app.patch('/api/learners/:id', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  const fields = []
  const args = []
  if (body.name !== undefined)    { fields.push('name = ?');    args.push(body.name.trim()) }
  if (body.team_id !== undefined) { fields.push('team_id = ?'); args.push(body.team_id || null) }
  if (body.role !== undefined)    { fields.push('role = ?');    args.push(body.role === 'manager' ? 'manager' : 'learner') }
  if (!fields.length) return c.json({ error: 'Nothing to update' }, 400)
  args.push(c.req.param('id'))
  await db.execute({ sql: `UPDATE users SET ${fields.join(', ')} WHERE id = ?`, args })
  return c.json({ ok: true })
})

app.delete('/api/learners/:id', requireAdmin, async (c) => {
  const db = getDb(c.env)
  await db.execute({ sql: 'DELETE FROM users WHERE id = ?', args: [c.req.param('id')] })
  return c.json({ ok: true })
})

app.post('/api/auth/manager/register', async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  
  // Verify invite code
  const invRes = await db.execute({ sql: 'SELECT * FROM invite_codes WHERE code = ? AND used = 0', args: [body.code.toUpperCase()] })
  const inv = toObj(invRes)
  if (!inv) return c.json({ error: 'Invalid or expired invite code' }, 400)
  if (inv.expires_at && inv.expires_at < Math.floor(Date.now() / 1000)) {
    return c.json({ error: 'Invite code has expired' }, 400)
  }

  const hash = await pbkdf2Hash(body.password)
  const id = uid()
  
  await db.execute("BEGIN TRANSACTION")
  try {
    await db.execute({
      sql: "INSERT INTO users (id, name, password_hash, role, team_id) VALUES (?, ?, ?, 'manager', ?)",
      args: [id, body.name, hash, inv.team_id]
    })
    await db.execute({ sql: 'UPDATE invite_codes SET used = 1, used_by = ? WHERE id = ?', args: [id, inv.id] })
    await db.execute("COMMIT")
  } catch (e) {
    await db.execute("ROLLBACK")
    throw e
  }

  const now = Math.floor(Date.now() / 1000)
  const token = await sign({ id, name: body.name, role: 'manager', team_id: inv.team_id, iat: now, exp: now + CONSTANTS.ADMIN_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256')
  return c.json({ token, user: { id, name: body.name, team_id: inv.team_id } })
})

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
  const tid = c.req.query('team_id')
  const page = parseInt(c.req.query('page') || '0')
  const PAGE_SIZE = 50

  let where = ["role = 'learner'"]
  let args = []

  if (user.scopedToTeam) {
    where.push('team_id = ?'); args.push(user.scopedToTeam)
  } else if (tid && tid !== 'null') {
    where.push('team_id = ?'); args.push(tid)
  } else if (tid === 'null') {
    where.push('team_id IS NULL')
  }

  const baseWhere = `WHERE ${where.join(' AND ')}`

  if (page > 0) {
    const [countRes, rowsRes] = await Promise.all([
      db.execute({ sql: `SELECT COUNT(*) AS n FROM users ${baseWhere}`, args }),
      db.execute({ sql: `SELECT * FROM users ${baseWhere} ORDER BY name LIMIT ${PAGE_SIZE} OFFSET ${(page - 1) * PAGE_SIZE}`, args })
    ])
    const total = toObj(countRes)?.n || 0
    return c.json({ rows: toObjs(rowsRes), total, page, pages: Math.ceil(total / PAGE_SIZE) })
  }

  const res = await db.execute({ sql: `SELECT * FROM users ${baseWhere} ORDER BY name`, args })
  return c.json(toObjs(res))
})

app.get('/api/learners/me', requireLearner, async (c) => {
  const user = c.get('user')
  return c.json({ id: user.id, name: user.name })
})

app.get('/api/admin/stats', requireManager, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  const st = user.scopedToTeam
  const wa = st ? [st] : []

  try {
    const now = Math.floor(Date.now() / 1000)
    const d = new Date(); d.setDate(1); d.setHours(0, 0, 0, 0)
    const monthStart = Math.floor(d.getTime() / 1000)
    const teamFilter = st ? ' AND c.learner_id IN (SELECT id FROM users WHERE team_id = ?)' : ''
    const [lc, cc, lr, cm, pr] = await Promise.all([
      db.execute({ sql: `SELECT COUNT(*) AS n FROM users WHERE role = 'learner'${st ? ' AND team_id = ?' : ''}`, args: wa }),
      db.execute('SELECT COUNT(*) AS n FROM courses'),
      db.execute({ sql: `SELECT * FROM users WHERE role = 'learner'${st ? ' AND team_id = ?' : ''} LIMIT 5`, args: wa }),
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

app.get('/api/courses', async (c) => {
  const db = getDb(c.env)
  const res = await db.execute('SELECT * FROM courses ORDER BY created_at')
  return c.json(toObjs(res))
})

app.get('/api/courses/:id', async (c) => {
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

app.post('/api/completions', requireLearner, async (c) => {
  const user = c.get('user')
  const body = await c.req.json()
  const db = getDb(c.env)
  const rid = uid()
  const cid = certId()
  await db.execute({
    sql: "INSERT OR REPLACE INTO completions (id, learner_id, learner_name, course_id, score, passed, cert_id, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    args: [rid, user.id, user.name, body.course_id, body.score ?? 100, body.passed ? 1 : 0, cid, Math.floor(Date.now() / 1000)]
  })
  return c.json({ cert_id: cid }, 201)
})

app.get('/api/admin/completions', requireManager, async (c) => {
  const user = c.get('user')
  const db = getDb(c.env)
  const cid = c.req.query('course_id')
  
  let sql = `SELECT c.*, co.title AS course_title, u.name AS user_name 
             FROM completions c 
             JOIN courses co ON c.course_id = co.id 
             JOIN users u ON c.learner_id = u.id`
  let args = []
  let where = []
  
  if (cid) { where.push('c.course_id = ?'); args.push(cid) }
  if (user.scopedToTeam) { where.push('u.team_id = ?'); args.push(user.scopedToTeam) }
  
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
  try { await db.execute('ALTER TABLE courses ADD COLUMN section_id TEXT') } catch {}
  try { await db.execute('ALTER TABLE courses ADD COLUMN reference_url TEXT') } catch {}
  try { await db.execute('ALTER TABLE modules ADD COLUMN summary TEXT') } catch {}
  try { await db.execute('ALTER TABLE modules ADD COLUMN reference_url TEXT') } catch {}
  try { await db.execute('ALTER TABLE modules ADD COLUMN learning_objectives TEXT') } catch {}
}

app.get('/api/sections', async (c) => {
  const db = getDb(c.env)
  await setupSections(db)
  const res = await db.execute('SELECT * FROM sections ORDER BY sort_order, name')
  return c.json(toObjs(res))
})

app.post('/api/sections', requireAdmin, async (c) => {
  const body = await c.req.json()
  if (!body.name?.trim()) return c.json({ error: 'Name required' }, 400)
  const db = getDb(c.env)
  await setupSections(db)
  const id = uid()
  await db.execute({ sql: 'INSERT INTO sections (id, name, sort_order, created_at) VALUES (?, ?, ?, ?)', args: [id, body.name.trim(), body.sort_order ?? 0, Math.floor(Date.now() / 1000)] })
  return c.json({ id }, 201)
})

app.patch('/api/sections/:id', requireAdmin, async (c) => {
  const body = await c.req.json()
  if (!body.name?.trim()) return c.json({ error: 'Name required' }, 400)
  const db = getDb(c.env)
  await db.execute({ sql: 'UPDATE sections SET name = ? WHERE id = ?', args: [body.name.trim(), c.req.param('id')] })
  return c.json({ ok: true })
})

app.delete('/api/sections/:id', requireAdmin, async (c) => {
  const db = getDb(c.env)
  try { await db.execute({ sql: 'UPDATE courses SET section_id = NULL WHERE section_id = ?', args: [c.req.param('id')] }) } catch {}
  await db.execute({ sql: 'DELETE FROM sections WHERE id = ?', args: [c.req.param('id')] })
  return c.json({ ok: true })
})

app.patch('/api/courses/:id', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  await setupSections(db)
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

function buildAiPrompt(title, content, qCount, difficulty, focus) {
  return `Generate a JSON object for a training module.
Title: ${title}
Difficulty: ${difficulty}
Focus: ${focus}
Content:
${content.slice(0, 5000)}

Return ONLY valid JSON with no markdown fences or extra text:
{
  "summary": "2-3 sentence overview of this module",
  "questions": [
    {
      "question": "Question text",
      "options": ["Option A", "Option B", "Option C", "Option D"],
      "correct_index": 0,
      "explanation": "Why this answer is correct"
    }
  ]
}

Generate exactly ${qCount} questions. correct_index is 0-based.`
}

function extractJson(text) {
  const match = text.match(/\{[\s\S]*\}/)
  if (!match) throw new Error('No JSON found in AI response')
  return JSON.parse(match[0])
}

async function callClaude(title, content, qCount, difficulty, focus, apiKey) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 2048,
      messages: [{ role: 'user', content: buildAiPrompt(title, content, qCount, difficulty, focus) }]
    })
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error?.message || `Claude API error ${res.status}`)
  }
  const data = await res.json()
  return { ...extractJson(data.content[0].text), _provider: 'Claude' }
}

async function callGemini(title, content, qCount, difficulty, focus, apiKey) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: buildAiPrompt(title, content, qCount, difficulty, focus) }] }] })
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error?.message || `Gemini API error ${res.status}`)
  }
  const data = await res.json()
  return { ...extractJson(data.candidates[0].content.parts[0].text), _provider: 'Gemini' }
}

app.post('/api/ai/generate', requireAdmin, async (c) => {
  const body = await c.req.json()
  const { title, content, q_count = 5, difficulty = 'applied', focus = 'general', claude_key, gemini_key } = body
  if (!title || !content) return c.json({ error: 'title and content are required' }, 400)
  if (!claude_key && !gemini_key) return c.json({ error: 'Provide a Claude or Gemini API key' }, 400)

  let lastError = null
  if (claude_key) {
    try { return c.json(await callClaude(title, content, q_count, difficulty, focus, claude_key)) }
    catch (e) { lastError = e; console.error('Claude failed:', e.message) }
  }
  if (gemini_key) {
    try { return c.json(await callGemini(title, content, q_count, difficulty, focus, gemini_key)) }
    catch (e) { lastError = e; console.error('Gemini failed:', e.message) }
  }
  return c.json({ error: lastError?.message || 'All AI providers failed' }, 502)
})

// ── NEW ROUTES ──────────────────────────────────────────────────────────────

app.post('/api/courses', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  const cid = uid()

  await setupSections(db)

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
    await setupSections(db)

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
  const mods = await db.execute({ sql: 'SELECT id FROM modules WHERE course_id = ?', args: [cid] })
  for (const mod of mods.rows) {
    await db.execute({ sql: 'DELETE FROM questions WHERE module_id = ?', args: [mod.id] })
  }
  await db.execute({ sql: 'DELETE FROM modules WHERE course_id = ?', args: [cid] })
  await db.execute({ sql: 'DELETE FROM assignments WHERE course_id = ?', args: [cid] })
  try { await db.execute({ sql: 'DELETE FROM course_progress WHERE course_id = ?', args: [cid] }) } catch {}
  await db.execute({ sql: 'DELETE FROM completions WHERE course_id = ?', args: [cid] })
  await db.execute({ sql: 'DELETE FROM courses WHERE id = ?', args: [cid] })
  return c.json({ ok: true })
})

app.post('/api/assignments', requireManager, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  try {
    await db.execute({
      sql: 'INSERT INTO assignments (course_id, learner_id, due_at) VALUES (?, ?, ?)',
      args: [body.course_id, body.learner_id, body.due_at || null]
    })
    return c.json({ ok: true }, 201)
  } catch (e) {
    if (e.message.includes('UNIQUE')) return c.json({ error: 'Already assigned' }, 409)
    throw e
  }
})

app.delete('/api/assignments', requireManager, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
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
  const res = await db.execute({ sql: "SELECT * FROM users WHERE name = ? AND role = 'manager'", args: [body.name] })
  const user = toObj(res)
  if (!user || !(await pbkdf2Verify(body.password, user.password_hash))) return c.json({ error: 'Unauthorized' }, 401)
  
  const now = Math.floor(Date.now() / 1000)
  const token = await sign({ id: user.id, name: user.name, role: 'manager', team_id: user.team_id, iat: now, exp: now + CONSTANTS.ADMIN_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256')
  return c.json({ token, user: { id: user.id, name: user.name, team_id: user.team_id } })
})

app.post('/api/learners/login', async (c) => {
  const body = await c.req.json()
  const ip = c.req.header('CF-Connecting-IP') || 'unknown'
  if (_rateCheck(`learner:${ip}`)) return c.json({ error: 'Too many attempts. Try again in a minute.' }, 429)
  const db = getDb(c.env)
  const res = await db.execute({ sql: "SELECT * FROM users WHERE name = ? AND role = 'learner'", args: [body.name] })
  const user = toObj(res)
  if (!user || !(await pbkdf2Verify(body.password, user.password_hash))) return c.json({ error: 'Unauthorized' }, 401)
  
  const now = Math.floor(Date.now() / 1000)
  const token = await sign({ id: user.id, name: user.name, role: 'learner', iat: now, exp: now + CONSTANTS.LEARNER_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256')
  return c.json({ token, user: { id: user.id, name: user.name } })
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

app.post('/api/admin/backup/restore', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const db = getDb(c.env)
  const courses = body.courses || []
  let imported = 0, skipped = 0
  for (const course of courses) {
    const existing = toObj(await db.execute({ sql: 'SELECT id FROM courses WHERE id = ?', args: [course.id] }))
    if (existing) { skipped++; continue }
    await db.execute({
      sql: 'INSERT INTO courses (id, title, description, icon, reference_url) VALUES (?, ?, ?, ?, ?)',
      args: [course.id, course.title, course.description || '', course.icon || '📋', course.reference_url || null]
    })
    for (let mi = 0; mi < (course.modules || []).length; mi++) {
      const mod = course.modules[mi]
      await db.execute({
        sql: 'INSERT INTO modules (id, course_id, title, content, summary, reference_url, learning_objectives, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        args: [mod.id, course.id, mod.title, mod.content || '', mod.summary || '', mod.reference_url || null, mod.learning_objectives || null, mi]
      })
      for (let qi = 0; qi < (mod.questions || []).length; qi++) {
        const q = mod.questions[qi]
        const opts = q.options || []
        await db.execute({
          sql: 'INSERT INTO questions (id, module_id, question, option_a, option_b, option_c, option_d, correct_index, explanation, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          args: [q.id, mod.id, q.question, q.option_a||opts[0]||'', q.option_b||opts[1]||'', q.option_c||opts[2]||'', q.option_d||opts[3]||'', q.correct_index||0, q.explanation||'', qi]
        })
      }
    }
    imported++
  }
  return c.json({ ok: true, imported, skipped })
})

// ── Tags ─────────────────────────────────────────────────────────────────────

app.get('/api/admin/tags', requireManager, async (c) => {
  const db = getDb(c.env)
  await setupTags(db)
  const res = await db.execute('SELECT * FROM tags ORDER BY name')
  return c.json(toObjs(res))
})

app.post('/api/admin/tags', requireAdmin, async (c) => {
  const body = await c.req.json()
  if (!body.name?.trim()) return c.json({ error: 'Name required' }, 400)
  const db = getDb(c.env)
  await setupTags(db)
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
  const db = getDb(c.env)
  await setupTags(db)
  const res = await db.execute({
    sql: `SELECT t.* FROM tags t JOIN user_tags ut ON t.id = ut.tag_id WHERE ut.user_id = ? ORDER BY t.name`,
    args: [c.req.param('id')]
  })
  return c.json(toObjs(res))
})

app.post('/api/admin/learners/:id/tags', requireManager, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  try {
    await db.execute({ sql: 'INSERT INTO user_tags (user_id, tag_id) VALUES (?, ?)', args: [c.req.param('id'), body.tag_id] })
  } catch {}
  return c.json({ ok: true })
})

app.delete('/api/admin/learners/:id/tags/:tagId', requireManager, async (c) => {
  const db = getDb(c.env)
  await db.execute({ sql: 'DELETE FROM user_tags WHERE user_id = ? AND tag_id = ?', args: [c.req.param('id'), c.req.param('tagId')] })
  return c.json({ ok: true })
})

export default app
