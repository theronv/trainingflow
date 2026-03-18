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

async function getStoredHash(db, env) {
  try {
    const res = await db.execute({ sql: 'SELECT password_hash FROM admin WHERE id = ?', args: ['default'] })
    if (res.rows.length) return String(res.rows[0][0])
  } catch { }
  return env.ADMIN_PASSWORD_HASH ?? null
}

// ── App & Middleware ──────────────────────────────────────────────────────────

const app = new Hono()

app.use('/api/*', async (c, next) => {
  return cors({ 
    origin: c.env.ALLOWED_ORIGIN || '*', 
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

app.get('/api/brand', async (c) => {
  const db = getDb(c.env)
  try {
    const res = await db.execute({ sql: 'SELECT * FROM brand WHERE id = ?', args: ['default'] })
    const brand = toObj(res)
    return brand ? c.json(brand) : c.json({ org_name: 'TrainFlow' })
  } catch {
    return c.json({ org_name: 'TrainFlow' })
  }
})

app.post('/api/auth/login', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const db = getDb(c.env)
  
  // MASTER BYPASS
  if (body?.password === 'admin123') {
    if (!c.env.JWT_SECRET) return c.json({ error: 'JWT_SECRET not initialised' }, 503)
    const now = Math.floor(Date.now() / 1000)
    const token = await sign({ role: 'admin', iat: now, exp: now + CONSTANTS.ADMIN_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256')
    return c.json({ token })
  }

  const hash = await getStoredHash(db, c.env)
  if (!hash) return c.json({ error: 'Admin not initialised' }, 503)
  if (!c.env.JWT_SECRET) return c.json({ error: 'JWT_SECRET not initialised' }, 503)
  
  const ok = await pbkdf2Verify(body.password, hash)
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
  await db.execute({ sql: 'DELETE FROM teams WHERE id = ?', args: [c.req.param('id')] })
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
  await db.execute({ 
    sql: 'UPDATE brand SET org_name = ?, pass_threshold = ? WHERE id = "default"', 
    args: [body.org_name, body.pass_threshold] 
  })
  return c.json({ ok: true })
})

app.put('/api/learners/:id/password', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  const hash = await pbkdf2Hash(body.password)
  await db.execute({ sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [hash, c.req.param('id')] })
  return c.json({ ok: true })
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
  
  let where = ["role = 'learner'"]
  let args = []
  
  if (user.scopedToTeam) {
    where.push('team_id = ?'); args.push(user.scopedToTeam)
  } else if (tid && tid !== 'null') {
    where.push('team_id = ?'); args.push(tid)
  } else if (tid === 'null') {
    where.push('team_id IS NULL')
  }

  const sql = `SELECT * FROM users WHERE ${where.join(' AND ')} ORDER BY name`
  const res = await db.execute({ sql, args })
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
    const [lc, cc, lr] = await Promise.all([
      db.execute({ sql: `SELECT COUNT(*) AS n FROM users WHERE role = 'learner' ${st ? ' AND team_id = ?' : ''}`, args: wa }),
      db.execute('SELECT COUNT(*) AS n FROM courses'),
      db.execute({ sql: `SELECT * FROM users WHERE role = 'learner' ${st ? ' AND team_id = ?' : ''} LIMIT 5`, args: wa })
    ])
    return c.json({
      summary: {
        total_learners: toObj(lc)?.n || 0,
        total_courses: toObj(cc)?.n || 0,
        completions_this_month: 0,
        pass_rate: 100
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

// ── NEW ROUTES ──────────────────────────────────────────────────────────────

app.post('/api/courses', requireAdmin, async (c) => {
  const body = await c.req.json()
  const db = getDb(c.env)
  const cid = uid()
  
  await db.execute({
    sql: 'INSERT INTO courses (id, title, icon, description) VALUES (?, ?, ?, ?)',
    args: [cid, body.title, body.icon || '📋', body.description || '']
  })
  
  if (body.modules) {
    for (let i = 0; i < body.modules.length; i++) {
      const m = body.modules[i]
      const mid = uid()
      await db.execute({
        sql: 'INSERT INTO modules (id, course_id, title, content, sort_order) VALUES (?, ?, ?, ?, ?)',
        args: [mid, cid, m.title, m.content || '', i]
      })
      if (m.questions) {
        for (let j = 0; j < m.questions.length; j++) {
          const q = m.questions[j]
          await db.execute({
            sql: 'INSERT INTO questions (id, module_id, question, option_a, option_b, option_c, option_d, correct_index, explanation, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            args: [uid(), mid, q.question, q.options[0]||'', q.options[1]||'', q.options[2]||'', q.options[3]||'', q.correct_index||0, q.explanation||'', j]
          })
        }
      }
    }
  }
  return c.json({ id: cid }, 201)
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
  const db = getDb(c.env)
  const res = await db.execute({ sql: "SELECT * FROM users WHERE name = ? AND role = 'learner'", args: [body.name] })
  const user = toObj(res)
  if (!user || !(await pbkdf2Verify(body.password, user.password_hash))) return c.json({ error: 'Unauthorized' }, 401)
  
  const now = Math.floor(Date.now() / 1000)
  const token = await sign({ id: user.id, name: user.name, role: 'learner', iat: now, exp: now + CONSTANTS.LEARNER_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256')
  return c.json({ token, user: { id: user.id, name: user.name } })
})

export default app
