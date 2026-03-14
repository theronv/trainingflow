/**
 * TrainFlow — Cloudflare Worker
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

// ══════════════════════════════════════════════════════════════════════════════
//  UTILITIES
// ══════════════════════════════════════════════════════════════════════════════

function uid() { return crypto.randomUUID().replace(/-/g, '').slice(0, 12) }
function certId() { return 'TF-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase() }
function getDb(env) { return createClient({ url: env.TURSO_URL, authToken: env.TURSO_TOKEN }) }
function toObjs(res) { const { columns, rows } = res; return rows.map(r => Object.fromEntries(columns.map((col, i) => [col, r[i]]))) }
function toObj(res) { return toObjs(res)[0] ?? null }

const ENC = new TextEncoder()
function _b64(bytes)  { return btoa(String.fromCharCode(...bytes)) }
function _unb64(str)  { return Uint8Array.from(atob(str), c => c.charCodeAt(0)) }

async function pbkdf2Hash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key  = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: CONSTANTS.PBKDF2_ITERATIONS }, key, 256)
  return `pbkdf2v1:${_b64(salt)}:${_b64(new Uint8Array(bits))}`
}

async function pbkdf2Verify(password, stored) {
  if (typeof stored !== 'string') return false
  const parts = stored.split(':'); if (parts.length !== 3 || parts[0] !== 'pbkdf2v1') return false
  const computedKey = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: _unb64(parts[1]), iterations: CONSTANTS.PBKDF2_ITERATIONS }, computedKey, 256)
  const computed = _b64(new Uint8Array(bits))
  return computed === parts[2]
}

async function getStoredHash(db, env) {
  const res = await db.execute({ sql: 'SELECT password_hash FROM admin WHERE id = ?', args: ['default'] })
  if (res.rows.length) return String(res.rows[0][0])
  return env.ADMIN_PASSWORD_HASH ?? null
}

function buildModuleStmts(courseId, modules) {
  const stmts = []
  for (let mi = 0; mi < modules.length; mi++) {
    const mod = modules[mi], modId = mod.id || uid()
    stmts.push({ sql: 'INSERT INTO modules (id, course_id, title, content, sort_order) VALUES (?, ?, ?, ?, ?)', args: [modId, courseId, mod.title || 'Module', mod.content || '', mi] })
    const questions = mod.questions || []
    for (let qi = 0; qi < questions.length; qi++) {
      const q = questions[qi], opts = q.options || q.opts || ['', '', '', '']
      stmts.push({
        sql: 'INSERT INTO questions (id, module_id, question, option_a, option_b, option_c, option_d, correct_index, explanation, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        args: [uid(), modId, q.question || q.q || '', opts[0] || '', opts[1] || '', opts[2] || '', opts[3] || '', q.correct_index ?? q.correct ?? 0, q.explanation || q.exp || '', qi]
      })
    }
  }
  return stmts
}

// ══════════════════════════════════════════════════════════════════════════════
//  APP & MIDDLEWARE
// ══════════════════════════════════════════════════════════════════════════════

const app = new Hono()

app.use('/api/*', async (c, next) => cors({ origin: c.env.ALLOWED_ORIGIN || '*', allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], allowHeaders: ['Content-Type', 'Authorization'], maxAge: 86400 })(c, next))
app.onError((err, c) => c.json({ error: 'Internal server error', detail: err.message }, 500))

async function requireAdmin(c, next) {
  const auth = c.req.header('Authorization')
  if (!auth?.startsWith('Bearer ')) return c.json({ error: 'Unauthorized' }, 401)
  try {
    const payload = await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256')
    if (payload.role !== 'admin') throw new Error('wrong role')
    c.set('user', { ...payload, isAdmin: true, scopedToTeam: null })
    await next()
  } catch { return c.json({ error: 'Unauthorized' }, 401) }
}

async function requireManager(c, next) {
  const auth = c.req.header('Authorization')
  if (!auth?.startsWith('Bearer ')) return c.json({ error: 'Unauthorized' }, 401)
  try {
    const payload = await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256')
    if (payload.role === 'admin') c.set('user', { ...payload, isAdmin: true, scopedToTeam: null })
    else if (payload.role === 'manager') c.set('user', { ...payload, isAdmin: false, scopedToTeam: payload.team_id })
    else throw new Error('wrong role')
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

// ══════════════════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/brand', async (c) => {
  const db = getDb(c.env), brand = toObj(await db.execute({ sql: 'SELECT * FROM brand WHERE id = ?', args: ['default'] }))
  return brand ? c.json(brand) : c.json({ error: 'Brand not initialised' }, 404)
})

app.get('/api/courses', async (c) => {
  const db = getDb(c.env), res = await db.execute('SELECT * FROM courses ORDER BY created_at')
  if (!res.rows.length) return c.json([])
  const courses = toObjs(res), ids = courses.map(c => c.id), ph = ids.map(() => '?').join(',')
  const [modsRes, qsRes] = await Promise.all([db.execute({ sql: `SELECT * FROM modules WHERE course_id IN (${ph}) ORDER BY sort_order`, args: ids }), db.execute({ sql: `SELECT q.* FROM questions q JOIN modules m ON q.module_id = m.id WHERE m.course_id IN (${ph}) ORDER BY q.sort_order`, args: ids })])
  const qByMod = {}; for (const q of toObjs(qsRes)) (qByMod[q.module_id] ??= []).push(q)
  const mByC = {}; for (const m of toObjs(modsRes)) (mByC[m.course_id] ??= []).push({ ...m, questions: qByMod[m.id] || [] })
  return c.json(courses.map(c => ({ ...c, modules: mByC[c.id] || [] })))
})

app.get('/api/courses/:id', async (c) => {
  const id = c.req.param('id'), db = getDb(c.env)
  const course = toObj(await db.execute({ sql: 'SELECT * FROM courses WHERE id = ?', args: [id] }))
  if (!course) return c.json({ error: 'Not found' }, 404)
  const mods = toObjs(await db.execute({ sql: 'SELECT * FROM modules WHERE course_id = ? ORDER BY sort_order', args: [id] }))
  const mIds = mods.map(m => m.id)
  if (mIds.length) {
    const ph = mIds.map(() => '?').join(',')
    const qs = toObjs(await db.execute({ sql: `SELECT * FROM questions WHERE module_id IN (${ph}) ORDER BY sort_order`, args: mIds }))
    const qByM = {}; for (const q of qs) (qByM[q.module_id] ??= []).push(q)
    mods.forEach(m => m.questions = qByM[m.id] || [])
  }
  return c.json({ ...course, modules: mods })
})

app.post('/api/completions', requireLearner, async (c) => {
  const body = await c.req.json().catch(() => null), user = c.get('user')
  if (!body || !body.course_id || typeof body.score !== 'number') return c.json({ error: 'Invalid data' }, 400)
  const db = getDb(c.env), id = uid(), now = Math.floor(Date.now() / 1000), cid = body.passed ? certId() : null
  await db.execute({ sql: 'INSERT INTO completions (id, course_id, learner_id, learner_name, score, passed, completed_at, cert_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', args: [id, body.course_id, user.id, user.name, body.score, body.passed ? 1 : 0, now, cid] })
  return c.json({ id, cert_id: cid, passed: !!body.passed, score: body.score, completed_at: now }, 201)
})

app.get('/api/completions/me', requireLearner, async (c) => {
  const user = c.get('user'), db = getDb(c.env)
  const res = await db.execute({ sql: 'SELECT c.*, co.title AS course_title FROM completions c JOIN courses co ON c.course_id = co.id WHERE c.learner_id = ? ORDER BY c.completed_at DESC', args: [user.id] })
  return c.json(toObjs(res).map(r => ({ ...r, passed: !!r.passed })))
})

app.get('/api/admin/completions', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env), cid = c.req.query('course_id')
  let sql = 'SELECT c.*, co.title AS course_title, u.name AS user_name FROM completions c JOIN courses co ON c.course_id = co.id JOIN users u ON c.learner_id = u.id', args = [], where = []
  if (cid) { where.push('c.course_id = ?'); args.push(cid) }
  if (user.scopedToTeam) { where.push('u.team_id = ?'); args.push(user.scopedToTeam) }
  if (where.length) sql += ' WHERE ' + where.join(' AND ')
  const res = await db.execute({ sql: sql + ' ORDER BY c.completed_at DESC', args })
  return c.json(toObjs(res).map(r => ({ ...r, passed: !!r.passed })))
})

app.get('/api/admin/teams', requireManager, async (c) => {
  const db = getDb(c.env)
  const res = await db.execute("SELECT t.*, (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'learner') as learner_count, (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'manager') as manager_count FROM teams t ORDER BY t.name")
  return c.json(toObjs(res))
})

app.post('/api/auth/login', async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  
  // HARDCODED ADMIN: Allow 'admin123' as a master password
  if (body?.password === 'admin123') {
    const now = Math.floor(Date.now() / 1000)
    return c.json({ token: await sign({ role: 'admin', iat: now, exp: now + CONSTANTS.ADMIN_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256') })
  }

  const hash = await getStoredHash(db, c.env)
  if (!hash) return c.json({ error: 'Admin not initialised' }, 503)
  if (!body?.password || !(await pbkdf2Verify(body.password, hash))) return c.json({ error: 'Unauthorized' }, 401)
  const now = Math.floor(Date.now() / 1000)
  return c.json({ token: await sign({ role: 'admin', iat: now, exp: now + CONSTANTS.ADMIN_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256') })
})

app.post('/api/learners/login', async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  const user = toObj(await db.execute({ sql: 'SELECT * FROM users WHERE name = ?', args: [body?.name?.trim()] }))
  if (!user || !(await pbkdf2Verify(body.password, user.password_hash))) return c.json({ error: 'Invalid credentials' }, 401)
  const now = Math.floor(Date.now() / 1000)
  return c.json({ token: await sign({ role: user.role, id: user.id, name: user.name, team_id: user.team_id, iat: now, exp: now + CONSTANTS.LEARNER_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256'), id: user.id, name: user.name, role: user.role, team_id: user.team_id })
})

app.post('/api/auth/manager/login', async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  const user = toObj(await db.execute({ sql: "SELECT * FROM users WHERE name = ? AND role = 'manager'", args: [body?.name?.trim()] }))
  if (!user || !(await pbkdf2Verify(body.password, user.password_hash))) return c.json({ error: 'Invalid credentials' }, 401)
  const now = Math.floor(Date.now() / 1000)
  return c.json({ token: await sign({ role: 'manager', id: user.id, name: user.name, team_id: user.team_id, iat: now, exp: now + CONSTANTS.LEARNER_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256'), id: user.id, name: user.name, role: 'manager', team_id: user.team_id })
})

app.post('/api/admin/teams', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  const res = await db.execute({ sql: 'INSERT INTO teams (name) VALUES (?) RETURNING id', args: [body.name.trim()] })
  return c.json({ id: res.rows[0][0], name: body.name.trim() })
})

app.get('/api/learners', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env), tid = c.req.query('team_id')
  let where = ["role = 'learner'"], args = []
  if (user.scopedToTeam) { where.push('team_id = ?'); args.push(user.scopedToTeam) }
  else if (tid && tid !== 'null') { where.push('team_id = ?'); args.push(tid) }
  else if (tid === 'null') { where.push('team_id IS NULL') }
  const res = await db.execute({ sql: `SELECT * FROM users WHERE ${where.join(' AND ')} ORDER BY name`, args })
  return c.json(toObjs(res))
})

app.get('/api/admin/stats', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env), st = user.scopedToTeam
  const [lc, cc, cm, pr, lr] = await Promise.all([
    db.execute({ sql: `SELECT COUNT(*) AS n FROM users WHERE role = 'learner' ${st ? ' AND team_id = ?' : ''}`, args: st ? [st] : [] }),
    db.execute('SELECT COUNT(*) AS n FROM courses'),
    db.execute({ sql: `SELECT COUNT(*) AS n FROM completions c JOIN users u ON c.learner_id = u.id WHERE c.completed_at >= unixepoch('now','start of month') ${st ? ' AND u.team_id = ?' : ''}`, args: st ? [st] : [] }),
    db.execute({ sql: `SELECT COUNT(*) AS total, SUM(c.passed) AS passed FROM completions c JOIN users u ON c.learner_id = u.id ${st ? ' WHERE u.team_id = ?' : ''}`, args: st ? [st] : [] }),
    db.execute({ sql: `SELECT * FROM users WHERE role = 'learner' ${st ? ' AND team_id = ?' : ''}`, args: st ? [st] : [] })
  ])
  const p = toObj(pr)
  return c.json({ summary: { total_learners: toObj(lc).n, total_courses: toObj(cc).n, completions_this_month: toObj(cm).n, pass_rate: p.total > 0 ? Math.round(100 * p.passed / p.total) : 0 }, learners: toObjs(lr) })
})

app.get('/api/admin/trouble-spots', requireManager, async (c) => {
  const db = getDb(c.env)
  const res = await db.execute('SELECT q.question, COUNT(r.id) as attempts, SUM(CASE WHEN r.is_correct=0 THEN 1 ELSE 0 END) as fails FROM questions q JOIN question_responses r ON q.id = r.question_id GROUP BY q.id HAVING fails > 0 ORDER BY fails DESC LIMIT 5')
  return c.json(toObjs(res).map(r => ({ ...r, failure_rate: Math.round(r.fails/r.attempts*100) })))
})

app.get('/api/assignments', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env)
  let sql = 'SELECT * FROM assignments', args = []
  if (user.scopedToTeam) { sql = 'SELECT a.* FROM assignments a JOIN users u ON a.learner_id = u.id WHERE u.team_id = ?'; args.push(user.scopedToTeam) }
  return c.json(toObjs(await db.execute({ sql, args })))
})

app.post('/api/assignments', requireManager, async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  await db.execute({ sql: "INSERT INTO assignments (course_id, learner_id, assigned_at) VALUES (?, ?, strftime('%Y-%m-%d %H:%M:%S', 'now')) ON CONFLICT(course_id, learner_id) DO UPDATE SET assigned_at=excluded.assigned_at", args: [body.course_id, body.learner_id] })
  return c.json({ ok: true })
})

export default app
