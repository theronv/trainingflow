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
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: CONSTANTS.PBKDF2_ITERATIONS }, key, 256)
  return `pbkdf2v1:${_b64(salt)}:${_b64(new Uint8Array(bits))}`
}

async function pbkdf2Verify(password, stored) {
  if (typeof stored !== 'string') return false
  const parts = stored.split(':')
  if (parts.length !== 3 || parts[0] !== 'pbkdf2v1') return false
  const salt = _unb64(parts[1])
  const key  = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: CONSTANTS.PBKDF2_ITERATIONS }, key, 256)
  const computed = _b64(new Uint8Array(bits))
  const hmacKey = await crypto.subtle.importKey('raw', ENC.encode('trainflow-cmp'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const [sigA, sigB] = await Promise.all([
    crypto.subtle.sign('HMAC', hmacKey, ENC.encode(computed)),
    crypto.subtle.sign('HMAC', hmacKey, ENC.encode(parts[2])),
  ])
  const a = new Uint8Array(sigA), b = new Uint8Array(sigB)
  return a.length === b.length && a.every((x, i) => x === b[i])
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
app.notFound(c => c.json({ error: 'Not found' }, 404))

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

async function requireAnyAuth(c, next) {
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

app.post('/api/completions', requireLearner, async (c) => {
  const body = await c.req.json().catch(() => null), user = c.get('user')
  if (!body || !body.course_id || typeof body.score !== 'number') return c.json({ error: 'Invalid data' }, 400)
  const db = getDb(c.env), existing = toObj(await db.execute({ sql: 'SELECT cert_id FROM completions WHERE learner_id = ? AND course_id = ? AND passed = 1 LIMIT 1', args: [user.id, body.course_id] }))
  const id = uid(), now = Math.floor(Date.now() / 1000), cid = (body.passed && !existing?.cert_id) ? certId() : (existing?.cert_id || null)
  const queries = [{ sql: 'INSERT INTO completions (id, course_id, learner_id, learner_name, score, passed, completed_at, cert_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', args: [id, body.course_id, user.id, user.name, Math.round(body.score), body.passed ? 1 : 0, now, cid] }]
  if (Array.isArray(body.responses)) for (const r of body.responses) if (r.question_id) queries.push({ sql: 'INSERT INTO question_responses (completion_id, question_id, is_correct) VALUES (?, ?, ?)', args: [id, r.question_id, r.is_correct ? 1 : 0] })
  await db.batch(queries, 'write')
  return c.json({ id, cert_id: cid, passed: !!body.passed, score: Math.round(body.score), completed_at: now }, 201)
})

app.get('/api/completions/me', requireLearner, async (c) => {
  const user = c.get('user'), db = getDb(c.env)
  const res = await db.execute({ sql: 'SELECT c.*, co.title AS course_title FROM completions c JOIN courses co ON c.course_id = co.id WHERE c.learner_id = ? ORDER BY c.completed_at DESC', args: [user.id] })
  return c.json(toObjs(res).map(r => ({ ...r, passed: !!r.passed })))
})

app.get('/api/admin/completions', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env), cid = c.req.query('course_id')
  let sql = 'SELECT c.*, co.title AS course_title, u.id AS user_id, u.name AS user_name FROM completions c JOIN courses co ON c.course_id = co.id JOIN users u ON c.learner_id = u.id', args = [], where = []
  if (cid) { where.push('c.course_id = ?'); args.push(cid) }
  if (user.scopedToTeam) { where.push('u.team_id = ?'); args.push(user.scopedToTeam) }
  if (where.length) sql += ' WHERE ' + where.join(' AND ')
  const res = await db.execute({ sql: sql + ' ORDER BY c.completed_at DESC', args })
  return c.json(toObjs(res).map(r => ({ ...r, passed: !!r.passed })))
})

app.get('/api/certificates/:certId', async (c) => {
  const db = getDb(c.env), res = await db.execute({ sql: 'SELECT u.name AS learner_name, co.title AS course_title, c.completed_at FROM completions c JOIN users u ON c.learner_id = u.id JOIN courses co ON c.course_id = co.id WHERE c.cert_id = ? AND c.passed = 1', args: [c.req.param('certId').toUpperCase()] })
  const r = toObj(res); return r ? c.json({ valid: true, ...r, completed_at: new Date(r.completed_at * 1000).toISOString() }) : c.json({ valid: false }, 404)
})

app.post('/api/auth/login', async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  const hash = await getStoredHash(db, c.env)
  if (!hash) return c.json({ error: 'Admin not initialised' }, 503)
  if (!body?.password || !(await pbkdf2Verify(body.password, hash))) { await new Promise(r => setTimeout(r, 400)); return c.json({ error: 'Unauthorized' }, 401) }
  const now = Math.floor(Date.now() / 1000)
  return c.json({ token: await sign({ role: 'admin', iat: now, exp: now + CONSTANTS.ADMIN_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256') })
})

app.post('/api/learners/login', async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  if (!body?.name || !body?.password) return c.json({ error: 'Missing credentials' }, 400)
  const user = toObj(await db.execute({ sql: 'SELECT * FROM users WHERE name = ?', args: [body.name.trim()] }))
  if (!user || !(await pbkdf2Verify(body.password, user.password_hash))) { await new Promise(r => setTimeout(r, 400)); return c.json({ error: 'Invalid credentials' }, 401) }
  await db.execute({ sql: 'UPDATE users SET last_login_at = ? WHERE id = ?', args: [Math.floor(Date.now() / 1000), user.id] })
  const now = Math.floor(Date.now() / 1000)
  return c.json({ token: await sign({ role: user.role, id: user.id, name: user.name, team_id: user.team_id, iat: now, exp: now + CONSTANTS.LEARNER_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256'), id: user.id, name: user.name, role: user.role, team_id: user.team_id })
})

app.get('/api/admin/teams', requireAdmin, async (c) => {
  const db = getDb(c.env), res = await db.execute("SELECT t.*, (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'learner') as learner_count, (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'manager') as manager_count FROM teams t ORDER BY t.name")
  return c.json(toObjs(res))
})

app.post('/api/admin/teams', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  if (!body?.name?.trim()) return c.json({ error: 'Name required' }, 400)
  const res = await db.execute({ sql: 'INSERT INTO teams (name) VALUES (?) RETURNING id', args: [body.name.trim()] })
  return c.json({ id: res.rows[0][0], name: body.name.trim() })
})

app.patch('/api/admin/teams/:id', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  await db.execute({ sql: 'UPDATE teams SET name = ? WHERE id = ?', args: [body.name.trim(), c.req.param('id')] })
  return c.json({ ok: true })
})

app.delete('/api/admin/teams/:id', requireAdmin, async (c) => {
  const db = getDb(c.env), id = c.req.param('id'), check = toObj(await db.execute({ sql: 'SELECT COUNT(*) as n FROM users WHERE team_id = ?', args: [id] }))
  if (check.n > 0) return c.json({ error: 'Team not empty' }, 409)
  await db.execute({ sql: 'DELETE FROM teams WHERE id = ?', args: [id] }); return c.json({ ok: true })
})

app.post('/api/auth/manager/register', async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  const invite = toObj(await db.execute({ sql: "SELECT * FROM invite_codes WHERE code = ? AND role = 'manager' AND used = 0", args: [body?.invite_code?.toUpperCase()] }))
  if (!invite || (invite.expires_at && new Date(invite.expires_at) < new Date())) return c.json({ error: 'Invalid invite' }, 400)
  const id = uid(), hash = await pbkdf2Hash(body.password), now = Math.floor(Date.now() / 1000)
  await db.batch([{ sql: 'INSERT INTO users (id, name, password_hash, role, team_id, created_at) VALUES (?, ?, ?, ?, ?, ?)', args: [id, body.name.trim(), hash, 'manager', invite.team_id, now] }, { sql: 'UPDATE invite_codes SET used = 1, used_by = ? WHERE id = ?', args: [id, invite.id] }], 'write')
  return c.json({ token: await sign({ id, name: body.name.trim(), role: 'manager', team_id: invite.team_id, iat: now, exp: now + CONSTANTS.LEARNER_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256'), id, name: body.name.trim(), role: 'manager', team_id: invite.team_id })
})

app.get('/api/admin/invites', requireAdmin, async (c) => {
  const db = getDb(c.env), res = await db.execute('SELECT i.*, t.name as team_name, u.name as used_by_name FROM invite_codes i LEFT JOIN teams t ON i.team_id = t.id LEFT JOIN users u ON i.used_by = u.id ORDER BY i.created_at DESC')
  return c.json(toObjs(res))
})

app.post('/api/admin/invites', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env), code = crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase()
  await db.execute({ sql: 'INSERT INTO invite_codes (code, team_id, expires_at) VALUES (?, ?, ?)', args: [code, body.team_id, body.expires_at || null] })
  return c.json({ code, team_id: body.team_id, expires_at: body.expires_at || null })
})

app.get('/api/learners', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env), tid = c.req.query('team_id')
  let where = ["role = 'learner'"], args = []
  if (user.scopedToTeam) { where.push('team_id = ?'); args.push(user.scopedToTeam) } else if (tid) { where.push('team_id = ?'); args.push(tid) }
  const learners = toObjs(await db.execute({ sql: `SELECT l.*, (SELECT COUNT(*) FROM completions c WHERE c.learner_id = l.id) as completion_count, (SELECT COUNT(*) FROM (SELECT a.course_id FROM assignments a WHERE a.learner_id = l.id AND a.due_at < datetime('now') UNION SELECT ta.course_id FROM tag_assignments ta JOIN learner_tags lt ON ta.tag_id = lt.tag_id WHERE lt.learner_id = l.id AND ta.due_at < datetime('now')) as all_a WHERE NOT EXISTS (SELECT 1 FROM completions comp WHERE comp.learner_id = l.id AND comp.course_id = all_a.course_id AND comp.passed = 1)) as overdue_count FROM users l WHERE ${where.join(' AND ')} ORDER BY l.name`, args }))
  const tags = toObjs(await db.execute('SELECT lt.learner_id, t.id, t.name FROM learner_tags lt JOIN tags t ON lt.tag_id = t.id')), tByL = {}
  for (const t of tags) (tByL[t.learner_id] ??= []).push(t)
  return c.json(learners.map(l => ({ ...l, tags: tByL[l.id] || [] })))
})

app.post('/api/learners', requireManager, async (c) => {
  const body = await c.req.json().catch(() => null), user = c.get('user'), db = getDb(c.env), id = uid(), hash = await pbkdf2Hash(body.password), tid = user.scopedToTeam || body.team_id || null
  await db.execute({ sql: 'INSERT INTO users (id, name, password_hash, role, team_id) VALUES (?, ?, ?, ?, ?)', args: [id, body.name.trim(), hash, 'learner', tid] })
  return c.json({ id, name: body.name.trim(), role: 'learner', team_id: tid }, 201)
})

app.get('/api/admin/stats', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env), st = user.scopedToTeam, w = st ? ' WHERE team_id = ?' : '', wa = st ? [st] : []
  const [lc, cc, cm, pr, lr, cr, mr] = await Promise.all([
    db.execute({ sql: `SELECT COUNT(*) AS n FROM users WHERE role = 'learner' ${st ? ' AND team_id = ?' : ''}`, args: wa }),
    db.execute('SELECT COUNT(*) AS n FROM courses'),
    db.execute({ sql: `SELECT COUNT(*) AS n FROM completions c JOIN users u ON c.learner_id = u.id WHERE c.completed_at >= unixepoch('now','start of month') ${st ? ' AND u.team_id = ?' : ''}`, args: wa }),
    db.execute({ sql: `SELECT COUNT(*) AS total, SUM(c.passed) AS passed FROM completions c JOIN users u ON c.learner_id = u.id ${st ? ' WHERE u.team_id = ?' : ''}`, args: wa }),
    db.execute({ sql: `SELECT l.id, l.name, l.last_login_at, COUNT(DISTINCT mp.course_id) AS courses_started, COUNT(DISTINCT c.course_id) AS courses_completed, CAST(AVG(CASE WHEN mp.score > 0 THEN mp.score END) AS INTEGER) AS avg_score FROM users l LEFT JOIN module_progress mp ON mp.learner_id = l.id LEFT JOIN completions c ON c.learner_id = l.id WHERE l.role = 'learner' ${st ? ' AND l.team_id = ?' : '' } GROUP BY l.id ORDER BY l.name`, args: wa }),
    db.execute({ sql: `SELECT co.id, co.title, COUNT(DISTINCT mp.learner_id) AS enrolled, COUNT(DISTINCT c.learner_id) AS completed, CAST(AVG(c.score) AS INTEGER) AS avg_score, CAST(100.0 * SUM(c.passed) / NULLIF(COUNT(c.id), 0) AS INTEGER) AS pass_rate FROM courses co LEFT JOIN module_progress mp ON mp.course_id = co.id LEFT JOIN completions c ON c.course_id = co.id ${st ? ' JOIN users u ON (mp.learner_id = u.id OR c.learner_id = u.id) WHERE u.team_id = ?' : ''} GROUP BY co.id ORDER BY co.title`, args: wa }),
    db.execute({ sql: `SELECT mp.learner_id, mp.passed, mp.score, mp.completed_at, co.title AS course_title, m.title AS module_title FROM module_progress mp JOIN courses co ON co.id = mp.course_id JOIN modules m ON m.id = mp.module_id JOIN users u ON mp.learner_id = u.id WHERE u.role = 'learner' ${st ? ' AND u.team_id = ?' : ''} ORDER BY co.title`, args: wa })
  ])
  const p = toObj(pr), mpL = {}; for (const r of toObjs(mr)) (mpL[r.learner_id] ??= []).push({ ...r, passed: !!r.passed })
  return c.json({ summary: { total_learners: toObj(lc).n, total_courses: toObj(cc).n, completions_this_month: toObj(cm).n, pass_rate: p.total > 0 ? Math.round(100 * p.passed / p.total) : 0 }, learners: toObjs(lr).map(l => ({ ...l, modules: mpL[l.id] || [] })), courses: toObjs(cr) })
})

app.get('/api/admin/trouble-spots', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env)
  let sql = 'SELECT q.id, q.question, co.title as course_title, m.title as module_title, COUNT(r.id) as total_attempts, SUM(CASE WHEN r.is_correct = 0 THEN 1 ELSE 0 END) as failure_count FROM questions q JOIN modules m ON q.module_id = m.id JOIN courses co ON m.course_id = co.id JOIN question_responses r ON q.id = r.question_id', args = []
  if (user.scopedToTeam) { sql += ' JOIN completions comp ON r.completion_id = comp.id JOIN users u ON comp.learner_id = u.id WHERE u.team_id = ?'; args.push(user.scopedToTeam) }
  const res = await db.execute({ sql: sql + ' GROUP BY q.id HAVING failure_count > 0 ORDER BY failure_count DESC LIMIT 10', args })
  return c.json(toObjs(res).map(r => ({ ...r, failure_rate: Math.round(r.failure_count / r.total_attempts * 100) })))
})

app.post('/api/ai/generate', requireManager, async (c) => {
  const body = await c.req.json().catch(() => null); if (!body?.type || !body?.content || !c.env.GEMINI_API_KEY) return c.json({ error: 'Missing data' }, 400)
  let prompt = ''; if (body.type === 'questions') prompt = `Write ${body.qCount || 5} multiple-choice questions for module: ${body.title}. Content: ${body.content.slice(0, 4000)}. JSON array only: [{"question":"","options":["","","",""],"correct_index":0,"explanation":""}]`
  else if (body.type === 'summary') prompt = `Summarize module: ${body.title}. Content: ${body.content.slice(0, 4000)}. JSON object: {"intro":"","bullets":[]}`
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${c.env.GEMINI_API_KEY}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { response_mime_type: 'application/json' } }) })
  const d = await res.json(), t = d.candidates?.[0]?.content?.parts?.[0]?.text; return t ? c.json(JSON.parse(t)) : c.json({ error: 'AI failed' }, 500)
})

app.get('/api/assignments/me', requireLearner, async (c) => {
  const user = c.get('user'), db = getDb(c.env)
  const res = await db.execute({ sql: "SELECT course_id, course_title, assigned_at, due_at, completed FROM (SELECT a.course_id, co.title AS course_title, a.assigned_at, a.due_at, (SELECT COUNT(*) FROM completions c WHERE c.learner_id = a.learner_id AND c.course_id = a.course_id AND c.passed = 1) > 0 AS completed FROM assignments a JOIN courses co ON a.course_id = co.id WHERE a.learner_id = ? UNION ALL SELECT ta.course_id, co.title AS course_title, datetime(ta.created_at, 'unixepoch') AS assigned_at, ta.due_at, (SELECT COUNT(*) FROM completions c WHERE c.learner_id = lt.learner_id AND c.course_id = ta.course_id AND c.passed = 1) > 0 AS completed FROM tag_assignments ta JOIN courses co ON ta.course_id = co.id JOIN learner_tags lt ON ta.tag_id = lt.tag_id WHERE lt.learner_id = ?) GROUP BY course_id", args: [user.id, user.id] })
  return c.json(toObjs(res).map(r => ({ ...r, completed: !!r.completed })))
})

app.get('/api/progress/:courseId', requireLearner, async (c) => {
  const user = c.get('user'), db = getDb(c.env)
  const res = await db.execute({ sql: 'SELECT * FROM module_progress WHERE learner_id = ? AND course_id = ?', args: [user.id, c.req.param('courseId')] })
  return c.json(toObjs(res).map(r => ({ ...r, passed: !!r.passed })))
})

app.get('/api/assignments', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env)
  let sql = 'SELECT * FROM assignments', args = []
  if (user.scopedToTeam) { sql = 'SELECT a.* FROM assignments a JOIN users u ON a.learner_id = u.id WHERE u.team_id = ?'; args.push(user.scopedToTeam) }
  return c.json(toObjs(await db.execute({ sql, args })))
})

app.post('/api/assignments', requireManager, async (c) => {
  const user = c.get('user'), body = await c.req.json().catch(() => null), db = getDb(c.env)
  if (user.scopedToTeam) { const l = toObj(await db.execute({ sql: 'SELECT team_id FROM users WHERE id = ?', args: [body.learner_id] })); if (!l || l.team_id !== user.scopedToTeam) return c.json({ error: 'Forbidden' }, 403) }
  await db.execute({ sql: "INSERT INTO assignments (course_id, learner_id, due_at, assigned_at) VALUES (?, ?, ?, strftime('%Y-%m-%d %H:%M:%S', 'now')) ON CONFLICT(course_id, learner_id) DO UPDATE SET due_at = excluded.due_at", args: [body.course_id, body.learner_id, body.due_at || null] })
  return c.json({ ok: true })
})

app.delete('/api/assignments', requireManager, async (c) => {
  const user = c.get('user'), body = await c.req.json().catch(() => null), db = getDb(c.env)
  if (user.scopedToTeam) { const l = toObj(await db.execute({ sql: 'SELECT team_id FROM users WHERE id = ?', args: [body.learner_id] })); if (!l || l.team_id !== user.scopedToTeam) return c.json({ error: 'Forbidden' }, 403) }
  await db.execute({ sql: 'DELETE FROM assignments WHERE course_id = ? AND learner_id = ?', args: [body.course_id, body.learner_id] }); return c.json({ ok: true })
})

app.get('/api/tags', requireManager, async (c) => {
  const db = getDb(c.env), res = await db.execute('SELECT * FROM tags ORDER BY name')
  return c.json(toObjs(res))
})

app.post('/api/tags', requireManager, async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env), id = uid()
  await db.execute({ sql: 'INSERT INTO tags (id, name) VALUES (?, ?)', args: [id, body.name.trim()] })
  return c.json({ id, name: body.name.trim() })
})

app.delete('/api/tags/:id', requireManager, async (c) => {
  const db = getDb(c.env); await db.execute({ sql: 'DELETE FROM tags WHERE id = ?', args: [c.req.param('id')] }); return c.json({ ok: true })
})

app.post('/api/learners/:id/tags', requireManager, async (c) => {
  const lid = c.req.param('id'), user = c.get('user'), body = await c.req.json().catch(() => null), db = getDb(c.env)
  if (user.scopedToTeam) { const l = toObj(await db.execute({ sql: 'SELECT team_id FROM users WHERE id = ?', args: [lid] })); if (!l || l.team_id !== user.scopedToTeam) return c.json({ error: 'Forbidden' }, 403) }
  await db.batch([{ sql: 'DELETE FROM learner_tags WHERE learner_id = ?', args: [lid] }, ...body.tag_ids.map(tid => ({ sql: 'INSERT INTO learner_tags (learner_id, tag_id) VALUES (?, ?)', args: [lid, tid] }))], 'write'); return c.json({ ok: true })
})

app.get('/api/tag-assignments', requireManager, async (c) => {
  const db = getDb(c.env); return c.json(toObjs(await db.execute('SELECT * FROM tag_assignments')))
})

app.post('/api/tag-assignments', requireManager, async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  await db.execute({ sql: 'INSERT INTO tag_assignments (course_id, tag_id, due_at) VALUES (?, ?, ?) ON CONFLICT(course_id, tag_id) DO UPDATE SET due_at = excluded.due_at', args: [body.course_id, body.tag_id, body.due_at || null] }); return c.json({ ok: true })
})

app.delete('/api/tag-assignments', requireManager, async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  await db.execute({ sql: 'DELETE FROM tag_assignments WHERE course_id = ? AND tag_id = ?', args: [body.course_id, body.tag_id] }); return c.json({ ok: true })
})

app.put('/api/brand', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
  await db.execute({ sql: "INSERT INTO brand (id, org_name, tagline, logo_url, primary_color, secondary_color, pass_threshold) VALUES ('default', ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET org_name=excluded.org_name, tagline=excluded.tagline, logo_url=excluded.logo_url, primary_color=excluded.primary_color, secondary_color=excluded.secondary_color, pass_threshold=excluded.pass_threshold", args: [body.org_name.trim(), body.tagline.trim(), body.logo_url, body.primary_color, body.secondary_color, Number(body.pass_threshold)] })
  return c.json(toObj(await db.execute({ sql: "SELECT * FROM brand WHERE id = 'default'" })))
})

app.put('/api/auth/password', requireAdmin, async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env), hash = await pbkdf2Hash(body.password)
  await db.execute({ sql: "INSERT INTO admin (id, password_hash) VALUES ('default', ?) ON CONFLICT(id) DO UPDATE SET password_hash=excluded.password_hash", args: [hash] }); return c.json({ updated: true })
})

export default app
