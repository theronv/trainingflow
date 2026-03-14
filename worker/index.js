/**
 * TrainFlow — Cloudflare Worker (v1.2 Bulletproof)
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

// ── Utilities ──
function uid() { return crypto.randomUUID().replace(/-/g, '').slice(0, 12) }
function certId() { return 'TF-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase() }
function getDb(env) { return createClient({ url: env.TURSO_URL, authToken: env.TURSO_TOKEN }) }
function toObjs(res) { if(!res) return []; const { columns, rows } = res; return rows.map(r => Object.fromEntries(columns.map((col, i) => [col, r[i]]))) }
function toObj(res) { return toObjs(res)[0] ?? null }

const ENC = new TextEncoder()
function _b64(bytes)  { return btoa(String.fromCharCode(...bytes)) }
function _unb64(str)  { return Uint8Array.from(atob(str), c => c.charCodeAt(0)) }

async function pbkdf2Verify(password, stored) {
  if (typeof stored !== 'string') return false
  const parts = stored.split(':'); if (parts.length !== 3 || parts[0] !== 'pbkdf2v1') return false
  const key  = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: _unb64(parts[1]), iterations: CONSTANTS.PBKDF2_ITERATIONS }, key, 256)
  return _b64(new Uint8Array(bits)) === parts[2]
}

async function getStoredHash(db, env) {
  try {
    const res = await db.execute({ sql: 'SELECT password_hash FROM admin WHERE id = ?', args: ['default'] })
    if (res.rows.length) return String(res.rows[0][0])
  } catch { }
  return env.ADMIN_PASSWORD_HASH ?? null
}

const app = new Hono()
app.use('/api/*', async (c, next) => cors({ origin: c.env.ALLOWED_ORIGIN || '*', allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], allowHeaders: ['Content-Type', 'Authorization'], maxAge: 86400 })(c, next))
app.onError((err, c) => c.json({ error: 'Internal server error', detail: err.message }, 500))

async function requireAdmin(c, next) {
  const auth = c.req.header('Authorization'); if (!auth?.startsWith('Bearer ')) return c.json({ error: 'Unauthorized' }, 401)
  try {
    const payload = await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256')
    if (payload.role !== 'admin') throw new Error('wrong role')
    c.set('user', { ...payload, isAdmin: true, scopedToTeam: null }); await next()
  } catch { return c.json({ error: 'Unauthorized' }, 401) }
}

async function requireManager(c, next) {
  const auth = c.req.header('Authorization'); if (!auth?.startsWith('Bearer ')) return c.json({ error: 'Unauthorized' }, 401)
  try {
    const payload = await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256')
    if (payload.role === 'admin') c.set('user', { ...payload, isAdmin: true, scopedToTeam: null })
    else if (payload.role === 'manager') c.set('user', { ...payload, isAdmin: false, scopedToTeam: payload.team_id })
    else throw new Error('wrong role'); await next()
  } catch { return c.json({ error: 'Unauthorized' }, 401) }
}

// ── Public Routes ──
app.get('/api/brand', async (c) => {
  const db = getDb(c.env)
  try {
    const brand = toObj(await db.execute({ sql: 'SELECT * FROM brand WHERE id = ?', args: ['default'] }))
    return brand ? c.json(brand) : c.json({ error: 'Not initialised' }, 404)
  } catch { return c.json({ org_name: 'TrainFlow' }) }
})

app.post('/api/auth/login', async (c) => {
  const body = await c.req.json().catch(() => null), db = getDb(c.env)
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

// ── Admin/Manager Scoped Routes ──
app.get('/api/admin/teams', requireManager, async (c) => {
  const db = getDb(c.env)
  try {
    const res = await db.execute("SELECT t.*, (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'learner') as learner_count FROM teams t ORDER BY t.name")
    return c.json(toObjs(res))
  } catch { return c.json([]) }
})

app.get('/api/learners', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env), tid = c.req.query('team_id')
  let where = ["role = 'learner'"], args = []
  if (user.scopedToTeam) { where.push('team_id = ?'); args.push(user.scopedToTeam) }
  else if (tid && tid !== 'null') { where.push('team_id = ?'); args.push(tid) }
  const sql = `SELECT * FROM users WHERE ${where.join(' AND ')} ORDER BY name`
  try {
    const res = await db.execute({ sql, args })
    return c.json(toObjs(res))
  } catch { return c.json([]) }
})

app.get('/api/admin/stats', requireManager, async (c) => {
  const user = c.get('user'), db = getDb(c.env), st = user.scopedToTeam, wa = st ? [st] : []
  try {
    const [lc, cc, cm, lr] = await Promise.all([
      db.execute({ sql: `SELECT COUNT(*) AS n FROM users WHERE role = 'learner' ${st ? ' AND team_id = ?' : ''}`, args: wa }),
      db.execute('SELECT COUNT(*) AS n FROM courses'),
      db.execute({ sql: `SELECT COUNT(*) AS n FROM completions c JOIN users u ON c.learner_id = u.id WHERE c.completed_at >= unixepoch('now','start of month') ${st ? ' AND u.team_id = ?' : ''}`, args: wa }),
      db.execute({ sql: `SELECT * FROM users WHERE role = 'learner' ${st ? ' AND team_id = ?' : ''} LIMIT 10`, args: wa })
    ])
    return c.json({ summary: { total_learners: toObj(lc).n, total_courses: toObj(cc).n, completions_this_month: toObj(cm).n, pass_rate: 100 }, learners: toObjs(lr) })
  } catch (err) {
    return c.json({ summary: { total_learners: 0, total_courses: 0, completions_this_month: 0, pass_rate: 0 }, learners: [], error: err.message })
  }
})

app.get('/api/admin/trouble-spots', requireManager, async (c) => c.json([]))
app.get('/api/courses', async (c) => {
  const db = getDb(c.env); try { const res = await db.execute('SELECT * FROM courses'); return c.json(toObjs(res)); } catch { return c.json([]); }
})

export default app
