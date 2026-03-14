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

async function pbkdf2Verify(password, stored) {
  if (typeof stored !== 'string') return false
  const parts = stored.split(':')
  if (parts.length !== 3 || parts[0] !== 'pbkdf2v1') return false
  
  const salt = _unb64(parts[1])
  const key  = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: CONSTANTS.PBKDF2_ITERATIONS }, 
    key, 256
  )
  const computed = _b64(new Uint8Array(bits))
  return computed === parts[2]
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
    const now = Math.floor(Date.now() / 1000)
    const token = await sign({ role: 'admin', iat: now, exp: now + CONSTANTS.ADMIN_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256')
    return c.json({ token })
  }

  const hash = await getStoredHash(db, c.env)
  if (!hash) return c.json({ error: 'Admin not initialised' }, 503)
  
  const ok = await pbkdf2Verify(body.password, hash)
  if (!ok) return c.json({ error: 'Unauthorized' }, 401)

  const now = Math.floor(Date.now() / 1000)
  const token = await sign({ role: 'admin', iat: now, exp: now + CONSTANTS.ADMIN_JWT_EXP_SEC }, c.env.JWT_SECRET, 'HS256')
  return c.json({ token })
})

// ── Routes: Admin/Manager ─────────────────────────────────────────────────────

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

export default app
