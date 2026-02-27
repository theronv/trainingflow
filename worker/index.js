/**
 * TrainFlow — Cloudflare Worker
 *
 * Architecture:
 *   Browser  →  this Worker (holds secrets)  →  Turso (libSQL)
 *
 * The TURSO_TOKEN, JWT_SECRET, and ADMIN_PASSWORD_HASH secrets never
 * leave this Worker. The browser only ever talks to /api/* endpoints.
 *
 * Environment bindings (set via `wrangler secret put` or wrangler.toml [vars]):
 *   TURSO_URL            – libsql:// database URL            (var, not secret)
 *   ALLOWED_ORIGIN       – CORS origin, e.g. GitHub Pages URL (var, not secret)
 *   TURSO_TOKEN          – Turso auth token                  (secret)
 *   JWT_SECRET           – Signing key for admin JWTs        (secret)
 *   ADMIN_PASSWORD_HASH  – Fallback PBKDF2 hash for initial login (secret)
 */

import { Hono }           from 'hono'
import { cors }           from 'hono/cors'
import { sign, verify }   from 'hono/jwt'
import { createClient }   from '@libsql/client/web'

// ══════════════════════════════════════════════════════════════════════════════
//  UTILITIES
// ══════════════════════════════════════════════════════════════════════════════

/** Compact 12-char random ID safe for DB primary keys. */
function uid() {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12)
}

/** Certificate display ID — "TF-" + 8 uppercase hex chars. */
function certId() {
  return 'TF-' + crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase()
}

// ── Turso client ──────────────────────────────────────────────────────────────

function getDb(env) {
  return createClient({ url: env.TURSO_URL, authToken: env.TURSO_TOKEN })
}

// ── Row → plain object ────────────────────────────────────────────────────────
//
// libsql Row objects expose named columns as NON-enumerable properties, so
// Object.entries(row) yields only numeric indices.  We always go through
// ResultSet.columns for reliable key→value conversion.

function toObjs(res) {
  const { columns, rows } = res
  return rows.map(r => Object.fromEntries(columns.map((col, i) => [col, r[i]])))
}

function toObj(res) {
  return toObjs(res)[0] ?? null
}

// ══════════════════════════════════════════════════════════════════════════════
//  PBKDF2 PASSWORD HELPERS
//
//  Hash format:  "pbkdf2v1:<base64-salt-16B>:<base64-hash-32B>"
//  Algorithm:    PBKDF2-SHA-256, 100 000 iterations, 256-bit output
//  All crypto:   Web Crypto API — zero extra dependencies, no CPU cap risk.
//
//  The ADMIN_PASSWORD_HASH env secret uses the same format.
//  Generate it with:  node scripts/hash-password.mjs <password>
// ══════════════════════════════════════════════════════════════════════════════

const ENC = new TextEncoder()

function _b64(bytes)  { return btoa(String.fromCharCode(...bytes)) }
function _unb64(str)  { return Uint8Array.from(atob(str), c => c.charCodeAt(0)) }

async function pbkdf2Hash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key  = await crypto.subtle.importKey(
    'raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits']
  )
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 },
    key, 256
  )
  return `pbkdf2v1:${_b64(salt)}:${_b64(new Uint8Array(bits))}`
}

async function pbkdf2Verify(password, stored) {
  if (typeof stored !== 'string') return false
  const parts = stored.split(':')
  if (parts.length !== 3 || parts[0] !== 'pbkdf2v1') return false

  const salt = _unb64(parts[1])
  const key  = await crypto.subtle.importKey(
    'raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits']
  )
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100_000 },
    key, 256
  )
  const computed = _b64(new Uint8Array(bits))

  // Timing-safe comparison: HMAC-sign both strings with a fixed key,
  // then compare the signatures byte-by-byte.
  const hmacKey = await crypto.subtle.importKey(
    'raw', ENC.encode('trainflow-cmp'),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  const [sigA, sigB] = await Promise.all([
    crypto.subtle.sign('HMAC', hmacKey, ENC.encode(computed)),
    crypto.subtle.sign('HMAC', hmacKey, ENC.encode(parts[2])),
  ])
  const a = new Uint8Array(sigA), b = new Uint8Array(sigB)
  return a.length === b.length && a.every((x, i) => x === b[i])
}

/**
 * Return the active password hash.
 * DB row takes precedence over the env fallback so that a password change
 * via the admin UI immediately supersedes the deploy-time secret.
 */
async function getStoredHash(db, env) {
  const res = await db.execute({
    sql:  'SELECT password_hash FROM admin WHERE id = ?',
    args: ['default'],
  })
  if (res.rows.length) return String(res.rows[0][0])
  return env.ADMIN_PASSWORD_HASH ?? null
}

// ══════════════════════════════════════════════════════════════════════════════
//  COURSE BUILDER HELPER
//
//  Returns an array of InStatement objects that insert a set of modules and
//  their questions for a given courseId.  Used by both POST and PUT /api/courses
//  so the logic lives in one place.
// ══════════════════════════════════════════════════════════════════════════════

function buildModuleStmts(courseId, modules) {
  const stmts = []
  for (let mi = 0; mi < modules.length; mi++) {
    const mod   = modules[mi]
    const modId = mod.id || uid()
    stmts.push({
      sql:  'INSERT INTO modules (id, course_id, title, content, sort_order) VALUES (?, ?, ?, ?, ?)',
      args: [modId, courseId, mod.title || 'Module', mod.content || '', mi],
    })
    const questions = mod.questions || []
    for (let qi = 0; qi < questions.length; qi++) {
      const q    = questions[qi]
      const opts = q.options || q.opts || ['', '', '', '']
      stmts.push({
        sql: `INSERT INTO questions
                (id, module_id, question,
                 option_a, option_b, option_c, option_d,
                 correct_index, explanation, sort_order)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          uid(), modId,
          q.question || q.q || '',
          opts[0] || '', opts[1] || '', opts[2] || '', opts[3] || '',
          q.correct_index ?? q.correct ?? 0,
          q.explanation   || q.exp    || '',
          qi,
        ],
      })
    }
  }
  return stmts
}

// ══════════════════════════════════════════════════════════════════════════════
//  APP
// ══════════════════════════════════════════════════════════════════════════════

const app = new Hono()

// ── CORS ──────────────────────────────────────────────────────────────────────
// ALLOWED_ORIGIN should be your GitHub Pages URL in production.
// Unset → defaults to "*" (open), which is fine during local dev.

app.use('/api/*', async (c, next) =>
  cors({
    origin:         c.env.ALLOWED_ORIGIN || '*',
    allowMethods:   ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders:   ['Content-Type', 'Authorization'],
    maxAge:         86_400,
  })(c, next)
)

// ── Global error handler ──────────────────────────────────────────────────────
// All unhandled throws end up here.  Always returns JSON — never a raw 500 page.

app.onError((err, c) => {
  console.error('[trainflow]', err)
  return c.json({ error: 'Internal server error' }, 500)
})

app.notFound(c => c.json({ error: 'Not found' }, 404))

// ── Admin auth middleware ─────────────────────────────────────────────────────

async function adminAuth(c, next) {
  const auth = c.req.header('Authorization')
  if (!auth?.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401)
  }
  try {
    const payload = await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256')
    if (payload.role !== 'admin') throw new Error('wrong role')
    c.set('admin', payload)
    await next()
  } catch {
    return c.json({ error: 'Unauthorized' }, 401)
  }
}

// ── Learner auth middleware ───────────────────────────────────────────────────

async function learnerAuth(c, next) {
  const auth = c.req.header('Authorization')
  if (!auth?.startsWith('Bearer ')) {
    return c.json({ error: 'Unauthorized' }, 401)
  }
  try {
    const payload = await verify(auth.slice(7), c.env.JWT_SECRET, 'HS256')
    if (payload.role !== 'learner') throw new Error('wrong role')
    c.set('learner', { id: payload.id, name: payload.name })
    await next()
  } catch {
    return c.json({ error: 'Unauthorized' }, 401)
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// ── GET /api/brand ────────────────────────────────────────────────────────────

app.get('/api/brand', async (c) => {
  const db    = getDb(c.env)
  const brand = toObj(await db.execute({
    sql: 'SELECT * FROM brand WHERE id = ?', args: ['default'],
  }))
  if (!brand) return c.json({ error: 'Brand not initialised' }, 404)
  return c.json(brand)
})

// ── GET /api/courses ──────────────────────────────────────────────────────────
// Returns ALL courses with nested modules and questions.
// Uses 3 queries total (courses → modules → questions) assembled in JS to
// avoid N+1 without complex SQL aggregation.

app.get('/api/courses', async (c) => {
  const db         = getDb(c.env)
  const coursesRes = await db.execute('SELECT * FROM courses ORDER BY created_at')
  if (!coursesRes.rows.length) return c.json([])

  const courses   = toObjs(coursesRes)
  const courseIds = courses.map(c => c.id)
  const ph        = courseIds.map(() => '?').join(',')

  const [modsRes, qsRes] = await Promise.all([
    db.execute({
      sql:  `SELECT * FROM modules WHERE course_id IN (${ph}) ORDER BY sort_order`,
      args: courseIds,
    }),
    db.execute({
      sql:  `SELECT q.*
             FROM   questions q
             JOIN   modules   m ON q.module_id = m.id
             WHERE  m.course_id IN (${ph})
             ORDER  BY q.sort_order`,
      args: courseIds,
    }),
  ])

  const modules   = toObjs(modsRes)
  const questions = toObjs(qsRes)

  // Index questions by module_id
  const qByMod = {}
  for (const q of questions) {
    const mid = String(q.module_id);
    (qByMod[mid] ??= []).push(q)
  }

  // Index modules (with their questions) by course_id
  const mByCourse = {}
  for (const m of modules) {
    const cid = String(m.course_id);
    (mByCourse[cid] ??= []).push({ ...m, questions: qByMod[String(m.id)] || [] })
  }

  return c.json(courses.map(course => ({
    ...course,
    modules: mByCourse[String(course.id)] || [],
  })))
})

// ── GET /api/courses/:id ──────────────────────────────────────────────────────

app.get('/api/courses/:id', async (c) => {
  const id = c.req.param('id')
  const db = getDb(c.env)

  const course = toObj(await db.execute({
    sql: 'SELECT * FROM courses WHERE id = ?', args: [id],
  }))
  if (!course) return c.json({ error: 'Course not found' }, 404)

  const modules = toObjs(await db.execute({
    sql:  'SELECT * FROM modules WHERE course_id = ? ORDER BY sort_order',
    args: [id],
  }))

  if (!modules.length) return c.json({ ...course, modules: [] })

  const modIds = modules.map(m => m.id)
  const ph     = modIds.map(() => '?').join(',')
  const qsRes  = await db.execute({
    sql:  `SELECT * FROM questions WHERE module_id IN (${ph}) ORDER BY sort_order`,
    args: modIds,
  })

  const qByMod = {}
  for (const q of toObjs(qsRes)) {
    const mid = String(q.module_id);
    (qByMod[mid] ??= []).push(q)
  }

  return c.json({
    ...course,
    modules: modules.map(m => ({ ...m, questions: qByMod[String(m.id)] || [] })),
  })
})

// ── POST /api/completions ─────────────────────────────────────────────────────
// Requires learner JWT — learner identity comes from the token, not the body.

app.post('/api/completions', learnerAuth, async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body) return c.json({ error: 'Invalid JSON' }, 400)

  const { course_id, score, passed } = body
  const learner = c.get('learner')

  if (!course_id) return c.json({ error: 'course_id is required' }, 400)
  if (typeof score !== 'number' || score < 0 || score > 100) {
    return c.json({ error: 'score must be a number between 0 and 100' }, 400)
  }

  const db  = getDb(c.env)
  const id  = uid()
  const cid = certId()

  await db.execute({
    sql:  `INSERT INTO completions
             (id, course_id, learner_name, learner_id, score, passed, cert_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
    args: [id, course_id, learner.name, learner.id, Math.round(score), passed ? 1 : 0, cid],
  })

  return c.json({ id, cert_id: cid }, 201)
})

// ── GET /api/completions/me ───────────────────────────────────────────────────
// Learner sees only their own records.

app.get('/api/completions/me', learnerAuth, async (c) => {
  const learner = c.get('learner')
  const db      = getDb(c.env)
  const res     = await db.execute({
    sql:  'SELECT * FROM completions WHERE learner_id = ? ORDER BY completed_at DESC',
    args: [learner.id],
  })
  return c.json(toObjs(res).map(r => ({ ...r, passed: Boolean(r.passed) })))
})

// ── GET /api/completions/learner/:name ────────────────────────────────────────
// Admin lookup by name.

app.get('/api/completions/learner/:name', adminAuth, async (c) => {
  const name = decodeURIComponent(c.req.param('name'))
  const db   = getDb(c.env)

  const res = await db.execute({
    sql:  'SELECT * FROM completions WHERE learner_name = ? ORDER BY completed_at DESC',
    args: [name],
  })

  return c.json(toObjs(res).map(r => ({ ...r, passed: Boolean(r.passed) })))
})

// ── GET /api/completions/cert/:certId ────────────────────────────────────────
// Public certificate verification endpoint.
// Returns the completion record that matches the cert_id, or 404 if not found.

app.get('/api/completions/cert/:certId', async (c) => {
  const certId = c.req.param('certId').toUpperCase()
  const db     = getDb(c.env)

  const res    = await db.execute({
    sql:  'SELECT * FROM completions WHERE cert_id = ?',
    args: [certId],
  })
  const record = toObj(res)
  if (!record) return c.json({ error: 'Certificate not found' }, 404)

  return c.json({ ...record, passed: Boolean(record.passed) })
})

// ── POST /api/auth/login ──────────────────────────────────────────────────────

app.post('/api/auth/login', async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body?.password) return c.json({ error: 'password is required' }, 400)

  const db     = getDb(c.env)
  const stored = await getStoredHash(db, c.env)

  if (!stored) {
    return c.json({
      error: 'Admin account not initialised — set ADMIN_PASSWORD_HASH in Worker secrets',
    }, 503)
  }

  const ok = await pbkdf2Verify(body.password, stored)
  if (!ok) {
    // Deliberate 400 ms pause to blunt brute-force attempts.
    await new Promise(r => setTimeout(r, 400))
    return c.json({ error: 'Incorrect password' }, 401)
  }

  const now   = Math.floor(Date.now() / 1000)
  const token = await sign(
    { role: 'admin', iat: now, exp: now + 8 * 3600 },
    c.env.JWT_SECRET,
    'HS256'
  )
  return c.json({ token })
})

// ══════════════════════════════════════════════════════════════════════════════
//  LEARNER AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════════

// ── POST /api/learners/login ──────────────────────────────────────────────────

app.post('/api/learners/login', async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body?.name?.trim() || !body?.password) {
    return c.json({ error: 'name and password are required' }, 400)
  }

  const db  = getDb(c.env)
  const res = await db.execute({
    sql:  'SELECT * FROM learners WHERE name = ?',
    args: [body.name.trim()],
  })
  const learner = toObj(res)

  // Use the same delay whether name not found or password wrong — prevents enumeration.
  if (!learner || !(await pbkdf2Verify(body.password, String(learner.password_hash)))) {
    await new Promise(r => setTimeout(r, 400))
    return c.json({ error: 'Invalid name or password' }, 401)
  }

  await db.execute({
    sql:  'UPDATE learners SET last_login_at = ? WHERE id = ?',
    args: [Math.floor(Date.now() / 1000), learner.id],
  })

  const now   = Math.floor(Date.now() / 1000)
  const token = await sign(
    { role: 'learner', id: learner.id, name: learner.name, iat: now, exp: now + 24 * 3600 },
    c.env.JWT_SECRET,
    'HS256'
  )
  return c.json({ token, id: learner.id, name: learner.name })
})

// ── GET /api/learners/me ──────────────────────────────────────────────────────

app.get('/api/learners/me', learnerAuth, async (c) => {
  const learner = c.get('learner')
  return c.json({ id: learner.id, name: learner.name })
})

// ── PUT /api/learners/me/password ─────────────────────────────────────────────

app.put('/api/learners/me/password', learnerAuth, async (c) => {
  const learner = c.get('learner')
  const body    = await c.req.json().catch(() => null)

  if (!body?.current_password) return c.json({ error: 'current_password is required' }, 400)
  if (!body?.new_password || body.new_password.length < 8) {
    return c.json({ error: 'new_password must be at least 8 characters' }, 400)
  }

  const db  = getDb(c.env)
  const row = toObj(await db.execute({
    sql: 'SELECT password_hash FROM learners WHERE id = ?', args: [learner.id],
  }))
  if (!row) return c.json({ error: 'Learner not found' }, 404)

  const ok = await pbkdf2Verify(body.current_password, String(row.password_hash))
  if (!ok) {
    await new Promise(r => setTimeout(r, 400))
    return c.json({ error: 'Current password is incorrect' }, 401)
  }

  await db.execute({
    sql:  'UPDATE learners SET password_hash = ? WHERE id = ?',
    args: [await pbkdf2Hash(body.new_password), learner.id],
  })
  return c.json({ updated: true })
})

// ══════════════════════════════════════════════════════════════════════════════
//  ADMIN ROUTES  — Bearer JWT required on every route below
// ══════════════════════════════════════════════════════════════════════════════

// ── POST /api/courses ─────────────────────────────────────────────────────────

app.post('/api/courses', adminAuth, async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body?.title?.trim()) return c.json({ error: 'title is required' }, 400)

  const db       = getDb(c.env)
  const courseId = uid()

  await db.batch([
    {
      sql:  'INSERT INTO courses (id, icon, title, description) VALUES (?, ?, ?, ?)',
      args: [courseId, body.icon || '📋', body.title.trim(), body.description || ''],
    },
    ...buildModuleStmts(courseId, body.modules || []),
  ], 'write')

  return c.json({ id: courseId }, 201)
})

// ── PUT /api/courses/:id ──────────────────────────────────────────────────────
// Full replace strategy: delete existing modules (questions cascade via FK)
// then re-insert.  Simpler and safer than diffing.

app.put('/api/courses/:id', adminAuth, async (c) => {
  const id   = c.req.param('id')
  const body = await c.req.json().catch(() => null)
  if (!body?.title?.trim()) return c.json({ error: 'title is required' }, 400)

  const db       = getDb(c.env)
  const existing = toObj(await db.execute({
    sql: 'SELECT id FROM courses WHERE id = ?', args: [id],
  }))
  if (!existing) return c.json({ error: 'Course not found' }, 404)

  await db.batch([
    {
      sql:  'UPDATE courses SET icon = ?, title = ?, description = ? WHERE id = ?',
      args: [body.icon || '📋', body.title.trim(), body.description || '', id],
    },
    { sql: 'DELETE FROM modules WHERE course_id = ?', args: [id] },
    ...buildModuleStmts(id, body.modules || []),
  ], 'write')

  return c.json({ id })
})

// ── DELETE /api/courses/:id ───────────────────────────────────────────────────

app.delete('/api/courses/:id', adminAuth, async (c) => {
  const id       = c.req.param('id')
  const db       = getDb(c.env)
  const existing = toObj(await db.execute({
    sql: 'SELECT id FROM courses WHERE id = ?', args: [id],
  }))
  if (!existing) return c.json({ error: 'Course not found' }, 404)

  // FK CASCADE removes modules and questions automatically.
  await db.execute({ sql: 'DELETE FROM courses WHERE id = ?', args: [id] })
  return c.json({ deleted: id })
})

// ── GET /api/completions ──────────────────────────────────────────────────────
// Paginated admin view.  Query params: limit (max 500, default 200), offset.

app.get('/api/completions', adminAuth, async (c) => {
  const limit  = Math.min(Math.max(Number(c.req.query('limit')  || 200), 1), 500)
  const offset = Math.max(Number(c.req.query('offset') || 0), 0)
  const db     = getDb(c.env)

  const [dataRes, countRes] = await Promise.all([
    db.execute({
      sql:  'SELECT * FROM completions ORDER BY completed_at DESC LIMIT ? OFFSET ?',
      args: [limit, offset],
    }),
    db.execute('SELECT COUNT(*) AS total FROM completions'),
  ])

  return c.json({
    total:  Number(toObj(countRes).total),
    limit,
    offset,
    rows:   toObjs(dataRes).map(r => ({ ...r, passed: Boolean(r.passed) })),
  })
})

// ── DELETE /api/completions ───────────────────────────────────────────────────

app.delete('/api/completions', adminAuth, async (c) => {
  const db      = getDb(c.env)
  const before  = toObj(await db.execute('SELECT COUNT(*) AS total FROM completions'))
  await db.execute('DELETE FROM completions')
  return c.json({ deleted: Number(before.total) })
})

// ── PUT /api/brand ────────────────────────────────────────────────────────────

app.put('/api/brand', adminAuth, async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body) return c.json({ error: 'Invalid JSON' }, 400)

  const {
    org_name, tagline, logo_url,
    primary_color, secondary_color, pass_threshold,
  } = body

  const db = getDb(c.env)
  await db.execute({
    sql: `INSERT INTO brand
            (id, org_name, tagline, logo_url, primary_color, secondary_color, pass_threshold)
          VALUES ('default', ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            org_name        = excluded.org_name,
            tagline         = excluded.tagline,
            logo_url        = excluded.logo_url,
            primary_color   = excluded.primary_color,
            secondary_color = excluded.secondary_color,
            pass_threshold  = excluded.pass_threshold`,
    args: [
      (org_name || 'TrainFlow').trim(),
      (tagline  || 'Training & Certification Platform').trim(),
      logo_url        || '',
      primary_color   || '#2563eb',
      secondary_color || '#1d4ed8',
      Number(pass_threshold) || 80,
    ],
  })

  // Return the saved row so the frontend can sync state immediately.
  const updated = toObj(await db.execute({
    sql: 'SELECT * FROM brand WHERE id = ?', args: ['default'],
  }))
  return c.json(updated)
})

// ── PUT /api/auth/password ────────────────────────────────────────────────────
// Writes a new PBKDF2 hash to the admin table.  From this point on the DB
// value overrides the ADMIN_PASSWORD_HASH env secret for all future logins.

app.put('/api/auth/password', adminAuth, async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body?.password) return c.json({ error: 'password is required' }, 400)
  if (typeof body.password !== 'string' || body.password.length < 8) {
    return c.json({ error: 'Password must be at least 8 characters' }, 400)
  }

  const hash = await pbkdf2Hash(body.password)
  const db   = getDb(c.env)

  await db.execute({
    sql: `INSERT INTO admin (id, password_hash) VALUES ('default', ?)
          ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash`,
    args: [hash],
  })

  return c.json({ updated: true })
})

// ── GET /api/learners ─────────────────────────────────────────────────────────

app.get('/api/learners', adminAuth, async (c) => {
  const db  = getDb(c.env)
  const res = await db.execute(`
    SELECT l.id, l.name, l.last_login_at, l.created_at,
           COUNT(c.id) AS completion_count
    FROM   learners l
    LEFT   JOIN completions c ON c.learner_id = l.id
    GROUP  BY l.id
    ORDER  BY l.name
  `)
  return c.json(toObjs(res))
})

// ── POST /api/learners ────────────────────────────────────────────────────────

app.post('/api/learners', adminAuth, async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body?.name?.trim()) return c.json({ error: 'name is required' }, 400)
  if (!body?.password || body.password.length < 8) {
    return c.json({ error: 'password must be at least 8 characters' }, 400)
  }

  const db   = getDb(c.env)
  const id   = uid()
  const hash = await pbkdf2Hash(body.password)

  try {
    await db.execute({
      sql:  'INSERT INTO learners (id, name, password_hash) VALUES (?, ?, ?)',
      args: [id, body.name.trim(), hash],
    })
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) {
      return c.json({ error: 'A learner with that name already exists' }, 409)
    }
    throw e
  }

  return c.json({ id, name: body.name.trim() }, 201)
})

// ── DELETE /api/learners/:id ──────────────────────────────────────────────────

app.delete('/api/learners/:id', adminAuth, async (c) => {
  const id       = c.req.param('id')
  const db       = getDb(c.env)
  const existing = toObj(await db.execute({
    sql: 'SELECT id FROM learners WHERE id = ?', args: [id],
  }))
  if (!existing) return c.json({ error: 'Learner not found' }, 404)

  // FK ON DELETE CASCADE removes their completions automatically.
  await db.execute({ sql: 'DELETE FROM learners WHERE id = ?', args: [id] })
  return c.json({ deleted: id })
})

// ── PUT /api/learners/:id/password ────────────────────────────────────────────

app.put('/api/learners/:id/password', adminAuth, async (c) => {
  const id   = c.req.param('id')
  const body = await c.req.json().catch(() => null)
  if (!body?.password || body.password.length < 8) {
    return c.json({ error: 'password must be at least 8 characters' }, 400)
  }

  const db       = getDb(c.env)
  const existing = toObj(await db.execute({
    sql: 'SELECT id FROM learners WHERE id = ?', args: [id],
  }))
  if (!existing) return c.json({ error: 'Learner not found' }, 404)

  await db.execute({
    sql:  'UPDATE learners SET password_hash = ? WHERE id = ?',
    args: [await pbkdf2Hash(body.password), id],
  })
  return c.json({ updated: true })
})

// ── Export ────────────────────────────────────────────────────────────────────
export default app
