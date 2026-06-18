/**
 * Test harness for the TrainFlow Worker.
 *
 * Drives the real Hono `app` (worker/index.js) against an in-memory libSQL
 * database. The worker's getDb() honours env.DB_CLIENT (a test-only hook), so
 * no production code path is mocked — every assertion runs the actual route
 * handlers and middleware.
 */
import { createClient } from '@libsql/client'
import { sign } from 'hono/jwt'
import { readFileSync } from 'node:fs'
import app from '../index.js'

const SCHEMA = readFileSync(new URL('../../schema.sql', import.meta.url), 'utf8')
const JWT_SECRET = 'test-secret-at-least-32-chars-long-xxxxx'

const ENC = new TextEncoder()
const b64 = (bytes) => Buffer.from(bytes).toString('base64')

/** Mirrors pbkdf2Hash() in worker/index.js (100k iters, SHA-256, 16-byte salt). */
export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const key = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, key, 256
  )
  return `pbkdf2v1:${b64(salt)}:${b64(new Uint8Array(bits))}`
}

let _ip = 0
function nextIp() { return `10.1.${Math.floor(_ip / 255) % 255}.${(_ip++) % 255}` }

/**
 * Spin up a fresh harness: in-memory DB seeded with the real schema, plus
 * helpers to mint tokens, seed rows, and issue requests against the app.
 */
export async function setupHarness({ adminPassword = 'admin-pass-123' } = {}) {
  const db = createClient({ url: ':memory:' })
  // executeMultiple parses the full script (triggers included) statement by statement.
  await db.executeMultiple(SCHEMA)

  const adminHash = await hashPassword(adminPassword)
  await db.execute({
    sql: "INSERT OR REPLACE INTO admin (id, password_hash) VALUES ('default', ?)",
    args: [adminHash],
  })

  const env = {
    DB_CLIENT: db,
    JWT_SECRET,
    ADMIN_PASSWORD_HASH: adminHash,
    ALLOWED_ORIGIN: 'http://localhost',
  }

  const now = () => Math.floor(Date.now() / 1000)
  const mint = (claims) => sign({ ...claims, iat: now(), exp: now() + 3600 }, JWT_SECRET, 'HS256')

  // ── seed helpers ────────────────────────────────────────────────────────
  let seq = 0
  const id = (p) => `${p}${(seq++).toString().padStart(6, '0')}`

  async function createTeam(name) {
    const res = await db.execute({ sql: 'INSERT INTO teams (name) VALUES (?)', args: [name] })
    return Number(res.lastInsertRowid)
  }

  async function createUser({ name, role = 'learner', team_id = null, password = 'learner-pass-1' }) {
    const uid = id('u')
    const hash = await hashPassword(password)
    await db.execute({
      sql: 'INSERT INTO users (id, name, password_hash, role, team_id) VALUES (?, ?, ?, ?, ?)',
      args: [uid, name, hash, role, team_id],
    })
    return { id: uid, name, role, team_id, password }
  }

  /** Course with one module and `answers` length questions. correct_index per answers[]. */
  async function createCourse({ title = 'Safety 101', answers = [0, 1] } = {}) {
    const cid = id('c')
    const mid = id('m')
    await db.execute({ sql: 'INSERT INTO courses (id, title) VALUES (?, ?)', args: [cid, title] })
    await db.execute({ sql: 'INSERT INTO modules (id, course_id, title, sort_order) VALUES (?, ?, ?, 0)', args: [mid, cid, 'Module 1'] })
    const qids = []
    for (let i = 0; i < answers.length; i++) {
      const qid = id('q')
      qids.push(qid)
      await db.execute({
        sql: 'INSERT INTO questions (id, module_id, question, option_a, option_b, option_c, option_d, correct_index, explanation, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        args: [qid, mid, `Q${i}`, 'A', 'B', 'C', 'D', answers[i], `Because ${i}`, i],
      })
    }
    return { id: cid, module_id: mid, question_ids: qids }
  }

  async function assign(course_id, learner_id, due_at = null) {
    await db.execute({ sql: 'INSERT INTO assignments (course_id, learner_id, due_at) VALUES (?, ?, ?)', args: [course_id, learner_id, due_at] })
  }

  // ── request helper ──────────────────────────────────────────────────────
  async function request(path, { method = 'GET', token, body, ip } = {}) {
    const headers = { 'CF-Connecting-IP': ip || nextIp() }
    const tok = await token // token helpers are async (hono/jwt sign returns a Promise)
    if (tok) headers.Authorization = `Bearer ${tok}`
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    const res = await app.request(
      path,
      { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined },
      env,
    )
    let json = null
    try { json = await res.json() } catch { /* non-JSON body */ }
    return { status: res.status, json }
  }

  return {
    db, env, request, mint, adminPassword,
    createTeam, createUser, createCourse, assign,
    adminToken: () => mint({ role: 'admin' }),
    managerToken: (u) => mint({ id: u.id, name: u.name, role: 'manager', team_id: u.team_id }),
    learnerToken: (u) => mint({ id: u.id, name: u.name, role: 'learner' }),
  }
}
