import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

/**
 * Scoring & answer-key integrity (audit findings F1/F2).
 *
 * These tests document the CURRENT behaviour and act as tripwires for the fix.
 * The `it.fails(...)` cases assert the *secure* behaviour we want: while the
 * gap is open they pass (the assertion fails as expected); once F1/F2 is fixed
 * the assertion will pass and vitest will flag the `it.fails` case as failing —
 * that's the signal to delete the `.fails` marker and lock in the fix.
 *
 * See docs + CLAUDE.md "Security Status" for the fix direction.
 */
describe('F1 — answer key exposure via GET /api/courses/:id', () => {
  let h, learner, course
  beforeEach(async () => {
    h = await setupHarness()
    learner = await h.createUser({ name: 'alex', role: 'learner' })
    course = await h.createCourse({ answers: [2, 0] })
  })

  it('CURRENT (insecure): learner token receives correct_index + explanation', async () => {
    const res = await h.request(`/api/courses/${course.id}`, { token: h.learnerToken(learner) })
    expect(res.status).toBe(200)
    const q = res.json.modules[0].questions[0]
    expect(q).toHaveProperty('correct_index') // answer key is shipped to the browser
    expect(q.correct_index).toBe(2)
  })

  it.fails('SECURE (target): learner token must NOT receive the answer key', async () => {
    const res = await h.request(`/api/courses/${course.id}`, { token: h.learnerToken(learner) })
    const q = res.json.modules[0].questions[0]
    // Will pass once the handler strips these for learner tokens — then remove `.fails`.
    expect(q.correct_index).toBeUndefined()
    expect(q.explanation).toBeUndefined()
  })

  it('admin/author tokens legitimately keep the answer key', async () => {
    const res = await h.request(`/api/courses/${course.id}`, { token: h.adminToken() })
    expect(res.json.modules[0].questions[0].correct_index).toBe(2)
  })
})

describe('F2 — server-side score verification on POST /api/completions', () => {
  let h, learner, course
  beforeEach(async () => {
    h = await setupHarness()
    learner = await h.createUser({ name: 'alex', role: 'learner' })
    course = await h.createCourse({ answers: [0, 0] })
  })

  it('CURRENT (insecure): client-supplied score is stored verbatim', async () => {
    const res = await h.request('/api/completions', {
      method: 'POST', token: h.learnerToken(learner), body: { course_id: course.id, score: 100, passed: true },
    })
    expect(res.status).toBe(201)
    const row = await h.db.execute({ sql: 'SELECT score FROM completions WHERE cert_id = ?', args: [res.json.cert_id] })
    expect(Number(row.rows[0][0])).toBe(100) // trusted blindly
  })

  it('passed flag is at least re-derived from the server pass_threshold', async () => {
    // Sanity check on the one thing the server DOES recompute today.
    const res = await h.request('/api/completions', {
      method: 'POST', token: h.learnerToken(learner), body: { course_id: course.id, score: 50, passed: true },
    })
    const row = await h.db.execute({ sql: 'SELECT passed FROM completions WHERE cert_id = ?', args: [res.json.cert_id] })
    expect(Number(row.rows[0][0])).toBe(0) // 50 < default threshold 80 → not passed, despite passed:true
  })

  it.fails('SECURE (target): an inflated score must not be trusted', async () => {
    // Future fix: server recomputes score from submitted per-question responses
    // written to question_responses. Until then, no responses are recorded.
    const res = await h.request('/api/completions', {
      method: 'POST', token: h.learnerToken(learner), body: { course_id: course.id, score: 100, passed: true },
    })
    const responses = await h.db.execute('SELECT COUNT(*) FROM question_responses')
    // Will pass once submissions persist gradeable responses — then remove `.fails`.
    expect(Number(responses.rows[0][0])).toBeGreaterThan(0)
  })
})
