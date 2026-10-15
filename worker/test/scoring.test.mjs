import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

/**
 * Scoring & answer-key integrity (audit findings F1/F2) — now enforced.
 *
 *  F1: learners/managers never receive correct_index or explanation from the course
 *      endpoint; answers are graded one at a time by POST /api/quiz/answer.
 *  F2: POST /api/completions ignores any client-supplied score/passed and computes the
 *      result from the learner's server-recorded answers, persisting question_responses.
 */
describe('F1 — answer key is not exposed by GET /api/courses/:id', () => {
  let h, learner, manager, course
  beforeEach(async () => {
    h = await setupHarness()
    const team = await h.createTeam('T')
    learner = await h.createUser({ name: 'alex', role: 'learner', team_id: team })
    manager = await h.createUser({ name: 'sarah', role: 'manager', team_id: team })
    course = await h.createCourse({ answers: [2, 0] })
  })

  it('learner token does not receive correct_index or explanation', async () => {
    const res = await h.request(`/api/courses/${course.id}`, { token: h.learnerToken(learner) })
    expect(res.status).toBe(200)
    const q = res.json.modules[0].questions[0]
    expect(q).not.toHaveProperty('correct_index')
    expect(q).not.toHaveProperty('explanation')
    expect(q.question).toBe('Q0')
    expect(q.option_a).toBe('A')
  })

  it('manager token does not receive the answer key either', async () => {
    const res = await h.request(`/api/courses/${course.id}`, { token: h.managerToken(manager) })
    expect(res.json.modules[0].questions[0]).not.toHaveProperty('correct_index')
  })

  it('admin token keeps the answer key (authoring/preview)', async () => {
    const res = await h.request(`/api/courses/${course.id}`, { token: h.adminToken() })
    expect(res.json.modules[0].questions[0].correct_index).toBe(2)
  })

  it('course and section lists require authentication', async () => {
    expect((await h.request('/api/courses')).status).toBe(401)
    expect((await h.request('/api/sections')).status).toBe(401)
    expect((await h.request('/api/courses', { token: h.learnerToken(learner) })).status).toBe(200)
    expect((await h.request('/api/sections', { token: h.learnerToken(learner) })).status).toBe(200)
  })
})

describe('POST /api/quiz/answer', () => {
  let h, learner, course
  beforeEach(async () => {
    h = await setupHarness()
    learner = await h.createUser({ name: 'alex', role: 'learner' })
    course = await h.createCourse({ answers: [2, 0] })
  })

  const answer = (qid, sel, token) =>
    h.request('/api/quiz/answer', { method: 'POST', token: token ?? h.learnerToken(learner), body: { question_id: qid, selected_index: sel } })

  it('grades server-side and reveals the key only after answering', async () => {
    const wrong = await answer(course.question_ids[0], 0)
    expect(wrong.status).toBe(200)
    expect(wrong.json).toMatchObject({ correct: false, correct_index: 2, explanation: 'Because 0' })
    const right = await answer(course.question_ids[0], 2)
    expect(right.json.correct).toBe(true)
  })

  it('requires a learner token', async () => {
    expect((await h.request('/api/quiz/answer', { method: 'POST', body: { question_id: course.question_ids[0], selected_index: 0 } })).status).toBe(401)
    expect((await answer(course.question_ids[0], 0, h.adminToken())).status).toBe(401)
  })

  it('validates input', async () => {
    expect((await answer(course.question_ids[0], 7)).status).toBe(400)
    expect((await answer('nope', 1)).status).toBe(404)
  })
})

describe('F2 — completion score is computed server-side', () => {
  let h, learner, course
  beforeEach(async () => {
    h = await setupHarness()
    learner = await h.createUser({ name: 'alex', role: 'learner' })
    course = await h.createCourse({ answers: [0, 1] })
  })

  const answer = (qid, sel) =>
    h.request('/api/quiz/answer', { method: 'POST', token: h.learnerToken(learner), body: { question_id: qid, selected_index: sel } })
  const complete = (body) =>
    h.request('/api/completions', { method: 'POST', token: h.learnerToken(learner), body })

  it('a forged score with no answers is rejected and mints nothing', async () => {
    const res = await complete({ course_id: course.id, score: 100, passed: true })
    expect(res.status).toBe(400)
    const rows = await h.db.execute('SELECT COUNT(*) FROM completions')
    expect(Number(rows.rows[0][0])).toBe(0)
  })

  it('score comes from recorded answers, ignoring the client value', async () => {
    await answer(course.question_ids[0], 0) // correct
    await answer(course.question_ids[1], 3) // wrong (answer is 1)
    const res = await complete({ course_id: course.id, score: 100, passed: true })
    expect(res.status).toBe(201)
    expect(res.json).toMatchObject({ score: 50, passed: false })
    const row = await h.db.execute({ sql: 'SELECT score, passed FROM completions WHERE cert_id = ?', args: [res.json.cert_id] })
    expect(Number(row.rows[0][0])).toBe(50)
    expect(Number(row.rows[0][1])).toBe(0)
  })

  it('all-correct answers pass and persist question_responses', async () => {
    await answer(course.question_ids[0], 0)
    await answer(course.question_ids[1], 1)
    const res = await complete({ course_id: course.id })
    expect(res.json).toMatchObject({ score: 100, passed: true })
    const responses = await h.db.execute('SELECT is_correct FROM question_responses')
    expect(responses.rows.length).toBe(2)
    expect(responses.rows.every(r => Number(r[0]) === 1)).toBe(true)
  })

  it('the latest answer wins (retake) and answers are consumed on completion', async () => {
    await answer(course.question_ids[0], 3)
    await answer(course.question_ids[1], 3)
    await answer(course.question_ids[0], 0) // retake corrects it
    await answer(course.question_ids[1], 1)
    expect((await complete({ course_id: course.id })).json.score).toBe(100)
    // Answers were consumed — a second certificate needs the quiz taken again.
    expect((await complete({ course_id: course.id })).status).toBe(400)
  })

  it('unknown course is a 404', async () => {
    expect((await complete({ course_id: 'missing' })).status).toBe(404)
  })

  it('a course with no questions completes at 100', async () => {
    const empty = await h.createCourse({ answers: [] })
    const res = await complete({ course_id: empty.id })
    expect(res.status).toBe(201)
    expect(res.json.score).toBe(100)
  })
})
