import { describe, it, expect, beforeEach } from 'vitest'
import { setupHarness } from './helpers.mjs'

/** POST /api/completions returns what the certificate ceremony needs: attempt number and a per-module breakdown. */
describe('completion result details', () => {
  let h, learner, course, token
  beforeEach(async () => {
    h = await setupHarness()
    learner = await h.createUser({ name: 'alex', role: 'learner' })
    course = await h.createCourse({ answers: [2, 0] })
    token = h.learnerToken(learner)
  })

  const answerAll = async (picks) => {
    for (let i = 0; i < picks.length; i++) {
      await h.request('/api/quiz/answer', { method: 'POST', token, body: { question_id: course.question_ids[i], selected_index: picks[i] } })
    }
  }
  const finish = () => h.request('/api/completions', { method: 'POST', token, body: { course_id: course.id } })

  it('reports a first attempt with a per-module breakdown', async () => {
    await answerAll([2, 0])
    const res = await finish()
    expect(res.status).toBe(201)
    expect(res.json).toMatchObject({ passed: true, score: 100, attempt: 1 })
    expect(res.json.cert_id).toMatch(/^PG-[0-9A-F]{8}$/)
    expect(res.json.breakdown).toEqual([{ module_id: course.module_id, title: 'Module 1', correct: 2, total: 2 }])
  })

  it('counts earlier attempts and shows which module was missed', async () => {
    await answerAll([0, 0])
    const failed = await finish()
    expect(failed.json).toMatchObject({ passed: false, score: 50, attempt: 1 })
    expect(failed.json.breakdown[0]).toMatchObject({ correct: 1, total: 2 })
    await answerAll([2, 0])
    const retake = await finish()
    expect(retake.json).toMatchObject({ passed: true, attempt: 2 })
  })
})
