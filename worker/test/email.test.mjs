import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { setupHarness } from './helpers.mjs'

/** Certificate-earned emails via Resend. fetch is stubbed; nothing leaves the process. */
describe('certificate emails', () => {
  let h, team, learner, manager, course, token, calls

  const setEmail = (u, email, notify = 1) =>
    h.db.execute({ sql: 'UPDATE users SET email = ?, email_notifications = ? WHERE id = ?', args: [email, notify, u.id] })
  const answerAll = async (picks) => {
    for (let i = 0; i < picks.length; i++) {
      await h.request('/api/quiz/answer', { method: 'POST', token, body: { question_id: course.question_ids[i], selected_index: picks[i] } })
    }
  }
  const finish = () => h.request('/api/completions', { method: 'POST', token, body: { course_id: course.id } })
  const sent = () => calls.map(c => ({ url: c.url, headers: c.init.headers, body: JSON.parse(c.init.body) }))

  beforeEach(async () => {
    h = await setupHarness()
    Object.assign(h.env, { RESEND_API_KEY: 're_test', EMAIL_FROM: 'Pregame Academy <academy@example.test>', APP_URL: 'https://app.example.test' })
    team = await h.createTeam('North')
    learner = await h.createUser({ name: 'Alex Rivera', role: 'learner', team_id: team })
    manager = await h.createUser({ name: 'Sam Boss', role: 'manager', team_id: team })
    course = await h.createCourse({ title: 'Safety 101', answers: [2, 0] })
    token = h.learnerToken(learner)
    await setEmail(learner, 'alex@example.test')
    await setEmail(manager, 'sam@example.test')
    calls = []
    vi.stubGlobal('fetch', vi.fn(async (url, init) => { calls.push({ url, init }); return new Response('{"id":"x"}', { status: 200 }) }))
  })
  afterEach(() => vi.unstubAllGlobals())

  it('emails the learner and their team manager when they pass', async () => {
    await answerAll([2, 0])
    const res = await finish()
    expect(res.status).toBe(201)
    const mails = sent()
    expect(mails).toHaveLength(2)
    mails.forEach(m => {
      expect(m.url).toBe('https://api.resend.com/emails')
      expect(m.headers.Authorization).toBe('Bearer re_test')
      expect(m.body.from).toBe('Pregame Academy <academy@example.test>')
    })
    const toLearner = mails.find(m => m.body.to[0] === 'alex@example.test')
    expect(toLearner.body.subject).toBe('You earned a certificate: Safety 101')
    expect(toLearner.body.html).toContain(`https://app.example.test/#/verify/${res.json.cert_id}`)
    expect(toLearner.body.text).toContain('100%')
    expect(toLearner.headers['Idempotency-Key']).toBe(`cert-${res.json.cert_id}-${learner.id}`)
    const toManager = mails.find(m => m.body.to[0] === 'sam@example.test')
    expect(toManager.body.subject).toBe('Alex Rivera earned a certificate: Safety 101')
  })

  it('escapes learner-supplied text in the HTML', async () => {
    await h.db.execute({ sql: 'UPDATE users SET name = ? WHERE id = ?', args: ['<img src=x onerror=alert(1)>', learner.id] })
    const t = h.mint({ id: learner.id, name: '<img src=x onerror=alert(1)>', role: 'learner' })
    for (let i = 0; i < 2; i++) await h.request('/api/quiz/answer', { method: 'POST', token: t, body: { question_id: course.question_ids[i], selected_index: [2, 0][i] } })
    await h.request('/api/completions', { method: 'POST', token: t, body: { course_id: course.id } })
    for (const m of sent()) {
      expect(m.body.html).not.toContain('<img')
      expect(m.body.html).toContain('&lt;img')
    }
  })

  it('sends nothing for a failed attempt', async () => {
    await answerAll([0, 1])
    expect((await finish()).json.passed).toBe(false)
    expect(calls).toHaveLength(0)
  })

  it('sends nothing when Resend is not configured', async () => {
    delete h.env.RESEND_API_KEY
    await answerAll([2, 0])
    expect((await finish()).status).toBe(201)
    expect(calls).toHaveLength(0)
  })

  it('respects opt-out and missing addresses, and only emails the learner\'s own team', async () => {
    const otherTeam = await h.createTeam('South')
    const other = await h.createUser({ name: 'Other Boss', role: 'manager', team_id: otherTeam })
    await setEmail(other, 'other@example.test')
    await setEmail(manager, 'sam@example.test', 0)
    await h.db.execute({ sql: 'UPDATE users SET email = NULL WHERE id = ?', args: [learner.id] })
    await answerAll([2, 0])
    await finish()
    expect(calls).toHaveLength(0)
  })

  it('does not email a manager about their own certificate twice', async () => {
    const t = h.managerToken(manager)
    for (let i = 0; i < 2; i++) await h.request('/api/quiz/answer', { method: 'POST', token: t, body: { question_id: course.question_ids[i], selected_index: [2, 0][i] } })
    await h.request('/api/completions', { method: 'POST', token: t, body: { course_id: course.id } })
    const to = sent().map(m => m.body.to[0])
    expect(to).toEqual(['sam@example.test'])
  })

  it('never fails the completion when Resend errors or is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network down') }))
    await answerAll([2, 0])
    const res = await finish()
    expect(res.status).toBe(201)
    expect(res.json.passed).toBe(true)
  })
})

describe('email notification preference', () => {
  it('is readable and switchable on /api/learners/me', async () => {
    const h = await setupHarness()
    const u = await h.createUser({ name: 'Alex', role: 'learner' })
    await h.db.execute({ sql: 'UPDATE users SET email = ? WHERE id = ?', args: ['alex@example.test', u.id] })
    const token = h.learnerToken(u)
    expect((await h.request('/api/learners/me', { token })).json).toMatchObject({ email: 'alex@example.test', email_notifications: true })
    const off = await h.request('/api/learners/me', { method: 'PATCH', token, body: { email_notifications: false } })
    expect(off.status).toBe(200)
    expect((await h.request('/api/learners/me', { token })).json.email_notifications).toBe(false)
  })
})
