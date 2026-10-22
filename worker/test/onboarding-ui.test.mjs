import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const src = readFileSync(fileURLToPath(new URL('../../js/onboarding.js', import.meta.url)), 'utf8')

// The module touches only esc/escJs and localStorage; stub them the way core.js provides them.
const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
const escJs = s => String(s ?? '').replace(/\\/g, '\\\\').replace(/'/g, "\\'")
function load(storage) {
  return new Function('esc', 'escJs', 'localStorage', src + '\nreturn Onboarding;')(esc, escJs, storage)
}
const memory = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) } }
const broken = { getItem() { throw new Error('blocked') }, setItem() { throw new Error('blocked') }, removeItem() { throw new Error('blocked') } }

const Onboarding = load(memory())
const DAY = 86400
const a = (course_id, due_at = null, course_title = course_id.toUpperCase()) => ({ course_id, due_at, course_title })
const rec = (course_id, passed = 1) => ({ course_id, passed })
const prog = course_id => ({ course_id })

describe('Onboarding.learnerStage', () => {
  it('is new with no completions and no progress', () => {
    expect(Onboarding.learnerStage({ assignments: [a('x')], completions: [], progress: [] })).toBe('new')
    expect(Onboarding.learnerStage({})).toBe('new')
  })
  it('is active once any module progress exists or a course was attempted', () => {
    expect(Onboarding.learnerStage({ assignments: [a('x')], progress: [prog('x')] })).toBe('active')
    expect(Onboarding.learnerStage({ completions: [rec('x', 0)] })).toBe('active')
  })
  it('is done once every assigned course is passed', () => {
    expect(Onboarding.learnerStage({ assignments: [a('x')], completions: [rec('x')] })).toBe('done')
  })
  it('is active when a passed course sits beside an unpassed assignment', () => {
    expect(Onboarding.learnerStage({ assignments: [a('x'), a('y')], completions: [rec('x')] })).toBe('active')
  })
})

describe('Onboarding.todo and startCourse', () => {
  it('skips passed courses and orders by soonest due, undated last', () => {
    const assignments = [a('late', 300 * DAY), a('none'), a('soon', 100 * DAY), a('done', 50 * DAY)]
    const todo = Onboarding.todo({ assignments, completions: [rec('done')] })
    expect(todo.map(t => t.course_id)).toEqual(['soon', 'late', 'none'])
    expect(Onboarding.startCourse({ assignments, completions: [rec('done')] }).course_id).toBe('soon')
  })
  it('accepts due_at as a date string', () => {
    const todo = Onboarding.todo({ assignments: [a('b', '2030-06-01'), a('a', '2030-01-01')] })
    expect(todo.map(t => t.course_id)).toEqual(['a', 'b'])
  })
  it('returns null when nothing is left', () => {
    expect(Onboarding.startCourse({ assignments: [] })).toBeNull()
  })
})

describe('Onboarding.learnerHtml', () => {
  const base = { name: 'Jamie Lee', team: 'Patient Services', pass: 80, assignments: [a('csx', 100 * DAY, 'Customer Service'), a('hip', null, 'HIPAA')], completions: [], progress: [] }

  it('greets by first name and starts the soonest-due course', () => {
    const html = Onboarding.learnerHtml(base)
    expect(html).toContain('Welcome, Jamie')
    expect(html).toContain('Patient Services')
    expect(html).toContain('2 courses')
    expect(html).toContain("Onboarding.start('csx')")
    expect(html).toContain('Start your first course →')
    expect(html).toContain('aria-label="Start your first course: Customer Service"')
    expect(html).toContain(new Date(100 * DAY * 1000).toLocaleDateString())
    expect(html).toContain('80%')
  })
  it('uses the singular for one course', () => {
    expect(Onboarding.learnerHtml({ ...base, assignments: [a('csx')] })).toContain('1 course</strong>')
  })
  it('explains what happens next when nothing is assigned, with no start button', () => {
    const html = Onboarding.learnerHtml({ ...base, assignments: [] })
    expect(html).toContain('Welcome, Jamie')
    expect(html).toContain('Patient Services manager')
    expect(html).not.toContain('Onboarding.start')
    expect(html).toContain('Onboarding.dismiss()')
  })
  it('omits the team when the account has none', () => {
    const html = Onboarding.learnerHtml({ ...base, team: '' })
    expect(html).not.toContain('You\'re on')
  })
  it('renders nothing once the learner has started', () => {
    expect(Onboarding.learnerHtml({ ...base, progress: [prog('csx')] })).toBe('')
    expect(Onboarding.learnerHtml({ ...base, completions: [rec('csx')] })).toBe('')
  })
  it('escapes names, teams and course titles in text and in the handler', () => {
    const html = Onboarding.learnerHtml({ ...base, name: '<img onerror=x>', team: '<b>t</b>', assignments: [{ course_id: "a'b", due_at: null, course_title: '<script>x</script>' }] })
    expect(html).not.toContain('<img')
    expect(html).not.toContain('<b>t</b>')
    expect(html).not.toContain('<script>')
    expect(html).toContain("Onboarding.start('a\\'b')")
  })
  it('falls back to a plain greeting without a name', () => {
    expect(Onboarding.learnerHtml({ ...base, name: '' })).toContain('Welcome</')
  })
})

describe('Onboarding markup', () => {
  it('only uses onb-* classes that the stylesheet defines', () => {
    const css = readFileSync(fileURLToPath(new URL('../../css/style.css', import.meta.url)), 'utf8')
    const html = Onboarding.learnerHtml({ name: 'Jamie', team: 'T', pass: 80, assignments: [a('x', 5 * DAY)] })
    const used = [...html.matchAll(/class="([^"]+)"/g)].flatMap(m => m[1].split(/\s+/)).filter(c => c.startsWith('onb-'))
    expect(used.length).toBeGreaterThan(4)
    for (const c of used) expect(css, c).toContain('.' + c)
  })
})

describe('Onboarding dismissal', () => {
  it('remembers per role and user', () => {
    const O = load(memory())
    expect(O.isDismissed('learner', 'u1')).toBe(false)
    O.dismissFor('learner', 'u1')
    expect(O.isDismissed('learner', 'u1')).toBe(true)
    expect(O.isDismissed('learner', 'u2')).toBe(false)
    expect(O.isDismissed('manager', 'u1')).toBe(false)
  })
  it('never throws and shows the card when storage is blocked', () => {
    const O = load(broken)
    expect(() => O.dismissFor('learner', 'u1')).not.toThrow()
    expect(O.isDismissed('learner', 'u1')).toBe(false)
  })
})
