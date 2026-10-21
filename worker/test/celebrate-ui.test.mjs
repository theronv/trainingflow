import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// js/celebrate.js is a browser global script; its pure helpers are exercised without a DOM.
const src = readFileSync(fileURLToPath(new URL('../../js/celebrate.js', import.meta.url)), 'utf8')
const Celebrate = new Function(src + '\nreturn Celebrate;')()

describe('formatDuration', () => {
  it('rounds to friendly units', () => {
    expect(Celebrate.formatDuration(20_000)).toBe('Under a minute')
    expect(Celebrate.formatDuration(NaN)).toBe('Under a minute')
    expect(Celebrate.formatDuration(12 * 60_000)).toBe('12 min')
    expect(Celebrate.formatDuration(60 * 60_000)).toBe('1 h')
    expect(Celebrate.formatDuration(95 * 60_000)).toBe('1 h 35 min')
  })
})

describe('missedModules', () => {
  it('lists only modules with a miss, worst first', () => {
    const out = Celebrate.missedModules([
      { title: 'A', correct: 3, total: 3 },
      { title: 'B', correct: 2, total: 3 },
      { title: 'C', correct: 1, total: 4 },
    ])
    expect(out.map(m => m.title)).toEqual(['C', 'B'])
    expect(Celebrate.missedModules(undefined)).toEqual([])
  })
})

describe('nextUp', () => {
  const asg = (course_id, due_at = null) => ({ course_id, due_at, course_title: course_id })
  it('skips the current and already-passed courses and prefers the soonest due date', () => {
    const next = Celebrate.nextUp(
      [asg('cur'), asg('done'), asg('later', '2030-02-01'), asg('sooner', '2030-01-01'), asg('nodate')],
      [{ course_id: 'done', passed: 1 }, { course_id: 'later', passed: 0 }],
      'cur')
    expect(next.course_id).toBe('sooner')
  })
  it('returns null when everything is done', () => {
    expect(Celebrate.nextUp([asg('cur')], [], 'cur')).toBeNull()
    expect(Celebrate.nextUp(undefined, undefined, 'x')).toBeNull()
  })
})

describe('stats', () => {
  const breakdown = [{ correct: 3, total: 3 }, { correct: 4, total: 5 }]
  it('summarises answers, attempt and time', () => {
    expect(Celebrate.stats({ breakdown, attempt: 1 }, 5 * 60_000)).toEqual([
      { label: 'Correct answers', value: '7 of 8' },
      { label: 'Attempt', value: 'First try' },
      { label: 'Time this session', value: '5 min' },
    ])
  })
  it('labels retakes and drops time when unknown', () => {
    const out = Celebrate.stats({ breakdown, attempt: 3 }, 0)
    expect(out.map(s => s.value)).toEqual(['7 of 8', 'Attempt 3'])
  })
})
