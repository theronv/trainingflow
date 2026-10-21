import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const src = readFileSync(fileURLToPath(new URL('../../js/milestones.js', import.meta.url)), 'utf8')
const Milestones = new Function(src + '\nreturn Milestones;')()

const rec = (course_id, score, passed, completed_at, cert_id = `PG-${course_id}-${completed_at}`) => ({ course_id, score, passed: passed ? 1 : 0, completed_at, cert_id })
const ids = (list) => list.map(m => m.id)

describe('Milestones.earned', () => {
  it('earns nothing without a pass', () => {
    expect(Milestones.earned([], [])).toEqual([])
    expect(Milestones.earned([rec('a', 40, false, 1)], [])).toEqual([])
  })

  it('first certificate, first try and perfect score from one clean pass', () => {
    expect(ids(Milestones.earned([rec('a', 100, true, 1)], []))).toEqual(['first', 'perfect', 'first-try'])
  })

  it('a retake earns Comeback, not First try', () => {
    const out = ids(Milestones.earned([rec('a', 50, false, 1), rec('a', 90, true, 2)], []))
    expect(out).toContain('comeback')
    expect(out).not.toContain('first-try')
  })

  it('counts distinct courses, so repeat passes of one course do not add up', () => {
    const out = ids(Milestones.earned([rec('a', 90, true, 1), rec('a', 95, true, 2), rec('b', 90, true, 3)], []))
    expect(out).not.toContain('three')
    expect(ids(Milestones.earned([rec('a', 90, true, 1), rec('b', 90, true, 2), rec('c', 90, true, 3)], []))).toContain('three')
  })

  it('section complete needs every course of a section with at least two courses', () => {
    const courses = [{ id: 'a', section_id: 's1' }, { id: 'b', section_id: 's1' }, { id: 'c', section_id: 's2' }]
    expect(ids(Milestones.earned([rec('a', 90, true, 1)], courses))).not.toContain('section')
    expect(ids(Milestones.earned([rec('a', 90, true, 1), rec('b', 90, true, 2)], courses))).toContain('section')
    // a lone course in a section is not a "section"
    expect(ids(Milestones.earned([rec('c', 90, true, 1)], courses))).not.toContain('section')
  })
})

describe('Milestones.fresh', () => {
  it('returns only what the newest completion unlocked', () => {
    const before = [rec('a', 90, true, 1)]
    const after = [...before, rec('b', 100, true, 2)]
    expect(ids(Milestones.fresh(before, after, []))).toEqual(['perfect'])
  })
})
