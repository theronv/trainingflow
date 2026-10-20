import { describe, it, expect, beforeEach, afterAll } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// js/builder.js is a browser global script; evaluate it with stubs to test the assign-selection logic.
const src = readFileSync(fileURLToPath(new URL('../../js/builder.js', import.meta.url)), 'utf8')
const els = {}
const el = (id) => (els[id] ||= { classList: { toggle(c, on) { this.hidden = on }, hidden: true }, textContent: '', disabled: false })
const globals = { $$: el, esc: (s) => String(s), curManager: null, Admin: { _cv: { courses: [{ id: 'c1' }, { id: 'c2' }, { id: 'c3' }] } }, Manager: {} }
const names = Object.keys(globals)
globalThis.document = { querySelectorAll: () => [] }
const Builder = new Function(...names, 'App', 'Toast', 'api', 'managerApi', 'cbState', `${src}\nreturn Builder;`)(
  ...names.map((n) => globals[n]), {}, {}, () => {}, () => {}, {},
)

const state = (courseIds, assigned) => ({ courseIds, assigned, learners: new Set(), teams: new Set(), people: [{ id: 'a', team_id: 1 }, { id: 'b', team_id: 1 }, { id: 'c', team_id: 2 }] })

describe('assign selection', () => {
  afterAll(() => { delete globalThis.document })
  beforeEach(() => { Builder._sel = new Set(); Builder._assign = null })

  it('select all toggles every course and the bar label', () => {
    Builder.selectAllCourses()
    expect([...Builder._sel]).toEqual(['c1', 'c2', 'c3'])
    expect(els['a-sel-count'].textContent).toBe('3 courses selected')
    expect(els['a-sel-all'].textContent).toBe('Deselect all')
    Builder.selectAllCourses()
    expect(Builder._sel.size).toBe(0)
    expect(els['a-sel-all'].textContent).toBe('Select all')
  })

  it('prunes selections for courses that no longer exist', () => {
    Builder._sel = new Set(['c1', 'gone'])
    Builder.selPrune(['c1', 'c2'])
    expect([...Builder._sel]).toEqual(['c1'])
    expect(els['a-sel-count'].textContent).toBe('1 course selected')
  })

  it('a learner is pending until they hold every selected course', () => {
    const st = state(['c1', 'c2'], { c1: new Set(['a', 'b']), c2: new Set(['a']) })
    expect(Builder._assignPending(st, 'a')).toBe(0)
    expect(Builder._assignPending(st, 'b')).toBe(1)
    expect(Builder._assignPending(st, 'c')).toBe(2)
  })

  it('counts people who would gain an assignment and labels the button', () => {
    const st = state(['c1', 'c2'], { c1: new Set(['a', 'b']), c2: new Set(['a']) })
    st.teams.add(1); st.learners.add('c')
    Builder._assign = st
    expect(Builder._assignCount()).toBe(2)
    Builder._assignUpdateBtn()
    expect(els['assign-submit-btn'].textContent).toBe('Assign 2 courses to 2 learners')
  })

  it('keeps the single-course label and disables when nothing is pending', () => {
    Builder._assign = state(['c1'], { c1: new Set(['a', 'b', 'c']) })
    Builder._assign.teams.add(1)
    Builder._assignUpdateBtn()
    expect(els['assign-submit-btn'].disabled).toBe(true)
    Builder._assign = state(['c1'], { c1: new Set() })
    Builder._assign.learners.add('a')
    Builder._assignUpdateBtn()
    expect(els['assign-submit-btn'].textContent).toBe('Assign to 1 learner')
  })
})
