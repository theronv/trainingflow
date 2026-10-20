import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// js/importer.js is a browser global script. Evaluate it with the browser globals stubbed so
// its pure logic (parsing, validation, prompt building, reply merging) can be tested directly.
const src = readFileSync(fileURLToPath(new URL('../../js/importer.js', import.meta.url)), 'utf8')
const Importer = new Function('$$', 'esc', 'Toast', 'adminApi', 'api', 'ICON', 'Admin', `${src}\nreturn Importer;`)(
  () => null, (s) => String(s), {}, () => {}, () => {}, {}, {},
)

const q = (over = {}) => ({ question: 'Where do you filter?', options: ['Top bar', 'Side menu', 'Footer', 'Settings'], correct_index: 1, explanation: 'It lives in the side menu.', ...over })
const course = () => ({
  title: 'Demo', modules: [
    { _rid: 'm1', title: 'Filtering', content: 'Open the filter panel.', questions: [] },
    { _rid: 'm2', title: 'Reports', content: 'Open Reports.', questions: [] },
  ],
})

describe('extractJson', () => {
  it('reads fenced JSON surrounded by prose', () => {
    expect(Importer.extractJson('Here you go:\n```json\n{"a":1}\n```\nDone.').data).toEqual({ a: 1 })
  })
  it('repairs smart quotes', () => {
    expect(Importer.extractJson('{“a”:“b”}').data).toEqual({ a: 'b' })
  })
  it('accepts a top-level array', () => {
    expect(Importer.extractJson('[{"id":"m1"}]').data).toEqual([{ id: 'm1' }])
  })
  it('reports missing and invalid JSON', () => {
    expect(Importer.extractJson('no json here').error).toMatch(/No JSON/)
    expect(Importer.extractJson('{"a":').error).toMatch(/No JSON|Invalid JSON/)
    expect(Importer.extractJson('{"a": nope}').error).toMatch(/Invalid JSON/)
  })
})

describe('normalizeQuestion', () => {
  it('accepts a valid question and letter answers', () => {
    const errors = []
    const out = Importer.normalizeQuestion(q({ correct_index: 'c' }), 'Q', errors)
    expect(errors).toEqual([])
    expect(out.correct_index).toBe(2)
  })
  it.each([
    ['fewer than 4 options', { options: ['a', 'b', 'c'] }, /4 non-empty options/],
    ['an empty option', { options: ['a', '', 'c', 'd'] }, /4 non-empty options/],
    ['no question text', { question: ' ' }, /missing "question"/],
    ['an out-of-range answer', { correct_index: 4 }, /correct_index/],
    ['a missing answer', { correct_index: null }, /correct_index/],
  ])('flags %s', (_, over, msg) => {
    const errors = []
    Importer.normalizeQuestion(q(over), 'Q', errors)
    expect(errors.join(' ')).toMatch(msg)
  })
  it('does not throw on a null question', () => {
    const errors = []
    expect(() => Importer.normalizeQuestion(null, 'Q', errors)).not.toThrow()
    expect(errors.length).toBeGreaterThan(0)
  })
})

describe('shuffleOptions', () => {
  it('keeps the correct answer pointing at the same text', () => {
    for (let seed = 0; seed < 25; seed++) {
      let s = seed + 1
      const rand = () => ((s = (s * 16807) % 2147483647) / 2147483647)
      const out = Importer.shuffleOptions(q(), rand)
      expect(out.options[out.correct_index]).toBe('Side menu')
      expect([...out.options].sort()).toEqual(['Footer', 'Settings', 'Side menu', 'Top bar'])
    }
  })
  it('moves the answer off position B at least sometimes', () => {
    const positions = new Set()
    for (let seed = 1; seed < 40; seed++) {
      let s = seed
      positions.add(Importer.shuffleOptions(q(), () => ((s = (s * 16807) % 2147483647) / 2147483647)).correct_index)
    }
    expect(positions.size).toBeGreaterThan(1)
  })
  it('leaves "all of the above" style options in order', () => {
    const fixed = q({ options: ['A', 'B', 'C', 'All of the above'], correct_index: 3 })
    expect(Importer.shuffleOptions(fixed)).toBe(fixed)
  })
})

describe('plainLesson', () => {
  it('turns screenshots into markers and links into text', () => {
    const out = Importer.plainLesson('Click [Filters](https://x.test/a).\n\n![Filter panel](https://img.test/1.jpg)\n\n\n\n![](https://img.test/2.jpg)\nDone')
    expect(out).toContain('Click Filters.')
    expect(out).toContain('[Screenshot: Filter panel]')
    expect(out).not.toMatch(/https?:/)
    expect(out).not.toMatch(/\n{3,}/)
  })
})

describe('batchModules', () => {
  const mods = (...lens) => lens.map((n, i) => ({ _rid: `m${i + 1}`, title: `T${i}`, content: 'x'.repeat(n) }))
  it('groups modules within the budget', () => {
    expect(Importer.batchModules(mods(40, 40, 40), 100).map(b => b.length)).toEqual([2, 1])
  })
  it('gives an oversized module its own batch', () => {
    expect(Importer.batchModules(mods(10, 500, 10), 100).map(b => b.length)).toEqual([1, 1, 1])
  })
  it('returns no batches for no modules', () => {
    expect(Importer.batchModules([])).toEqual([])
  })
})

describe('buildQuestionsPrompt', () => {
  const settings = { count: 4, difficulty: 'applied', focus: 'howto' }
  it('includes ids, titles, lesson text and the settings, without image URLs', () => {
    const c = course()
    c.modules[0].content = 'Open the panel.\n![Panel](https://img.test/p.jpg)'
    const p = Importer.buildQuestionsPrompt(c.modules, settings)
    expect(p).toContain('=== LESSON m1: Filtering ===')
    expect(p).toContain('=== LESSON m2: Reports ===')
    expect(p).toContain('[Screenshot: Panel]')
    expect(p).not.toContain('img.test')
    expect(p).toContain('up to 4 multiple-choice questions')
    expect(p).toContain('Product how-to')
  })
})

describe('applyQuestionsReply', () => {
  const reply = (mods) => '```json\n' + JSON.stringify({ modules: mods }) + '\n```'
  const entry = (id, over = {}) => ({ id, summary: 'Short summary.', learning_objectives: ['Do the thing'], questions: [q()], ...over })

  it('merges questions, summary and objectives into the matching modules', () => {
    const c = course()
    const { applied, errors } = Importer.applyQuestionsReply(c, reply([entry('m1'), entry('m2')]))
    expect(errors).toEqual([])
    expect(applied).toEqual(['m1', 'm2'])
    expect(c.modules[0].questions).toHaveLength(1)
    expect(c.modules[0].summary).toBe('Short summary.')
    expect(c.modules[1].learning_objectives).toEqual(['Do the thing'])
  })
  it('keeps the correct answer text after shuffling', () => {
    const c = course()
    Importer.applyQuestionsReply(c, reply([entry('m1')]))
    const [out] = c.modules[0].questions
    expect(out.options[out.correct_index]).toBe('Side menu')
  })
  it('never changes the lesson content or title', () => {
    const c = course()
    Importer.applyQuestionsReply(c, reply([entry('m1', { title: 'Hijacked', content: 'Rewritten' })]))
    expect(c.modules[0].title).toBe('Filtering')
    expect(c.modules[0].content).toBe('Open the filter panel.')
  })
  it('applies valid modules and reports the invalid ones', () => {
    const c = course()
    const { applied, errors } = Importer.applyQuestionsReply(c, reply([entry('m1'), entry('m2', { questions: [q({ options: ['a'] })] })]))
    expect(applied).toEqual(['m1'])
    expect(c.modules[1].questions).toEqual([])
    expect(errors.join(' ')).toMatch(/"Reports".*4 non-empty options/)
  })
  it('reports unknown ids and empty question lists', () => {
    const c = course()
    const { applied, errors } = Importer.applyQuestionsReply(c, reply([entry('m9'), entry('m1', { questions: [] })]))
    expect(applied).toEqual([])
    expect(errors.join(' ')).toMatch(/Unknown module id "m9"/)
    expect(errors.join(' ')).toMatch(/no questions/)
  })
  it('replaces earlier questions when a module is redone', () => {
    const c = course()
    Importer.applyQuestionsReply(c, reply([entry('m1')]))
    Importer.applyQuestionsReply(c, reply([entry('m1', { questions: [q(), q({ question: 'Second?' })] })]))
    expect(c.modules[0].questions).toHaveLength(2)
  })
  it('rejects text that is not JSON', () => {
    expect(Importer.applyQuestionsReply(course(), 'Sure! Here are some questions').errors[0]).toMatch(/No JSON/)
  })
})

describe('validateCourse', () => {
  it('passes a complete course', () => {
    const c = course(); c.modules.forEach(m => { m.questions = [q()] })
    expect(Importer.validateCourse(c)).toEqual([])
  })
  it('flags modules without questions and incomplete questions', () => {
    const c = course()
    c.modules[0].questions = [q({ options: ['a', 'b', 'c', ''] })]
    const errors = Importer.validateCourse(c).join(' ')
    expect(errors).toMatch(/Module 1.*4 non-empty options/)
    expect(errors).toMatch(/Module 2.*at least one question/)
  })
  it('flags a missing title', () => {
    const c = course(); c.title = ' '
    expect(Importer.validateCourse(c)[0]).toMatch(/needs a title/)
  })
})

describe('parseCourseJson (Claude full-course import)', () => {
  const full = (over = {}) => JSON.stringify({ title: 'T', modules: [{ title: 'M', content: 'Body', questions: [q()] }], ...over })
  it('parses a valid course', () => {
    const { course: c, errors } = Importer.parseCourseJson(full())
    expect(errors).toEqual([])
    expect(c.modules[0].questions[0].correct_index).toBe(1)
  })
  it('reports problems per module', () => {
    const { errors } = Importer.parseCourseJson(full({ modules: [{ title: 'M', content: '', questions: [] }] }))
    expect(errors.join(' ')).toMatch(/missing "content"/)
    expect(errors.join(' ')).toMatch(/no questions/)
  })
  it('rejects non-JSON', () => {
    expect(Importer.parseCourseJson('hello').course).toBeNull()
  })
})
