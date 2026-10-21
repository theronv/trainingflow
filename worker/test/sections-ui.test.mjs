import { describe, it, expect, beforeEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// js/sections.js is a browser global script; evaluate it with a stub localStorage/document.
const src = readFileSync(fileURLToPath(new URL('../../js/sections.js', import.meta.url)), 'utf8')
const store = new Map()
const localStorage = { getItem: k => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)) }
const foldAll = { disabled: false, textContent: '' }
const document = { getElementById: id => (id === 'a-fold-all' ? foldAll : null) }
const esc = s => String(s)
const escJs = s => String(s)
const { moveSectionOrder, SectionFold } = new Function('localStorage', 'document', 'esc', 'escJs',
  `${src}\nreturn { moveSectionOrder, SectionFold };`)(localStorage, document, esc, escJs)

// orderSections() output: parents first, each followed by its sub-sections.
const sec = (id, parent_id = null) => ({ id, parent_id, depth: parent_id ? 1 : 0 })
const ordered = [sec('A'), sec('a1', 'A'), sec('a2', 'A'), sec('B'), sec('b1', 'B'), sec('C')]

describe('moveSectionOrder', () => {
  it('moves a top-level section and carries its sub-sections with it', () => {
    expect(moveSectionOrder(ordered, 'B', -1)).toEqual(['B', 'b1', 'A', 'a1', 'a2', 'C'])
    expect(moveSectionOrder(ordered, 'A', 1)).toEqual(['B', 'b1', 'A', 'a1', 'a2', 'C'])
    expect(moveSectionOrder(ordered, 'C', -1)).toEqual(['A', 'a1', 'a2', 'C', 'B', 'b1'])
  })
  it('moves a sub-section only within its own parent', () => {
    expect(moveSectionOrder(ordered, 'a2', -1)).toEqual(['A', 'a2', 'a1', 'B', 'b1', 'C'])
    expect(moveSectionOrder(ordered, 'a1', 1)).toEqual(['A', 'a2', 'a1', 'B', 'b1', 'C'])
  })
  it('returns null at the ends, for an only child, and for unknown ids', () => {
    expect(moveSectionOrder(ordered, 'A', -1)).toBeNull()
    expect(moveSectionOrder(ordered, 'C', 1)).toBeNull()
    expect(moveSectionOrder(ordered, 'a1', -1)).toBeNull()
    expect(moveSectionOrder(ordered, 'a2', 1)).toBeNull()
    expect(moveSectionOrder(ordered, 'b1', -1)).toBeNull()
    expect(moveSectionOrder(ordered, 'b1', 1)).toBeNull()
    expect(moveSectionOrder(ordered, 'nope', 1)).toBeNull()
  })
  it('always returns every id exactly once', () => {
    const ids = moveSectionOrder(ordered, 'B', -1)
    expect([...ids].sort()).toEqual(ordered.map(s => s.id).sort())
  })
})

describe('SectionFold state', () => {
  beforeEach(() => store.clear())

  it('round-trips through localStorage and ignores junk', () => {
    SectionFold.save(new Set(['A', 'B']))
    expect([...SectionFold.load()].sort()).toEqual(['A', 'B'])
    store.set(SectionFold.KEY, '{not json')
    expect(SectionFold.load().size).toBe(0)
    store.set(SectionFold.KEY, JSON.stringify(['A', 3, null]))
    expect([...SectionFold.load()]).toEqual(['A'])
  })
  it('a collapsed parent hides its sub-sections', () => {
    const set = new Set(['A'])
    expect(SectionFold.isCollapsed(set, 'A', '')).toBe(true)
    expect(SectionFold.isCollapsed(set, 'a1', 'A')).toBe(true)
    expect(SectionFold.isCollapsed(set, 'B', '')).toBe(false)
    expect(SectionFold.isCollapsed(set, 'b1', 'B')).toBe(false)
  })
  it('escapes ids and titles in generated markup', () => {
    const html = SectionFold.headHtml({ cls: 'sec-head', id: 'x', title: 'T', count: '2 courses' })
    expect(html).toContain('data-sec-head="x"')
    expect(html).toContain('aria-expanded="true"')
    expect(html).toContain('2 courses')
    expect(SectionFold.attrs('a1', 'A')).toBe('data-sec="a1" data-sec-parent="A"')
    expect(SectionFold.attrs('B')).toBe('data-sec="B"')
  })
})

// Minimal fake DOM: heads and items with dataset/hidden, and a root that finds them.
function fakeRoot(heads, items) {
  const mk = (d) => ({ dataset: d, hidden: false, btn: { attr: {}, setAttribute(k, v) { this.attr[k] = v } }, querySelector() { return this.btn } })
  const hs = heads.map(([id, parent]) => mk({ secHead: id, ...(parent ? { secParent: parent } : {}) }))
  const is = items.map(([id, parent]) => mk({ sec: id, ...(parent ? { secParent: parent } : {}) }))
  return {
    hs, is, attrs: {},
    setAttribute(k, v) { this.attrs[k] = v },
    querySelectorAll(sel) { return sel === '[data-sec-head]' ? hs : is },
  }
}

describe('SectionFold.apply / toggleAll', () => {
  beforeEach(() => store.clear())
  const build = () => fakeRoot([['A'], ['a1', 'A'], ['B']], [['A'], ['a1', 'A'], ['B']])

  it('hides content of collapsed sections and sub-section headers under a collapsed parent', () => {
    SectionFold.save(new Set(['A']))
    const root = build(); SectionFold.apply(root)
    expect(root.is.map(e => e.hidden)).toEqual([true, true, false])
    expect(root.hs.map(h => h.hidden)).toEqual([false, true, false])
    expect(root.hs.map(h => h.btn.attr['aria-expanded'])).toEqual(['false', 'true', 'true'])
    expect(foldAll.textContent).toBe('Collapse all')
  })
  it('toggleAll collapses everything, then expands everything', () => {
    const root = build()
    SectionFold.toggleAll(root)
    expect([...SectionFold.load()].sort()).toEqual(['A', 'B', 'a1'])
    expect(root.is.every(e => e.hidden)).toBe(true)
    expect(foldAll.textContent).toBe('Expand all')
    SectionFold.toggleAll(root)
    expect(SectionFold.load().size).toBe(0)
    expect(root.is.every(e => !e.hidden)).toBe(true)
    expect(foldAll.textContent).toBe('Collapse all')
  })
  it('disables the fold-all button when there are no sections', () => {
    SectionFold.apply(fakeRoot([], []))
    expect(foldAll.disabled).toBe(true)
  })
})
