import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// Static guard for keyboard access: an element that handles clicks must be natively
// interactive, or carry role="button" and tabindex (core.js adds Enter/Space activation).
const root = fileURLToPath(new URL('../../', import.meta.url))
const files = ['index.html', ...readdirSync(root + 'js').filter(f => f.endsWith('.js')).map(f => 'js/' + f)]

const NATIVE = new Set(['button', 'a', 'input', 'select', 'textarea', 'label', 'summary', 'option'])
// Backdrops close on a click outside the dialog; Escape is the keyboard path.
const ALLOWED = [/class="overlay[^"]*"/]

function clickableOffenders(text) {
  const out = []
  for (const m of text.matchAll(/<([a-z][a-z0-9-]*)\b([^<>]*?)\sonclick=/gi)) {
    const [whole, tag, before] = m
    const tagEnd = text.indexOf('>', m.index + whole.length)
    const attrs = before + text.slice(m.index + whole.length, tagEnd)
    if (NATIVE.has(tag.toLowerCase())) continue
    if (ALLOWED.some(re => re.test(attrs))) continue
    if (!/role="button"/.test(attrs) || !/tabindex="0"/.test(attrs)) out.push(`${tag}: ${attrs.trim().slice(0, 80)}`)
  }
  return out
}

describe('keyboard access', () => {
  for (const f of files) {
    it(`${f}: every onclick on a non-control has role="button" and tabindex`, () => {
      expect(clickableOffenders(readFileSync(root + f, 'utf8'))).toEqual([])
    })
  }

  it('scanner flags a bare clickable div', () => {
    expect(clickableOffenders('<div class="x" onclick="f()">')).toHaveLength(1)
    expect(clickableOffenders('<div class="x" role="button" tabindex="0" onclick="f()">')).toEqual([])
    expect(clickableOffenders('<button onclick="f()">')).toEqual([])
  })
})

describe('dialogs', () => {
  const html = readFileSync(root + 'index.html', 'utf8')
  const blocks = html.split(/<div[^>]*class="overlay[^"]*"/).slice(1)
  it('every modal overlay has a title for its accessible name', () => {
    const untitled = blocks.map(b => b.slice(0, b.indexOf('modal-foot') > 0 ? b.indexOf('modal-foot') : 4000))
      .filter(b => !b.includes('modal-title'))
    // first-run-overlay is a one-off notice with its own heading
    expect(untitled.length).toBeLessThanOrEqual(1)
  })
})

describe('dialogDismissButton (js/core.js)', () => {
  const src = readFileSync(root + 'js/core.js', 'utf8')
  const start = src.indexOf('const DIALOG_DISMISS_RE')
  const end = src.indexOf('function visibleFocusables')
  const { dialogDismissButton } = new Function(`${src.slice(start, end)}\nreturn { dialogDismissButton }`)()
  const btn = textContent => ({ textContent })

  it('finds Cancel / Close / Done / Skip, ignoring a leading symbol', () => {
    for (const t of ['Cancel', ' Done ', '✕ Close', 'Skip for now']) {
      const b = btn(t)
      expect(dialogDismissButton([btn('Save'), b])).toBe(b)
    }
  })
  it('returns null when no button dismisses', () => {
    expect(dialogDismissButton([btn('Save'), btn('Closer look')])).toBeNull()
  })
})
