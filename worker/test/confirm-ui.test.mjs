import { describe, it, expect, beforeEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// js/confirm.js is a browser global script; evaluate it against a minimal fake DOM.
const src = readFileSync(fileURLToPath(new URL('../../js/confirm.js', import.meta.url)), 'utf8')
const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

let overlay, focused, listeners, opener
function makeButton(kind) {
  return { dataset: { confirm: kind }, focus() { focused = kind } }
}
function setup() {
  focused = null
  listeners = {}
  opener = { focus() { focused = 'opener' } }
  const buttons = { cancel: makeButton('cancel'), ok: makeButton('ok') }
  overlay = null
  const document = {
    activeElement: opener,
    body: { appendChild(el) { overlay = el } },
    createElement() {
      const classes = new Set(['hidden'])
      return {
        id: '', className: '', _html: '',
        classList: { add: c => classes.add(c), remove: c => classes.delete(c), has: c => classes.has(c) },
        addEventListener(type, fn) { listeners[type] = fn },
        set innerHTML(v) { this._html = v },
        get innerHTML() { return this._html },
        querySelector(sel) { return buttons[/"(\w+)"/.exec(sel)[1]] },
        querySelectorAll() { return [buttons.cancel, buttons.ok] },
      }
    },
  }
  const $$ = () => overlay
  return new Function('document', 'esc', '$$', `${src}\nreturn { Confirm, confirmMarkup };`)(document, esc, $$)
}

describe('confirmMarkup', () => {
  let confirmMarkup
  beforeEach(() => { ({ confirmMarkup } = setup()) })
  it('escapes title and body', () => {
    const html = confirmMarkup({ title: '<b>x</b>', body: 'a "q" & b' })
    expect(html).not.toContain('<b>x</b>')
    expect(html).toContain('&lt;b&gt;x&lt;/b&gt;')
    expect(html).toContain('a &quot;q&quot; &amp; b')
  })
  it('uses danger styling only when asked', () => {
    expect(confirmMarkup({ title: 't', body: 'b', danger: true })).toContain('btn btn-danger')
    expect(confirmMarkup({ title: 't', body: 'b' })).toContain('btn btn-primary')
  })
  it('labels both buttons', () => {
    const html = confirmMarkup({ title: 't', body: 'b', confirmLabel: 'Delete team', cancelLabel: 'Keep' })
    expect(html).toContain('>Delete team<')
    expect(html).toContain('>Keep<')
  })
})

describe('Confirm.ask', () => {
  let Confirm
  beforeEach(() => { ({ Confirm } = setup()) })
  const click = kind => listeners.click({ target: { dataset: { confirm: kind } } })

  it('resolves true on confirm and hides the dialog', async () => {
    const p = Confirm.ask({ title: 't', body: 'b' })
    expect(overlay.classList.has('hidden')).toBe(false)
    click('ok')
    expect(await p).toBe(true)
    expect(overlay.classList.has('hidden')).toBe(true)
  })
  it('resolves false on cancel, backdrop click and cancel()', async () => {
    let p = Confirm.ask({ title: 't', body: 'b' }); click('cancel'); expect(await p).toBe(false)
    p = Confirm.ask({ title: 't', body: 'b' }); listeners.click({ target: overlay }); expect(await p).toBe(false)
    p = Confirm.ask({ title: 't', body: 'b' }); Confirm.cancel(); expect(await p).toBe(false)
  })
  it('focuses Cancel for danger dialogs and Confirm otherwise', () => {
    Confirm.ask({ title: 't', body: 'b', danger: true }); expect(focused).toBe('cancel')
    Confirm.cancel()
    Confirm.ask({ title: 't', body: 'b' }); expect(focused).toBe('ok')
  })
  it('returns focus to the opener when closed', async () => {
    const p = Confirm.ask({ title: 't', body: 'b', danger: true })
    click('cancel'); await p
    expect(focused).toBe('opener')
  })
  it('cancels a pending dialog when a new one opens', async () => {
    const first = Confirm.ask({ title: 'one', body: 'b' })
    const second = Confirm.ask({ title: 'two', body: 'b' })
    expect(await first).toBe(false)
    click('ok')
    expect(await second).toBe(true)
  })
})
