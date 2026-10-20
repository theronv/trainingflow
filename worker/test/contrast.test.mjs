import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// Only top-level :root / [data-theme="light"] rules are read; tokens redefined inside @media blocks are not seen.
// Resolves the effective colour tokens for each theme from css/style.css and checks
// WCAG 2.2 AA contrast for the text/background pairs the UI actually uses.
const css = readFileSync(fileURLToPath(new URL('../../css/style.css', import.meta.url)), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '')

const SELECTOR_THEME = {
  ':root': ['dark', 'light'],
  '[data-theme="light"]': ['light'],
  ':root:not([data-theme="light"])': ['dark'],
}

function collectTokens() {
  const themes = { dark: {}, light: {} }
  let depth = 0
  let selector = ''
  let body = ''
  for (const ch of css) {
    if (ch === '{') {
      depth++
      if (depth === 1) { selector = body.trim(); body = ''; continue }
    } else if (ch === '}') {
      if (depth === 1) {
        for (const theme of SELECTOR_THEME[selector] || []) {
          for (const m of body.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
            // light is dark plus [data-theme="light"] overrides, so a plain :root rule hits both
            themes[theme][m[1]] = m[2].trim()
          }
        }
        body = ''
        depth--
        continue
      }
      depth--
    }
    if (depth === 0) { body += ch; continue }
    if (depth === 1) body += ch
  }
  return themes
}

function resolve(tokens, name, seen = new Set()) {
  let v = tokens[name]
  if (v === undefined || seen.has(name)) return undefined
  seen.add(name)
  const ref = v.match(/^var\((--[\w-]+)\)$/)
  return ref ? resolve(tokens, ref[1], seen) : v
}

function parseColor(value) {
  const hex = value.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/i)
  if (!hex) return null
  let h = hex[1]
  if (h.length === 3) h = [...h].map((c) => c + c).join('')
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16))
}

function luminance([r, g, b]) {
  const lin = [r, g, b].map((c) => { const s = c / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4 })
  return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]
}

function ratio(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

const THEMES = collectTokens()
const SURFACES = ['--bg', '--bg-2', '--surface', '--surface-2']
// --ink-4 is the disabled/placeholder tier and is exempt from AA by WCAG (inactive components).
const TEXT = ['--ink-1', '--ink-2', '--ink-3', '--accent', '--accent-strong']

describe.each(['dark', 'light'])('%s theme contrast (WCAG AA 4.5:1)', (theme) => {
  const tokens = THEMES[theme]
  const merged = theme === 'light' ? { ...THEMES.dark, ...THEMES.light } : tokens
  for (const fg of TEXT) {
    for (const bg of SURFACES) {
      it(`${fg} on ${bg}`, () => {
        const f = parseColor(resolve(merged, fg) ?? '')
        const b = parseColor(resolve(merged, bg) ?? '')
        expect(f, `${fg} must resolve to a hex colour`).not.toBeNull()
        expect(b, `${bg} must resolve to a hex colour`).not.toBeNull()
        expect(ratio(f, b)).toBeGreaterThanOrEqual(4.5)
      })
    }
  }
})
