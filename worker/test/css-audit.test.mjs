import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { parseCss, audit, applyFixes, cascadeDrift, resolveCascade, loadCorpus } from '../../scripts/css-audit.mjs'

const live = (...classes) => classes.map((c) => `class="${c}"`).join(' ')

describe('css-audit on synthetic CSS', () => {
  it('finds a declaration overridden by a later rule with the same selector and media', () => {
    const src = '.a { color: red; margin: 0; }\n.b { color: blue; }\n.a { color: green; }\n'
    const found = audit(src, live('a', 'b'))
    expect(found.deadDecls.map((d) => d.decl.prop)).toEqual(['color'])
  })
  it('keeps declarations that differ by media context, !important, or a progressive enhancement', () => {
    const src = [
      '.a { color: red; }', '@media (max-width: 600px) { .a { color: blue; } }',
      '.b { color: red !important; }', '.b { color: blue; }',
      '.c { height: 100vh; }', '.c { height: 100dvh; }',
    ].join('\n')
    expect(audit(src, live('a', 'b', 'c')).deadDecls).toEqual([])
  })
  it('removes rules for classes nothing renders, trims mixed lists, and keeps dynamic and utility classes', () => {
    const src = '.gone { color: red; }\n.keep, .gone2 { color: blue; }\n.t-ok { color: green; }\n.sr-only { color: black; }\n'
    const corpus = `${live('keep')} \`toast t-\${type}\``
    const found = audit(src, corpus)
    expect(found.deadRules.map((r) => r.selector)).toEqual(['.gone'])
    expect(found.trims.map((t) => t.keep)).toEqual([['.keep']])
    const fixed = applyFixes(src, found)
    expect(fixed).toContain('.keep {')
    expect(fixed).toContain('.t-ok')
    expect(fixed).toContain('.sr-only')
    expect(fixed).not.toContain('.gone')
    expect(cascadeDrift(src, fixed, found)).toEqual([])
  })
  it('does not treat a class inside :not() as the rule target', () => {
    expect(audit('.a:not(.legacy) { color: red; }', live('a')).deadRules).toEqual([])
  })
  it('flags drift when a winning declaration disappears', () => {
    const before = '.a { color: red; }'
    const found = { deadMembers: new Set(), keyframes: [], tokens: [] }
    expect(cascadeDrift(before, '.a { }', found)).toEqual(['||.a||color'])
    expect(resolveCascade(before).get('||.a||color')).toBe('red')
  })
  it('removes unused custom properties and keyframes, and drops emptied at-rules', () => {
    const src = ':root { --used: 1px; --orphan: 2px; }\n.a { width: var(--used); }\n@keyframes spin { to { opacity: 1; } }\n@media print { .gone { color: red; } }\n'
    const found = audit(src, live('a'))
    expect(found.tokens).toEqual(['--orphan'])
    expect(found.keyframes.map((k) => k.selector)).toEqual(['@keyframes spin'])
    const fixed = applyFixes(src, found)
    expect(fixed).not.toMatch(/--orphan|keyframes|@media/)
    expect(fixed).toContain('--used: 1px')
  })
})

describe('css/style.css', () => {
  const src = readFileSync(fileURLToPath(new URL('../../css/style.css', import.meta.url)), 'utf8')
  const found = audit(src, loadCorpus())
  it('parses with balanced rules', () => {
    expect(parseCss(src).length).toBeGreaterThan(500)
  })
  it('has no dead declarations, dead rules, unused keyframes or unused tokens (run: node scripts/css-audit.mjs --fix)', () => {
    expect(found.deadDecls.map((d) => `${d.rule.line} ${d.rule.selector} ${d.decl.prop}`)).toEqual([])
    expect(found.deadRules.map((r) => `${r.line} ${r.selector}`)).toEqual([])
    expect(found.trims).toEqual([])
    expect(found.keyframes.map((k) => k.selector)).toEqual([])
    expect(found.tokens).toEqual([])
  })
})
