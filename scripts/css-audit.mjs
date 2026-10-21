// CSS audit for css/style.css (no dependencies, no browser).
//
//   node scripts/css-audit.mjs            report dead declarations, dead rules, unused tokens/keyframes
//   node scripts/css-audit.mjs --fix      remove them in place, then verify the cascade is unchanged
//   node scripts/css-audit.mjs --merge    fold duplicate selectors into their last definition where provably safe
//
// "Dead" means provably unreachable:
//   - a declaration overridden by a later rule with the identical selector and media context
//   - a rule (or selector-list member) whose classes appear nowhere in index.html or js/
//   - a custom property or @keyframes nothing references
// resolveCascade() fingerprints the final value of every (media, selector, property), which is
// how --fix proves it removed nothing that was winning.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const ROOT = new URL('../', import.meta.url)

// Documented utilities and tokens that are kept even though nothing renders them yet.
const KEEP_CLASSES = new Set(['sr-only', 'tabular', 'mono', 'hidden'])
// Design-system tokens named in CLAUDE.md/README even where nothing uses them yet.
const KEEP_TOKENS = new Set(['--text-3xl', '--space-16', '--warn', '--warn-lt', '--warn-border'])
// A later declaration using one of these may be a progressive enhancement over an earlier
// fallback (e.g. 100vh then 100dvh), so the earlier one is not dead.
const ENHANCED_VALUE = /\d(?:dvh|svh|lvh|dvw|svw|lvw)\b|\benv\(|\bclamp\(|\bmin\(|\bmax\(|color-mix\(|oklch\(|\blab\(|\blch\(/

const maskComments = (src) => src.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))

function splitDeclarations(masked, bodyStart, bodyEnd) {
  const decls = []
  let segStart = bodyStart, depth = 0, quote = null
  const flush = (end, hasSemicolon) => {
    const raw = masked.slice(segStart, end)
    const colon = raw.indexOf(':')
    if (colon > -1 && raw.trim()) {
      const lead = raw.length - raw.trimStart().length
      const valueRaw = raw.slice(colon + 1).trim()
      decls.push({
        prop: raw.slice(lead, colon).trim(),
        value: valueRaw.replace(/\s*!important\s*$/, '').replace(/\s+/g, ' '),
        important: /!important\s*$/.test(valueRaw),
        start: segStart + lead,
        end: hasSemicolon ? end + 1 : end,
      })
    }
    segStart = end + 1
  }
  for (let i = bodyStart; i < bodyEnd; i++) {
    const ch = masked[i]
    if (quote) { if (ch === quote) quote = null; continue }
    if (ch === '"' || ch === "'") quote = ch
    else if (ch === '(') depth++
    else if (ch === ')') depth--
    else if (ch === ';' && depth === 0) flush(i, true)
  }
  flush(bodyEnd, false)
  return decls
}

/** Flat list of rules with source offsets. `ctx` is the enclosing at-rule chain ('' at top level). */
export function parseCss(src) {
  const masked = maskComments(src)
  const rules = []
  let i = 0
  const lineOf = (pos) => masked.slice(0, pos).split('\n').length

  function readBlock(ctx) {
    while (i < masked.length) {
      while (i < masked.length && /\s/.test(masked[i])) i++
      if (masked[i] === '}') { i++; return }
      if (i >= masked.length) return
      const ruleStart = i
      let depth = 0, quote = null
      while (i < masked.length && (masked[i] !== '{' || depth || quote)) {
        const ch = masked[i]
        if (quote) { if (ch === quote) quote = null } else if (ch === '"' || ch === "'") quote = ch
        else if (ch === '(') depth++
        else if (ch === ')') depth--
        i++
      }
      const selEnd = i
      const selector = masked.slice(ruleStart, selEnd).trim().replace(/\s+/g, ' ')
      i++
      if (/^@(media|supports|layer|container)/.test(selector)) {
        readBlock(ctx ? `${ctx} | ${selector}` : selector)
        continue
      }
      const bodyStart = i
      let d = 1
      while (i < masked.length && d) { if (masked[i] === '{') d++; else if (masked[i] === '}') d--; i++ }
      const bodyEnd = i - 1
      const atomic = /^@(keyframes|font-face)/.test(selector)
      rules.push({
        ctx, selector, ruleStart, selStart: ruleStart, selEnd, ruleEnd: i,
        line: lineOf(ruleStart), atomic,
        decls: atomic ? [] : splitDeclarations(masked, bodyStart, bodyEnd),
      })
    }
  }
  readBlock('')
  return rules
}

const groupKey = (r) => `${r.ctx}||${r.selector}`

/** Declarations overridden by a later rule with the same selector and media context. */
export function findDeadDeclarations(rules) {
  const groups = new Map()
  for (const r of rules) if (!r.atomic) (groups.get(groupKey(r)) || groups.set(groupKey(r), []).get(groupKey(r))).push(r)
  const dead = []
  for (const group of groups.values()) {
    for (let a = 0; a < group.length - 1; a++) {
      for (const decl of group[a].decls) {
        if (decl.important || /^-(?:webkit|moz|ms|o)-/.test(decl.prop)) continue
        const later = group.slice(a + 1).flatMap((r) => r.decls).filter((x) => x.prop === decl.prop)
        if (!later.length) continue
        if (later.some((x) => decl.value !== x.value && ENHANCED_VALUE.test(x.value))) continue
        dead.push({ rule: group[a], decl })
      }
    }
  }
  return dead
}

const stripPseudoArgs = (selector) => selector.replace(/:(?:not|is|where|has)\([^)]*\)/g, '')
const classesOf = (selector) => [...stripPseudoArgs(selector).matchAll(/\.([A-Za-z_][\w-]*)/g)].map((m) => m[1])

/** True when the class appears in index.html/js, is a kept utility, or is built from a `prefix-${…}` pattern. */
export function makeClassLiveness(corpus) {
  return (cls) => {
    if (KEEP_CLASSES.has(cls) || corpus.includes(cls)) return true
    const parts = cls.split('-')
    for (let k = 1; k < parts.length; k++) {
      const prefix = parts.slice(0, k).join('-')
      if (corpus.includes(`${prefix}-\${`) || corpus.includes(`'${prefix}-'`) || corpus.includes(`"${prefix}-"`)) return true
    }
    return false
  }
}

/** Rules that can never match (all members dead), and selector lists with some dead members to trim. */
export function findDeadRules(rules, isLive) {
  const memberDead = (member) => classesOf(member).some((c) => !isLive(c))
  const dead = [], trim = [], deadMembers = new Set()
  for (const r of rules) {
    if (r.atomic || r.selector.startsWith('@')) continue
    const members = selectorMembers(r.selector)
    const deadList = members.filter(memberDead)
    if (!deadList.length) continue
    deadList.forEach((m) => deadMembers.add(`${r.ctx}||${m}`))
    if (deadList.length === members.length) dead.push(r)
    else trim.push({ rule: r, keep: members.filter((m) => !memberDead(m)) })
  }
  return { dead, trim, deadMembers }
}

export function findUnusedKeyframes(src, rules) {
  return rules
    .filter((r) => r.atomic && r.selector.startsWith('@keyframes'))
    .filter((r) => !new RegExp(`animation[^;}]*\\b${r.selector.split(' ')[1]}\\b`).test(src))
}

/** Custom properties defined in CSS that no var(), stylesheet value or script mentions. */
export function findUnusedTokens(src, corpus) {
  const defined = new Set([...maskComments(src).matchAll(/(--[\w-]+)\s*:/g)].map((m) => m[1]))
  return [...defined].filter((t) => !KEEP_TOKENS.has(t) && !new RegExp(`var\\(${t}\\b`).test(src) && !corpus.includes(t))
}

const selectorMembers = (selector) => selector.split(/,(?![^(]*\))/).map((m) => m.trim())

/** Final value of every (media context, selector member, property), in document order. */
export function resolveCascade(src) {
  const resolved = new Map()
  for (const r of parseCss(src)) {
    if (r.atomic) { resolved.set(`${r.ctx}||${r.selector}`, 'atomic'); continue }
    for (const member of selectorMembers(r.selector)) {
      for (const d of r.decls) {
        const key = `${r.ctx}||${member}||${d.prop}`
        if (resolved.get(key)?.endsWith('!important') && !d.important) continue
        resolved.set(key, d.important ? `${d.value} !important` : d.value)
      }
    }
  }
  return resolved
}

function lineSpan(src, start, end) {
  const lineStart = src.lastIndexOf('\n', start - 1) + 1
  const tail = src.slice(end).match(/^[ \t]*\n/)
  if (src.slice(lineStart, start).trim() === '' && tail) return [lineStart, end + tail[0].length]
  return [start, end + (src.slice(end).match(/^[ \t]+/)?.[0].length ?? 0)]
}

/** Apply all removals and return the new stylesheet. */
export function applyFixes(src, { rules, deadDecls, deadRules, trims, keyframes, tokens }) {
  const edits = []
  const claimed = new Set()
  const removedRules = new Set()
  const removeRule = (r) => { removedRules.add(r); edits.push(lineSpan(src, r.ruleStart, r.ruleEnd)) }
  deadRules.forEach(removeRule)
  keyframes.forEach(removeRule)

  const deadByRule = new Map()
  for (const { rule, decl } of deadDecls) {
    if (removedRules.has(rule)) continue
    deadByRule.set(rule, [...(deadByRule.get(rule) || []), decl])
  }
  for (const [rule, decls] of deadByRule) {
    if (decls.length === rule.decls.length) { removeRule(rule); continue }
    decls.forEach((d) => { claimed.add(d); edits.push(lineSpan(src, d.start, d.end)) })
  }
  for (const { rule, keep } of trims) {
    if (!removedRules.has(rule)) edits.push([rule.selStart, rule.selEnd, keep.join(', ') + ' '])
  }
  for (const r of rules) {
    if (r.atomic || removedRules.has(r)) continue
    for (const d of r.decls) if (tokens.includes(d.prop) && !claimed.has(d)) edits.push(lineSpan(src, d.start, d.end))
  }

  let out = src
  for (const [start, end, text = ''] of edits.sort((a, b) => b[0] - a[0])) out = out.slice(0, start) + text + out.slice(end)
  // At-rules left with nothing inside
  for (let prev = ''; prev !== out;) { prev = out; out = out.replace(/@(?:media|supports)[^{}]*\{\s*\}\s*\n?/g, '') }
  return out.replace(/[ \t]+$/gm, '').replace(/\n{3,}/g, '\n\n')
}

// ---- Batch 3: merge duplicate rules in place -------------------------------------------------
// Specificity as [ids, classes/attributes/pseudo-classes, elements/pseudo-elements].
export function specificity(member) {
  let s = member.replace(/\[[^\]]*\]/g, '.a')
  const spec = [0, 0, 0]
  const add = (x) => x.forEach((n, i) => { spec[i] += n })
  s = s.replace(/:(not|is|has)\(([^)]*)\)/g, (_, _fn, args) => {
    const inner = args.split(',').map((m) => specificity(m.trim()))
    add(inner.sort((a, b) => b[0] - a[0] || b[1] - a[1] || b[2] - a[2])[0])
    return ''
  })
  s = s.replace(/:where\([^)]*\)/g, '')
  s = s.replace(/::[\w-]+|:(?:before|after|first-line|first-letter)\b/g, () => { spec[2]++; return '' })
  s = s.replace(/#[\w-]+/g, () => { spec[0]++; return '' })
  s = s.replace(/\.[\w-]+|:[\w-]+(?:\([^)]*\))?/g, () => { spec[1]++; return '' })
  s = s.replace(/[>+~*]/g, ' ')
  spec[2] += s.split(/\s+/).filter((t) => /^[a-zA-Z][\w-]*$/.test(t)).length
  return spec
}
const specKey = (member) => specificity(member).join(',')

// Properties that can interact: same name, or the same family (margin / margin-top, border / border-color…).
const FAMILY_OVERRIDES = {
  top: 'inset', right: 'inset', bottom: 'inset', left: 'inset',
  'row-gap': 'gap', 'column-gap': 'gap', 'grid-gap': 'gap',
  width: 'size', height: 'size', 'inline-size': 'size', 'block-size': 'size',
  'line-height': 'font', columns: 'column',
  'place-items': 'items', 'align-items': 'items', 'justify-items': 'items',
  'place-content': 'content', 'align-content': 'content', 'justify-content': 'content',
  'place-self': 'self', 'align-self': 'self', 'justify-self': 'self',
}
const propFamily = (prop) => {
  if (prop.startsWith('--')) return prop
  const bare = prop.replace(/^-(?:webkit|moz|ms)-/, '')
  return FAMILY_OVERRIDES[bare] ?? bare.split('-')[0]
}

/**
 * Every pair of declarations whose relative order can change the result: related properties in two
 * rules whose selectors can tie on specificity (same importance). Returned as sortable position pairs.
 */
export function orderPairs(src) {
  const rules = parseCss(src).filter((r) => !r.atomic)
  const seen = new Map()
  const decls = []
  rules.forEach((r, ri) => {
    const members = selectorMembers(r.selector).map(specKey)
    r.decls.forEach((d, di) => {
      const base = `${r.ctx}||${r.selector}||${d.prop}`
      const n = seen.get(base) ?? 0
      seen.set(base, n + 1)
      decls.push({ id: `${base}||${n}`, pos: ri * 1e4 + di, rule: ri, important: d.important, family: propFamily(d.prop), specs: new Set(members) })
    })
  })
  const buckets = new Map()
  for (const d of decls) for (const sp of d.specs) {
    const key = `${d.family}|${d.important}|${sp}`
    ;(buckets.get(key) || buckets.set(key, []).get(key)).push(d)
  }
  const pairs = new Map()
  for (const list of buckets.values()) {
    for (let a = 0; a < list.length; a++) for (let b = a + 1; b < list.length; b++) {
      const [x, y] = list[a].pos < list[b].pos ? [list[a], list[b]] : [list[b], list[a]]
      if (x.rule !== y.rule || x.id !== y.id) pairs.set(`${x.id} < ${y.id}`, true)
    }
  }
  return { pairs, decls }
}

/** Order-sensitive pairs (equal specificity, related properties) whose relative order differs between two stylesheets. */
export function orderDrift(before, after) {
  const pos = (src) => new Map(orderPairs(src).decls.map((d) => [d.id, d.pos]))
  const posAfter = pos(after)
  const posBefore = pos(before)
  const drift = []
  for (const key of orderPairs(before).pairs.keys()) {
    const [x, y] = key.split(' < ')
    if (!posAfter.has(x) || !posAfter.has(y)) continue
    if (posAfter.get(x) >= posAfter.get(y) && posBefore.get(x) < posBefore.get(y)) drift.push(key)
  }
  return drift
}

/**
 * Duplicate selectors (same media context) whose earlier rules can be folded into the last one.
 * A declaration moves only if no rule in between could tie it on specificity for a related property.
 */
export function findMerges(rules, src) {
  // Rules carrying comments stay put so no explanatory comment is orphaned or dropped.
  const indexed = rules.map((r, i) => ({ r, i })).filter(({ r }) => !r.atomic)
  const groups = new Map()
  for (const e of indexed) (groups.get(groupKey(e.r)) || groups.set(groupKey(e.r), []).get(groupKey(e.r))).push(e)
  const merges = [], manual = []
  for (const group of groups.values()) {
    if (group.length < 2) continue
    const last = group[group.length - 1]
    const specs = new Set(selectorMembers(last.r.selector).map(specKey))
    for (const from of group.slice(0, -1)) {
      if (src.slice(from.r.ruleStart, from.r.ruleEnd).includes('/*')) continue
      for (const decl of from.r.decls) {
        const family = propFamily(decl.prop)
        const blockers = indexed.filter(({ r, i }) => i > from.i && i < last.i && r !== from.r && r.decls.some((x) =>
          propFamily(x.prop) === family && x.important === decl.important
          && selectorMembers(r.selector).some((m) => specs.has(specKey(m)))))
        const lastClash = last.r.decls.some((x) => x.prop === decl.prop)
        if (decl.important || lastClash || blockers.length) {
          manual.push({ rule: from.r, decl, reason: decl.important ? 'important' : lastClash ? 'same property in last rule' : `ordering vs line ${blockers[0].r.line}` })
        } else merges.push({ from: from.r, to: last.r, decl })
      }
    }
  }
  return { merges, manual }
}

/** Fold merged declarations into the start of the last rule's body and drop rules left empty. */
export function applyMerges(src, merges) {
  const byTarget = new Map(), byFrom = new Map(), claimed = new Set()
  for (const m of merges) {
    byTarget.set(m.to, [...(byTarget.get(m.to) || []), m])
    byFrom.set(m.from, [...(byFrom.get(m.from) || []), m])
    claimed.add(m.decl)
  }
  const edits = []
  for (const [rule, list] of byFrom) {
    if (list.length === rule.decls.length) edits.push(lineSpan(src, rule.ruleStart, rule.ruleEnd))
    else list.forEach((m) => edits.push(lineSpan(src, m.decl.start, m.decl.end)))
  }
  for (const [rule, list] of byTarget) {
    const open = src.indexOf('{', rule.selEnd) + 1
    const oneLine = !src.slice(rule.ruleStart, rule.ruleEnd).includes('\n')
    const declText = (d) => src.slice(d.start, d.end).replace(/;?$/, ';')
    // Token definitions stay one per line (the token lint exempts only lines that start with `--`)
    if (oneLine && list.some((m) => m.decl.prop.startsWith('--'))) {
      const close = rule.ruleEnd - 1
      const body = [...list.map((m) => m.decl), ...rule.decls].map((d) => `\n  ${declText(d)}`).join('')
      edits.push([open, close, `${body}\n`])
      continue
    }
    const text = list.map((m) => `${oneLine ? ' ' : '\n  '}${declText(m.decl)}`).join('')
    edits.push([open, open, text])
  }
  let out = src
  for (const [start, end, text = ''] of edits.sort((a, b) => b[0] - a[0] || b[1] - a[1])) out = out.slice(0, start) + text + out.slice(end)
  for (let prev = ''; prev !== out;) { prev = out; out = out.replace(/@(?:media|supports)[^{}]*\{\s*\}\s*\n?/g, '') }
  return out.replace(/[ \t]+$/gm, '').replace(/\n{3,}/g, '\n\n')
}

export function audit(src, corpus) {
  const rules = parseCss(src)
  const { dead, trim, deadMembers } = findDeadRules(rules, makeClassLiveness(corpus))
  return {
    rules,
    deadDecls: findDeadDeclarations(rules),
    deadRules: dead,
    trims: trim,
    deadMembers,
    keyframes: findUnusedKeyframes(src, rules),
    tokens: findUnusedTokens(src, corpus),
  }
}

export function loadCorpus() {
  const read = (rel) => readFileSync(new URL(rel, ROOT), 'utf8')
  return [read('index.html'), ...readdirSync(new URL('js/', ROOT)).filter((f) => f.endsWith('.js')).map((f) => read(`js/${f}`))].join('\n')
}

/** Keys whose value changed or vanished, ignoring what the audit said it was removing. */
export function cascadeDrift(before, after, found) {
  const removedKeyframes = new Set(found.keyframes.map(groupKey))
  const removedTokens = new Set(found.tokens)
  const afterMap = resolveCascade(after)
  const drift = []
  for (const [key, value] of resolveCascade(before)) {
    const [ctx, member, prop] = key.split('||')
    if (found.deadMembers.has(`${ctx}||${member}`) || removedKeyframes.has(`${ctx}||${member}`) || removedTokens.has(prop)) continue
    if (afterMap.get(key) !== value) drift.push(key)
  }
  return drift
}

function main() {
  const cssPath = new URL('css/style.css', ROOT)
  const src = readFileSync(cssPath, 'utf8')
  const found = audit(src, loadCorpus())
  const lines = (rs) => rs.reduce((n, r) => n + src.slice(r.ruleStart, r.ruleEnd).split('\n').length, 0)
  console.log(`dead declarations: ${found.deadDecls.length}`)
  console.log(`dead rules:        ${found.deadRules.length} (${lines(found.deadRules)} lines)`)
  console.log(`selector lists to trim: ${found.trims.length}`)
  console.log(`unused keyframes:  ${found.keyframes.map((k) => k.selector).join(', ') || 'none'}`)
  console.log(`unused tokens:     ${found.tokens.join(' ') || 'none'}`)
  const { merges, manual } = findMerges(found.rules, src)
  console.log(`mergeable declarations: ${merges.length}; left for manual review: ${manual.length}`)
  if (process.argv.includes('--merge')) {
    const merged = applyMerges(src, merges)
    const drift = [...cascadeDrift(src, merged, { deadMembers: new Set(), keyframes: [], tokens: [] }), ...orderDrift(src, merged)]
    if (drift.length) {
      console.error(`Refusing to write: ${drift.length} resolved value(s) or tie orderings would change:\n  ${drift.slice(0, 10).join('\n  ')}`)
      process.exit(1)
    }
    writeFileSync(cssPath, merged)
    console.log(`css/style.css: ${src.split('\n').length} -> ${merged.split('\n').length} lines, cascade and tie order verified unchanged.`)
    return
  }
  if (!process.argv.includes('--fix')) return
  const fixed = applyFixes(src, found)
  const drift = cascadeDrift(src, fixed, found)
  if (drift.length) {
    console.error(`Refusing to write: ${drift.length} resolved value(s) would change:\n  ${drift.slice(0, 10).join('\n  ')}`)
    process.exit(1)
  }
  writeFileSync(cssPath, fixed)
  console.log(`css/style.css: ${src.split('\n').length} -> ${fixed.split('\n').length} lines, cascade verified unchanged.`)
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main()
