import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { parseAst } from 'rollup/parseAst'

// Static scan of every HTML template literal in js/: each ${…} must be escaped (esc), numeric, a literal, a
// ternary of safe parts, or an already-built HTML fragment. Inside a JS string in an inline handler
// (onclick="f('${…}')") only escJs() is safe: esc() output is decoded by the browser before the JS runs.

const dir = fileURLToPath(new URL('../../js/', import.meta.url))

// Reviewed expressions that are HTML fragments built elsewhere in js/ (those templates are scanned too),
// numbers, or constants from code. Keyed by file. Add an entry only after checking where the value comes from.
const REVIEWED = {
  'admin.js': ['teamName', 'icon', 'value', 'label', 'unassigned', 'role', 'expires', 'created', 'statusChip', 'opts', 'attrs', 'dir', 'enrollBadge', 'secOpts', 'teamHtml', 'roleChip'],
  'app.js': ['qCount'],
  'builder.js': ['g.label', 'name', 'label', 'meta', 'letter', 'courseIcon(e)', 't'],
  'celebrate.js': ['on', 'html', 'cls', 'Celebrate.RING_LEN', 'stats', 'm.correct', 'm.total', 'passMark', 'gap', 'list'],
  'certificate.js': ['size', 'd'],
  'core.js': ['fontUrl', 'body', 'chip', 'date'],
  'demo.js': ['other'],
  'importer.js': ['done', 'words', 'wc', 'oi', 'letters[oi]'],
  'learner.js': ['modCount', 'n', 'pct', 'attrs', 'desc', 'bar', 'chip', 'cta', 'dueStr', 'readMin', 'sourceBanner', 'overviewCard', 'letters[i]', 'nextFn', 'nextLabel', 'correct', 'a.course_id', 'iconOf(r.course_id)'],
  'manager.js': ['attrs', 'n', 'd', 'v', 'l'],
  'markdown.js': ['tag', 'attrs'],
  'sections.js': ['cls', 'extra'],
}

const isLiteral = (n) => n.type === 'Literal' || (n.type === 'TemplateLiteral' && n.expressions.length === 0)
const SAFE_TEXT = /^(esc|escJs|Number|Math\.\w+|courseIcon|\w*Html|\w*Chip|\w+Badge)\(|\.length$|\.id$|^\w*Html$|^(i|j|k|mi|qi|gi|ui|fi|tid|id|idx|page|count|total\w*|totalPages|totalCount|modsDone|totalMods|pct|score)$|^ICON\.|_ico\.|^\w+\.(learner_count|manager_count|score|failure_rate|pass_rate|overdue_count|completion_count|use_count|assignment_count|correct_index)$/

// Helpers that return finished HTML and escape their own inputs (checked when they were reviewed).
const HELPER_CALL = /^(_ringHtml|_soundToggleHtml|courseCheckbox|chipsHtml|gridHtml)$/
const callName = (c) => (c.type === 'MemberExpression' ? c.property.name : c.name)

function scan(file) {
  const src = readFileSync(dir + file, 'utf8')
  const text = (n) => src.slice(n.start, n.end)
  const lineOf = (n) => src.slice(0, n.start).split('\n').length
  const reviewed = new Set(REVIEWED[file] || [])
  const bad = []

  const safeValue = (e) => {
    const t = text(e)
    if (isLiteral(e) || e.type === 'NewExpression' || e.type === 'UnaryExpression') return true
    if (e.type === 'BinaryExpression') return ['+', '-', '*', '/', '%'].includes(e.operator) ? safeValue(e.left) && safeValue(e.right) : true
    if (e.type === 'ConditionalExpression') return safeValue(e.consequent) && safeValue(e.alternate)
    if (e.type === 'LogicalExpression') return safeValue(e.left) && safeValue(e.right)
    if (e.type === 'TemplateLiteral') return e.expressions.every(safeValue)
    if (e.type === 'CallExpression' && e.callee.type === 'MemberExpression' && ['map', 'join', 'toLocaleDateString', 'toFixed'].includes(e.callee.property.name)) return true
    if (e.type === 'CallExpression' && HELPER_CALL.test(callName(e.callee))) return true
    return SAFE_TEXT.test(t) || reviewed.has(t)
  }

  const check = (node) => {
    if (!node || typeof node.type !== 'string') return
    if (node.type === 'TemplateLiteral' && !node.quasis.some((q) => q.value.raw.includes('<'))) {
      // Handler code built outside markup (onclick="${handler}"): a quoted argument must still go through escJs().
      node.expressions.forEach((e, i) => {
        if (/[(,]\s*'$/.test(node.quasis[i].value.raw) && !/^escJs\(/.test(text(e)) && !isLiteral(e) && !reviewed.has(text(e))) bad.push(`${file}:${lineOf(e)} [handler argument] \${${text(e).slice(0, 80)}}`)
      })
    }
    if (node.type === 'TemplateLiteral' && node.quasis.some((q) => q.value.raw.includes('<'))) {
      let before = ''
      node.expressions.forEach((e, i) => {
        before += node.quasis[i].value.raw
        const tag = before.slice(before.lastIndexOf('<'))
        const handler = tag.match(/\son[a-z]+="([^"]*)$/)
        const inJsString = handler && (handler[1].match(/'/g) || []).length % 2 === 1
        const ok = inJsString ? /^escJs\(/.test(text(e)) : safeValue(e)
        if (!ok) bad.push(`${file}:${lineOf(e)} ${inJsString ? '[inline handler string] ' : ''}\${${text(e).replace(/\s+/g, ' ').slice(0, 80)}}`)
        before += '\u0000'
      })
    }
    for (const k of Object.keys(node)) {
      const v = node[k]
      if (Array.isArray(v)) v.forEach(check)
      else if (v && typeof v === 'object') check(v)
    }
  }
  check(parseAst(src))
  return bad
}

describe('HTML templates in js/', () => {
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.js'))) {
    it(`${file}: every interpolation is escaped, numeric or reviewed`, () => {
      expect(scan(file)).toEqual([])
    })
  }

  it('escJs output cannot end a quoted handler string or attribute', () => {
    const src = readFileSync(dir + 'core.js', 'utf8')
    const escJs = new Function(src.match(/function escJs[^\n]*/)[0] + '\nreturn escJs;')()
    for (const hostile of ["x');alert(1)//", '"><img src=x onerror=alert(1)>', '\\', 'a\nb', '\u2028', '😀']) {
      const out = escJs(hostile)
      expect(out, hostile).not.toMatch(/['"<>&\\](?!u[0-9a-f]{4})|\n|\u2028/)
      expect(new Function(`return '${out}'`)(), hostile).toBe(hostile)
    }
  })
})
