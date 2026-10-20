// Token-literal lint: raw colour literals (hex, rgb/rgba, hsl) outside token definitions
// must not grow. Counts are ratcheted against scripts/token-baseline.json; lower them as
// literals migrate to tokens (run with --update after a reduction).
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'

const FILES = ['css/style.css', 'index.html', ...readdirSync('js').filter((f) => f.endsWith('.js')).sort().map((f) => `js/${f}`)]
const LITERAL = /#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/g
const BASELINE = new URL('./token-baseline.json', import.meta.url)

function count(file) {
  let n = 0
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    // `--token: value` lines are definitions, which is where literals belong
    if (/^\s*--[\w-]+\s*:/.test(line) && file.endsWith('.css')) continue
    n += (line.match(LITERAL) || []).length
  }
  return n
}

const counts = Object.fromEntries(FILES.map((f) => [f, count(f)]))

if (process.argv.includes('--update')) {
  writeFileSync(BASELINE, JSON.stringify(counts, null, 2) + '\n')
  console.log('Baseline updated.')
  process.exit(0)
}

const baseline = JSON.parse(readFileSync(BASELINE, 'utf8'))
let failed = false
for (const f of FILES) {
  const allowed = baseline[f] ?? 0
  if (counts[f] > allowed) {
    console.error(`${f}: ${counts[f]} raw colour literals (baseline ${allowed}). Use a design token from css/style.css.`)
    failed = true
  } else if (counts[f] < allowed) {
    console.log(`${f}: ${counts[f]} literals, down from ${allowed}. Run "node scripts/check-tokens.mjs --update" to lock it in.`)
  }
}
const total = Object.values(counts).reduce((a, b) => a + b, 0)
console.log(`Token lint: ${total} legacy literals remain (target 0).`)
process.exit(failed ? 1 : 0)
