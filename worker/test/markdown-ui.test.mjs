import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

// js/markdown.js is a browser global script; esc() comes from core.js, so it is injected here.
const esc = (s) => String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
const src = readFileSync(fileURLToPath(new URL('../../js/markdown.js', import.meta.url)), 'utf8')
const load = (marked) => new Function('esc', 'marked', src + '\nreturn Markdown;')(esc, marked)
const Markdown = load(undefined)

describe('safeHref', () => {
  it('allows web, mail, phone, anchor and relative links', () => {
    for (const ok of ['https://a.test/x?y=1', 'http://a.test', 'mailto:a@b.test', 'tel:+15551234', '#top', '/path', 'assets/x.png', '../x', '?q=1']) {
      expect(Markdown.safeHref(ok)).toBe(ok)
    }
  })
  it('blocks script-capable schemes however they are disguised', () => {
    for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', ' javascript:alert(1)', 'java\tscript:alert(1)', 'java\nscript:alert(1)',
      '\u0001javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'vbscript:x', '&#106;avascript:alert(1)', 'javascript&colon;alert(1)', 'jav&#x61;script:alert(1)']) {
      expect(Markdown.safeHref(bad), bad).toBe('')
    }
  })
  it('allows only raster data: URLs for images', () => {
    expect(Markdown.safeHref('data:image/png;base64,AAAA', true)).toBe('data:image/png;base64,AAAA')
    expect(Markdown.safeHref('data:image/svg+xml;base64,AAAA', true)).toBe('')
    expect(Markdown.safeHref('data:image/png;base64,AAAA')).toBe('')
  })
})

describe('sanitize: what lessons need still works', () => {
  it('keeps tables, lists, emphasis, links and images', () => {
    const html = '<table><thead><tr><th colspan="2">H</th></tr></thead><tbody><tr><td>1</td><td>2</td></tr></tbody></table><ul><li><strong>a</strong></li></ul><p>x <em>y</em></p>'
    expect(Markdown.sanitize(html)).toBe(html)
  })
  it('keeps safe links (opening in a new tab) and images', () => {
    expect(Markdown.sanitize('<a href="https://a.test/x" title="T">go</a>')).toBe('<a href="https://a.test/x" title="T" target="_blank" rel="noopener noreferrer">go</a>')
    expect(Markdown.sanitize('<img src="assets/a.png" alt="shot" width="300">')).toBe('<img src="assets/a.png" alt="shot" width="300" loading="lazy">')
  })
  it('does not double-escape entities in text or attributes', () => {
    expect(Markdown.sanitize('<p>Tom &amp; Jerry &lt;3</p>')).toBe('<p>Tom &amp; Jerry &lt;3</p>')
    expect(Markdown.sanitize('<img src="a.png" alt="Tom &amp; Jerry">')).toContain('alt="Tom &amp; Jerry"')
  })
})

describe('sanitize: nothing can run', () => {
  const attack = (html) => {
    const out = Markdown.sanitize(html)
    expect(out, html).not.toMatch(/<\s*(script|style|iframe|object|embed|form|svg|math|link|meta|base|input|button|textarea|select)/i)
    expect(out, html).not.toMatch(/\son\w+\s*=/i)
    expect(out, html).not.toMatch(/javascript:/i)
    return out
  }
  it('drops event handlers and unknown tags', () => {
    expect(attack('<img src=x onerror=alert(1)>')).toBe('<img src="x" alt="" loading="lazy">')
    expect(attack('<p onclick="x()" style="position:fixed" class="a" id="b">hi</p>')).toBe('<p>hi</p>')
    attack('<svg onload=alert(1)><circle/></svg>')
    attack('<iframe src="https://evil.test"></iframe>')
    attack('<form action="https://evil.test"><input name=pw></form>')
  })
  it('keeps script text visible but inert', () => {
    expect(attack('<script>alert(1)</script>text')).toBe('alert(1)text')
  })
  it('neutralises javascript: and data: links and sources', () => {
    expect(attack('<a href="javascript:alert(1)">x</a>')).toBe('<a target="_blank" rel="noopener noreferrer">x</a>')
    expect(attack('<a href=" jAvAsCrIpT:alert(1)">x</a>')).not.toContain('href')
    expect(attack('<a href="java&#9;script:alert(1)">x</a>')).not.toContain('href')
    expect(attack('<img src="javascript:alert(1)">')).toBe('')
    expect(attack('<img src="data:text/html;base64,AAAA">')).toBe('')
  })
  it('escapes a stray < and survives malformed or nested tricks', () => {
    expect(Markdown.sanitize('1 < 2')).toBe('1 &lt; 2')
    expect(attack('<<script>script>alert(1)<</script>/script>')).not.toContain('<script')
    const unterminated = Markdown.sanitize('<img src="x" onerror="alert(1)"')
    expect(unterminated).toBe('&lt;img src="x" onerror="alert(1)"') // escaped text, not a tag
    const inAttr = Markdown.sanitize('<a href="x" title="><img src=x onerror=alert(1)>">y</a>')
    expect(inAttr).not.toContain('<img') // the payload stays inside the escaped title attribute
    expect(inAttr).toContain('title="&gt;&lt;img')
    expect(attack('<div><!-- <script>alert(1)</script> --></div>')).toBe('<div></div>')
  })
  it('re-emits attributes safely quoted', () => {
    const out = attack('<a href="https://a.test/?q=&quot;x&quot;" title=\'a"b\'>z</a>')
    expect(out).toContain('title="a&quot;b"')
  })
})

describe('render', () => {
  it('sanitises whatever marked returns', () => {
    const M = load({ parse: () => '<p onclick="x()">hi</p><script>alert(1)</script>' })
    expect(M.render('ignored')).toBe('<p>hi</p>alert(1)')
  })
  it('falls back to escaped text, never raw HTML, when marked failed to load', () => {
    expect(Markdown.render('<img onerror=alert(1)>')).not.toContain('<img')
    expect(Markdown.render('<img onerror=alert(1)>')).toContain('&lt;img')
  })
})
