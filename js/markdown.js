// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — Safe Markdown for lesson content
//  Lesson text can come from scraped web pages or AI, and marked passes raw HTML and `javascript:` links
//  straight through. Everything marked produces is rebuilt here from an allow-list of tags and attributes,
//  so lessons can keep tables, lists, links and images but nothing can run script.
// ══════════════════════════════════════════════════════════

const Markdown = {
  TAGS: new Set(['p', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'b', 'em', 'i', 'u', 's', 'del', 'ins', 'mark', 'small',
    'sub', 'sup', 'code', 'pre', 'kbd', 'abbr', 'blockquote', 'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'table', 'caption', 'colgroup', 'col',
    'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'a', 'img', 'span', 'div', 'details', 'summary', 'figure', 'figcaption']),
  VOID: new Set(['br', 'hr', 'img', 'col']),

  // The href to use, or '' when it could run script. Browsers ignore whitespace and control characters inside a
  // scheme ("java\tscript:"), so check the stripped form, and refuse HTML entities rather than decode them.
  safeHref(href, forImage = false) {
    const raw = String(href == null ? '' : href).trim();
    if (!raw || /&(#|[a-z]+;)/i.test(raw)) return '';
    const flat = [...raw].filter(ch => { const c = ch.charCodeAt(0); return c > 0x20 && !(c >= 0x7f && c <= 0x9f); }).join('');
    const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(flat);
    if (!scheme) return raw; // relative, anchor or query
    const s = scheme[1].toLowerCase();
    if (s === 'http' || s === 'https') return raw;
    if (!forImage && (s === 'mailto' || s === 'tel')) return raw;
    if (forImage && s === 'data' && /^data:image\/(png|jpe?g|gif|webp);base64,[a-z0-9+/=]+$/i.test(flat)) return raw;
    return '';
  },

  _attrEsc(v) {
    return String(v).replace(/&(?!#?\w+;)/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  },

  _attrs(source) {
    const out = {};
    const re = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
    let m;
    while ((m = re.exec(source))) out[m[1].toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
    return out;
  },

  // Rebuild one allowed opening tag from only the attributes it is allowed to carry; null drops the tag.
  _openTag(tag, a) {
    const q = (k, v) => ` ${k}="${Markdown._attrEsc(v)}"`;
    const num = (v, max) => (new RegExp(`^\\d{1,${max}}$`).test(String(v)) ? String(v) : null);
    let attrs = '';
    if (tag === 'a') {
      const href = Markdown.safeHref(a.href);
      if (href) attrs += q('href', href);
      if (a.title) attrs += q('title', a.title);
      attrs += ' target="_blank" rel="noopener noreferrer"';
    } else if (tag === 'img') {
      const src = Markdown.safeHref(a.src, true);
      if (!src) return null;
      attrs += q('src', src) + q('alt', a.alt || '');
      if (a.title) attrs += q('title', a.title);
      for (const k of ['width', 'height']) { const n = num(a[k], 4); if (n) attrs += q(k, n); }
      attrs += ' loading="lazy"';
    } else if (tag === 'td' || tag === 'th') {
      for (const k of ['colspan', 'rowspan']) { const n = num(a[k], 2); if (n) attrs += q(k, n); }
    } else if (tag === 'ol') {
      const n = num(a.start, 4); if (n) attrs += q('start', n);
    } else if (tag === 'details') {
      if ('open' in a) attrs += ' open';
    }
    return `<${tag}${attrs}>`;
  },

  // Allow-list HTML sanitiser. Disallowed tags are dropped (their text stays as harmless text), comments are removed,
  // a `<` that does not start a well-formed tag is escaped, and allowed tags are re-emitted with vetted attributes only.
  sanitize(html) {
    const s = String(html == null ? '' : html).replace(/<!--[\s\S]*?-->/g, '');
    const TAG = /<(\/?)([a-zA-Z][a-zA-Z0-9]*)((?:"[^"]*"|'[^']*'|[^'">])*)>/y;
    let out = '', i = 0;
    while (i < s.length) {
      const lt = s.indexOf('<', i);
      if (lt < 0) { out += s.slice(i); break; }
      out += s.slice(i, lt);
      TAG.lastIndex = lt;
      const m = TAG.exec(s);
      if (!m) { out += '&lt;'; i = lt + 1; continue; }
      const tag = m[2].toLowerCase();
      if (Markdown.TAGS.has(tag)) {
        if (m[1]) { if (!Markdown.VOID.has(tag)) out += `</${tag}>`; }
        else out += Markdown._openTag(tag, Markdown._attrs(m[3])) || '';
      }
      i = lt + m[0].length;
    }
    return out;
  },

  render(md) {
    const text = String(md == null ? '' : md);
    if (typeof marked === 'undefined') return `<p>${esc(text)}</p>`;
    return Markdown.sanitize(marked.parse(text, { gfm: true, breaks: true }));
  }
};
