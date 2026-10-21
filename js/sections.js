// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — Section ordering and collapse state
//  Shared by the Admin, Manager and Learner course lists.
// ══════════════════════════════════════════════════════════

// `ordered` is orderSections() output. Returns the full list of section ids after moving `id`
// one step among its siblings (dir -1 = up, +1 = down), or null when it can't move that way.
// A parent carries its sub-sections with it; sub-sections only move within their parent.
function moveSectionOrder(ordered, id, dir) {
  const target = ordered.find(s => s.id === id);
  if (!target) return null;
  const isTop = !target.depth;
  const tops = ordered.filter(s => !s.depth);
  const kidsOf = parentId => ordered.filter(s => s.depth && s.parent_id === parentId);
  const siblings = isTop ? tops : kidsOf(target.parent_id);
  const i = siblings.findIndex(s => s.id === id), j = i + dir;
  if (j < 0 || j >= siblings.length) return null;
  const moved = siblings.slice();
  [moved[i], moved[j]] = [moved[j], moved[i]];
  return (isTop ? moved : tops).flatMap(p => [
    p.id,
    ...(!isTop && p.id === target.parent_id ? moved : kidsOf(p.id)).map(s => s.id),
  ]);
}

// Which sections each viewer has collapsed is a per-browser preference (localStorage). Markup
// is tagged with data attributes and shown/hidden in place, so toggling never refetches.
//   header:  [data-sec-head="<id>"] (+ data-sec-parent for sub-sections)
//   content: [data-sec="<id>"]      (+ data-sec-parent for sub-sections)
// Collapsing a parent also hides its sub-sections.
const SectionFold = {
  KEY: 'trainflow_collapsed_sections',
  OTHER: '__other', // the "Unsectioned" / "Other" group

  load() {
    try {
      const v = JSON.parse(localStorage.getItem(SectionFold.KEY) || '[]');
      return new Set(Array.isArray(v) ? v.filter(x => typeof x === 'string') : []);
    } catch { return new Set(); }
  },
  save(set) {
    try { localStorage.setItem(SectionFold.KEY, JSON.stringify([...set])); } catch { /* preference only */ }
  },
  isCollapsed(set, id, parentId) { return set.has(id) || (!!parentId && set.has(parentId)); },

  attrs(id, parentId) {
    return `data-sec="${esc(id)}"${parentId ? ` data-sec-parent="${esc(parentId)}"` : ''}`;
  },

  // Header with a fold button (chevron + title + count) and optional trailing controls.
  headHtml({ cls, id, parentId = '', title, count, extra = '' }) {
    return `<div class="${cls}" data-sec-head="${esc(id)}"${parentId ? ` data-sec-parent="${esc(parentId)}"` : ''}>
      <button type="button" class="sec-fold" aria-expanded="true" onclick="SectionFold.toggle('${escJs(id)}', this)">
        <svg class="sec-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
        <span class="sec-title">${esc(title)}</span>${count ? `<span class="sec-count">${esc(count)}</span>` : ''}
      </button>${extra}
    </div>`;
  },

  apply(root) {
    if (!root) return;
    root.setAttribute('data-sec-root', '');
    const set = SectionFold.load();
    const heads = [...root.querySelectorAll('[data-sec-head]')];
    heads.forEach(h => {
      const btn = h.querySelector('.sec-fold');
      if (btn) btn.setAttribute('aria-expanded', String(!set.has(h.dataset.secHead)));
      h.hidden = !!h.dataset.secParent && set.has(h.dataset.secParent);
    });
    root.querySelectorAll('[data-sec]').forEach(el => {
      el.hidden = SectionFold.isCollapsed(set, el.dataset.sec, el.dataset.secParent);
    });
    const all = document.getElementById('a-fold-all');
    if (all) {
      all.disabled = !heads.length;
      all.textContent = heads.length && heads.every(h => set.has(h.dataset.secHead)) ? 'Expand all' : 'Collapse all';
    }
  },

  toggle(id, btn) {
    const set = SectionFold.load();
    if (!set.delete(id)) set.add(id);
    SectionFold.save(set);
    SectionFold.apply(btn.closest('[data-sec-root]'));
  },

  // Collapse everything, or expand everything unless it is all already expanded.
  toggleAll(root) {
    if (!root) return;
    const ids = [...root.querySelectorAll('[data-sec-head]')].map(h => h.dataset.secHead);
    const set = SectionFold.load();
    const allCollapsed = ids.length > 0 && ids.every(id => set.has(id));
    ids.forEach(id => (allCollapsed ? set.delete(id) : set.add(id)));
    SectionFold.save(set);
    SectionFold.apply(root);
  },
};
