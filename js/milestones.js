// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — Learner milestones
//  Badges are derived from a learner's completions (and the course list), so nothing extra is stored.
// ══════════════════════════════════════════════════════════

const Milestones = {
  DEFS: [
    { id: 'first',     title: 'First certificate',  hint: 'Pass your first course',                    test: s => s.passedCourses >= 1 },
    { id: 'three',     title: 'Hat trick',          hint: 'Pass 3 different courses',                  test: s => s.passedCourses >= 3 },
    { id: 'ten',       title: 'Ten and counting',   hint: 'Pass 10 different courses',                 test: s => s.passedCourses >= 10 },
    { id: 'perfect',   title: 'Perfect score',      hint: 'Score 100% on a course',                    test: s => s.perfect },
    { id: 'first-try', title: 'First try',          hint: 'Pass a course on your first attempt',       test: s => s.firstTry },
    { id: 'comeback',  title: 'Comeback',           hint: 'Pass a course after a retake',              test: s => s.comeback },
    { id: 'section',   title: 'Section complete',   hint: 'Pass every course in a section',            test: s => s.sectionsDone >= 1 },
  ],

  stats(completions, courses) {
    const byCourse = new Map();
    [...(completions || [])].sort((a, z) => a.completed_at - z.completed_at).forEach(c => {
      if (!byCourse.has(c.course_id)) byCourse.set(c.course_id, []);
      byCourse.get(c.course_id).push(c);
    });
    const passedIds = new Set();
    let perfect = false, firstTry = false, comeback = false;
    byCourse.forEach((list, id) => {
      const firstPass = list.findIndex(c => c.passed);
      if (firstPass < 0) return;
      passedIds.add(id);
      if (firstPass === 0) firstTry = true; else comeback = true;
      if (list.some(c => c.passed && c.score === 100)) perfect = true;
    });
    const sections = new Map();
    (courses || []).forEach(c => {
      if (!c.section_id) return;
      if (!sections.has(c.section_id)) sections.set(c.section_id, []);
      sections.get(c.section_id).push(c.id);
    });
    const sectionsDone = [...sections.values()].filter(list => list.length >= 2 && list.every(id => passedIds.has(id))).length;
    return { passedCourses: passedIds.size, perfect, firstTry, comeback, sectionsDone };
  },

  earned(completions, courses) {
    const s = Milestones.stats(completions, courses);
    return Milestones.DEFS.filter(d => d.test(s));
  },

  // Milestones present after a new completion that were not there before it.
  fresh(before, after, courses) {
    const had = new Set(Milestones.earned(before, courses).map(m => m.id));
    return Milestones.earned(after, courses).filter(m => !had.has(m.id));
  },

  // Badge grid for My Certificates: earned ones lit, the rest dimmed with how to unlock them.
  gridHtml(completions, courses) {
    const got = new Set(Milestones.earned(completions, courses).map(m => m.id));
    return `<div class="badge-grid">${Milestones.DEFS.map(d => {
      const on = got.has(d.id);
      return `<div class="badge${on ? ' badge-on' : ''}" title="${esc(d.hint)}">
        <div class="badge-icon" aria-hidden="true">${ICON.award}</div>
        <div class="badge-title">${esc(d.title)}</div>
        <div class="badge-hint">${on ? 'Earned' : esc(d.hint)}</div>
      </div>`;
    }).join('')}</div>`;
  },

  // Compact chips for the result screen.
  chipsHtml(list) {
    return list.map(m => `<span class="badge-chip">${ICON.award}<span>${esc(m.title)}</span></span>`).join('');
  }
};
