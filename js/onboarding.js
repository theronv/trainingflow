// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — Onboarding
//  What a new person sees first. Everything is derived from data the app already loads
//  (assignments, completions, progress), so the only thing stored is a per-browser "Got it".
// ══════════════════════════════════════════════════════════

const Onboarding = {
  KEY: 'trainflow_onboarding_',

  // due_at arrives as epoch seconds or as a date string; null means no deadline.
  dueMs(a) {
    if (!a || !a.due_at) return null;
    const ms = isNaN(a.due_at) ? new Date(a.due_at).getTime() : Number(a.due_at) * 1000;
    return isNaN(ms) ? null : ms;
  },

  // Assigned courses not yet passed, soonest deadline first, undated last.
  todo({ assignments = [], completions = [] }) {
    const passed = new Set(completions.filter(c => c.passed).map(c => c.course_id));
    const rank = a => Onboarding.dueMs(a) ?? Infinity;
    return assignments.filter(a => !passed.has(a.course_id)).sort((a, z) => rank(a) - rank(z));
  },

  startCourse(data) { return Onboarding.todo(data)[0] || null; },

  // new: nothing attempted yet · active: under way · done: every assigned course passed
  learnerStage(data) {
    const { assignments = [], completions = [], progress = [] } = data;
    if (!completions.length && !progress.length) return 'new';
    return assignments.length && !Onboarding.todo(data).length ? 'done' : 'active';
  },

  isDismissed(role, userId) {
    try { return localStorage.getItem(Onboarding.KEY + role + '_' + userId) === '1'; } catch (e) { return false; }
  },
  dismissFor(role, userId) {
    try { localStorage.setItem(Onboarding.KEY + role + '_' + userId, '1'); } catch (e) { /* card will simply show again */ }
  },

  learnerHtml({ name = '', team = '', pass, assignments = [], completions = [], progress = [] }) {
    const data = { assignments, completions, progress };
    if (Onboarding.learnerStage(data) !== 'new') return '';
    const todo = Onboarding.todo(data);
    const first = todo[0];
    const firstName = String(name).trim().split(/\s+/)[0];
    const teamHtml = team ? `You're on <strong>${esc(team)}</strong>. ` : '';

    let leadHtml, actionsHtml;
    if (first) {
      const due = Onboarding.dueMs(first);
      const dueHtml = due ? `, the first due ${esc(new Date(due).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }))}` : '';
      leadHtml = `${teamHtml}You have <strong>${todo.length} ${todo.length === 1 ? 'course' : 'courses'}</strong> to complete${dueHtml}.`;
      actionsHtml = `<button type="button" class="btn btn-primary" onclick="Onboarding.start('${escJs(first.course_id)}')">Start ${esc(first.course_title)} →</button>`;
    } else {
      leadHtml = `You're all set up. Your ${team ? esc(team) + ' ' : ''}manager will add courses to your plan. You'll see them here as soon as they do.`;
      actionsHtml = '';
    }
    const passHtml = Number(pass) > 0 ? `Pass mark ${Number(pass)}%` : 'Each quiz has a pass mark';

    return `<section class="onb-card" aria-labelledby="onb-title">
      <h2 class="onb-title" id="onb-title">Welcome${firstName ? ', ' + esc(firstName) : ''}</h2>
      <p class="onb-leadHtml">${leadHtml}</p>
      <ol class="onb-steps">
        <li><span class="onb-step-n" aria-hidden="true">1</span>Learn each module</li>
        <li><span class="onb-step-n" aria-hidden="true">2</span>Answer the quiz</li>
        <li><span class="onb-step-n" aria-hidden="true">3</span>Earn your certificate</li>
      </ol>
      <p class="onb-note">${passHtml} · progress saves automatically · you can retake any course</p>
      <div class="onb-actionsHtml">${actionsHtml}<button type="button" class="btn btn-ghost" onclick="Onboarding.dismiss()">Got it</button></div>
    </section>`;
  },

  renderLearner(el, data) {
    if (!el) return;
    el.innerHTML = curLearner && !Onboarding.isDismissed('learner', curLearner.id) ? Onboarding.learnerHtml(data) : '';
  },

  dismiss() {
    if (curLearner) Onboarding.dismissFor('learner', curLearner.id);
    const el = $$('l-welcome'); if (el) el.innerHTML = '';
  },

  start(courseId) {
    Onboarding.dismiss();
    Learner.startCourse(courseId);
  }
};
