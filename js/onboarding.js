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
      const dueHtml = due ? `, the first due ${esc(new Date(due).toLocaleDateString())}` : '';
      leadHtml = `${teamHtml}You have <strong>${todo.length} ${todo.length === 1 ? 'course' : 'courses'}</strong> to complete${dueHtml}.`;
      actionsHtml = `<button type="button" class="btn btn-primary" aria-label="Start your first course: ${esc(first.course_title)}" onclick="Onboarding.start('${escJs(first.course_id)}')">Start your first course →</button>`;
    } else {
      leadHtml = `You're all set up. Your ${team ? esc(team) + ' ' : ''}manager will add courses to your plan. You'll see them here as soon as they do.`;
      actionsHtml = '';
    }
    const passHtml = Number(pass) > 0 ? `Pass mark ${Number(pass)}%` : 'Each quiz has a pass mark';

    return `<section class="onb-card" aria-labelledby="onb-title">
      <h2 class="onb-title" id="onb-title">Welcome${firstName ? ', ' + esc(firstName) : ''}</h2>
      <p class="onb-lead">${leadHtml}</p>
      <ol class="onb-steps">
        <li><span class="onb-step-n" aria-hidden="true">1</span>Learn each module</li>
        <li><span class="onb-step-n" aria-hidden="true">2</span>Answer the quiz</li>
        <li><span class="onb-step-n" aria-hidden="true">3</span>Earn your certificate</li>
      </ol>
      <p class="onb-note">${passHtml} · progress saves automatically · you can retake any course</p>
      <div class="onb-actions">${actionsHtml}<button type="button" class="btn btn-outline" onclick="Onboarding.dismiss()">Got it</button></div>
    </section>`;
  },

  // The Demo rebuilds its state on every launch, so a dismissal there lasts only until the launch ends.
  seen(role) {
    const who = role === 'manager' ? curManager : curLearner;
    return isDemo ? !!(Demo.S.onboardingSeen || {})[role] : Onboarding.isDismissed(role, who.id);
  },

  renderLearner(el, data) {
    if (!el) return;
    el.innerHTML = data && curLearner && curLearner.id && !Onboarding.seen('learner') ? Onboarding.learnerHtml(data) : '';
  },

  dismiss(role = 'learner') {
    const who = role === 'manager' ? curManager : curLearner;
    if (isDemo) Demo.S.onboardingSeen = { ...Demo.S.onboardingSeen, [role]: true };
    else if (who && who.id) Onboarding.dismissFor(role, who.id);
    const el = $$(role === 'manager' ? 'm-onboarding' : 'l-welcome'); if (el) el.innerHTML = '';
  },

  // ─── Manager checklist ───
  // Assignments are per learner, so a team with nobody in it has nothing to assign to: step 2 waits for a first joiner.
  managerSteps({ learners = [], invites = [], assignments = [], completions = [] }) {
    const joined = learners.length > 0;
    return [
      { id: 'invite', done: joined || invites.length > 0, locked: false, cta: 'Create invite link',
        title: 'Invite your learners', hint: 'Share an invite link. Each person chooses their own password and lands on your team.' },
      { id: 'assign', done: assignments.length > 0, locked: !joined, cta: 'Choose a course',
        title: 'Assign a course',
        hint: joined ? 'Pick a course and assign it to your team. It reaches everyone who has joined so far.' : 'Once your first learner has joined, pick a course and assign it to your team.' },
      { id: 'progress', done: completions.length > 0, locked: false, cta: '',
        title: 'Watch progress arrive', hint: 'Scores, completions and overdue learners show up on this dashboard as your team works.' },
    ];
  },

  managerHtml({ team = '', ...data }) {
    const steps = Onboarding.managerSteps(data);
    if (steps.every(st => st.done)) return '';
    const current = steps.find(st => !st.done && !st.locked && st.cta);
    const doneCount = steps.filter(st => st.done).length;
    const itemsHtml = steps.map((st, i) => {
      const stateCls = st.done ? ' onb-item-done' : st === current ? ' onb-item-current' : '';
      const btnHtml = !st.done && !st.locked && st.cta
        ? `<button type="button" class="btn ${st === current ? 'btn-primary' : 'btn-outline'} btn-sm" onclick="Onboarding.go('${escJs(st.id)}')">${esc(st.cta)}</button>`
        : '';
      return `<li class="onb-item${esc(stateCls)}">
        <span class="onb-check" aria-hidden="true">${st.done ? '✓' : i + 1}</span>
        <div class="onb-item-body">
          <div class="onb-item-title">${esc(st.title)}${st.done ? '<span class="sr-only"> (completed)</span>' : ''}</div>
          <div class="onb-item-hint">${esc(st.hint)}</div>
          ${btnHtml}
        </div>
      </li>`;
    }).join('');
    return `<section class="onb-card" aria-labelledby="onb-m-title">
      <div class="onb-head">
        <h2 class="onb-title" id="onb-m-title">Get your team started</h2>
        <button type="button" class="btn btn-ghost btn-sm" onclick="Onboarding.dismiss('manager')">Hide</button>
      </div>
      <p class="onb-lead">${team ? esc(team) + ' · ' : ''}${Number(doneCount)} of ${steps.length} done</p>
      <ol class="onb-list">${itemsHtml}</ol>
    </section>`;
  },

  // Returns true when the checklist is on screen.
  renderManager(el, data) {
    if (!el) return false;
    const html = data && curManager && curManager.id && !Onboarding.seen('manager') ? Onboarding.managerHtml(data) : '';
    el.innerHTML = html;
    return html !== '';
  },

  go(step) {
    if (step === 'invite') Manager.openInviteLearners();
    else if (step === 'assign') Manager.nav('courses');
  },

  start(courseId) {
    Onboarding.dismiss();
    Learner.startCourse(courseId);
  }
};
