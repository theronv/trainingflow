// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — Interactive demo
//  A self-contained sandbox: sample team, sample progress, and one fully playable course.
//  makeApi() (core.js) routes every request here while isDemo is true, so the real manager
//  and learner screens run unchanged and nothing ever touches the server or storage.
//  State lives in memory and is rebuilt on each launch.
// ══════════════════════════════════════════════════════════

const DEMO_COURSE = {
  "id": "demo-cse",
  "icon": "⭐",
  "title": "Customer Service Excellence",
  "description": "Build the communication skills and service mindset needed to deliver consistently outstanding experiences, even in high-pressure situations.",
  "modules": [
    {
      "id": "demo-cse-m1",
      "title": "Communication Foundations",
      "content": "<h2>The Communication Model</h2>\n<p>Every interaction involves a sender, a message, a channel, and a receiver—plus the ever-present risk of noise (anything that distorts the message). Great communicators manage all four elements: they choose the right channel, craft a clear message, and actively verify that the receiver understood what was intended.</p>\n<h2>Active Listening</h2>\n<p>Active listening is the most underrated communication skill. It involves: giving full attention (put down your phone), reflecting back what you heard (\"So what I'm hearing is…\"), asking clarifying questions, and withholding judgment until the person has finished speaking. Studies consistently show that people rate interactions as \"excellent\" when they feel genuinely heard—even if the outcome wasn't what they wanted.</p>\n<h2>Non-Verbal Communication</h2>\n<p>Body language, facial expressions, tone of voice, and eye contact account for the majority of what people \"hear.\" Crossed arms signal defensiveness. Downward gaze signals disinterest. A warm, neutral tone combined with appropriate eye contact signals presence and respect. Align your non-verbals with your words—if they contradict each other, people will believe the non-verbals.</p>",
      "summary": "Master active listening, clear messaging, and non-verbal communication for high-quality interactions.",
      "learning_objectives": "[\"Apply the active listening framework in conversations\",\"Align verbal and non-verbal communication\",\"Choose the right communication channel for each situation\"]",
      "questions": [
        {
          "id": "demo-cse-m1-q1",
          "question": "Which behavior BEST demonstrates active listening?",
          "option_a": "Preparing your response while the other person is still speaking",
          "option_b": "Reflecting back what you heard to confirm understanding",
          "option_c": "Nodding continuously to show agreement",
          "option_d": "Taking notes and not making eye contact",
          "correct_index": 1,
          "explanation": "Reflecting back confirms understanding and signals to the speaker that they have been genuinely heard."
        },
        {
          "id": "demo-cse-m1-q2",
          "question": "When verbal and non-verbal messages contradict each other, people typically believe:",
          "option_a": "The verbal message, because words are explicit",
          "option_b": "The non-verbal message, because it is harder to fake",
          "option_c": "Whichever message came first",
          "option_d": "Neither — they ask for clarification",
          "correct_index": 1,
          "explanation": "Non-verbal communication is largely subconscious and therefore perceived as more authentic than spoken words."
        },
        {
          "id": "demo-cse-m1-q3",
          "question": "A customer is explaining a problem. The best time to start formulating your response is:",
          "option_a": "While they are still talking, so you are ready immediately",
          "option_b": "After they have finished and you have confirmed understanding",
          "option_c": "Midway through their explanation to save time",
          "option_d": "Before the conversation starts, by assuming the likely issue",
          "correct_index": 1,
          "explanation": "Formulating a response while someone speaks divides your attention and leads to missing key details."
        }
      ]
    },
    {
      "id": "demo-cse-m2",
      "title": "Handling Difficult Situations",
      "content": "<h2>The HEAT Framework</h2>\n<p>When someone is upset, use the HEAT framework: <strong>Hear them out</strong> (let them express frustration without interrupting), <strong>Empathize</strong> (\"I can see why that would be frustrating\"), <strong>Apologize</strong> for the experience even if it wasn't your fault (\"I'm sorry you had this experience\"), <strong>Take action</strong> (state what you will do and follow through).</p>\n<h2>Defusing Anger</h2>\n<p>Never match an angry person's energy. Stay calm, lower your voice slightly (not your eye contact), and slow your speech. Use \"I\" statements to avoid sounding accusatory. Avoid phrases like \"You need to calm down\" (invalidating) or \"That's our policy\" without explanation (dismissive). Instead: \"Let me find out what we can do\" keeps the door open.</p>\n<h2>Setting Limits Without Escalating</h2>\n<p>If a person becomes abusive or threatening, you have the right to set a firm, respectful limit: \"I want to help you, but I'm not able to continue our conversation while being spoken to this way. I'll step away briefly—when you're ready, I'll be right back.\" Then follow through. Involve a supervisor or security if behavior doesn't improve.</p>",
      "summary": "Use the HEAT framework to de-escalate difficult interactions and set appropriate limits with upset customers.",
      "learning_objectives": "[\"Apply the HEAT framework to an upset customer\",\"Use language that de-escalates rather than inflames\",\"Set limits professionally without escalating further\"]",
      "questions": [
        {
          "id": "demo-cse-m2-q1",
          "question": "In the HEAT framework, what does the \"E\" stand for?",
          "option_a": "Evaluate the complaint",
          "option_b": "Empathize with the customer",
          "option_c": "Explain your policy",
          "option_d": "Escalate to a supervisor",
          "correct_index": 1,
          "explanation": "Empathizing acknowledges the customer's feelings and lowers emotional temperature before moving to resolution."
        },
        {
          "id": "demo-cse-m2-q2",
          "question": "A customer is shouting. The most effective immediate response is to:",
          "option_a": "Match their volume to show you take it seriously",
          "option_b": "Lower your own voice and slow your speech",
          "option_c": "Immediately call a supervisor",
          "option_d": "Read them the relevant policy out loud",
          "correct_index": 1,
          "explanation": "Lowering your voice and slowing your speech creates contrast that naturally encourages the other person to do the same."
        },
        {
          "id": "demo-cse-m2-q3",
          "question": "Saying \"That's just our policy\" without further explanation is problematic because:",
          "option_a": "Policies cannot be mentioned to customers",
          "option_b": "It is dismissive and closes off options without helping",
          "option_c": "Policies must always be shown in writing",
          "option_d": "It might reveal confidential information",
          "correct_index": 1,
          "explanation": "Citing policy without context or an attempt to help signals indifference, which increases frustration rather than resolving it."
        }
      ]
    },
    {
      "id": "demo-cse-m3",
      "title": "Service Recovery",
      "content": "<h2>The Service Recovery Paradox</h2>\n<p>Research shows that customers who experience a problem that is resolved quickly and well often end up more loyal than customers who never had a problem at all. This is the service recovery paradox—it means a mistake, handled exceptionally, is an opportunity. The key word is \"quickly\": a delayed recovery loses most of its loyalty-building power.</p>\n<h2>The Five Steps of Service Recovery</h2>\n<ol>\n<li><strong>Acknowledge</strong> the failure directly (\"You're right, that should not have happened\").</li>\n<li><strong>Apologize</strong> sincerely and specifically (\"I'm sorry your appointment was delayed by 45 minutes\").</li>\n<li><strong>Ask</strong> what would make it right (\"What can I do to make this better for you?\").</li>\n<li><strong>Act</strong> swiftly with a concrete resolution.</li>\n<li><strong>Follow up</strong> to confirm the resolution was satisfactory.</li>\n</ol>\n<h2>Learning from Complaints</h2>\n<p>Every complaint is data. Systematically capture what went wrong: Was it a process failure? A communication breakdown? A resource gap? Share findings with your team without blame. Organizations that treat complaints as quality-improvement intelligence consistently outperform those that treat them as problems to bury.</p>",
      "summary": "Turn service failures into loyalty opportunities using the five-step recovery framework.",
      "learning_objectives": "[\"Explain the service recovery paradox\",\"Apply the five-step service recovery process\",\"Use complaint data to drive process improvement\"]",
      "questions": [
        {
          "id": "demo-cse-m3-q1",
          "question": "The \"service recovery paradox\" suggests that:",
          "option_a": "Customer complaints should always be escalated",
          "option_b": "A well-handled service failure can create greater loyalty than no failure at all",
          "option_c": "Service recovery is only effective if it includes a refund",
          "option_d": "Customers are more forgiving of second failures",
          "correct_index": 1,
          "explanation": "When handled quickly and genuinely, a resolved problem can exceed the customer's expectations and build stronger loyalty."
        },
        {
          "id": "demo-cse-m3-q2",
          "question": "In the five-step recovery process, what comes AFTER apologizing?",
          "option_a": "Follow up to confirm satisfaction",
          "option_b": "Ask what would make it right",
          "option_c": "Act with a concrete resolution",
          "option_d": "Document the incident in your report",
          "correct_index": 1,
          "explanation": "After acknowledging and apologizing, you ask the customer what resolution would satisfy them before acting — this ensures the action you take is actually helpful."
        },
        {
          "id": "demo-cse-m3-q3",
          "question": "Why is it important to share complaint findings with your team?",
          "option_a": "To assign blame and prevent repeat offenses",
          "option_b": "To demonstrate compliance during audits",
          "option_c": "To identify process failures and improve quality collectively",
          "option_d": "It is required by customer service law",
          "correct_index": 2,
          "explanation": "Treating complaints as quality-improvement data — shared without blame — is how organizations systematically reduce the root causes of service failures."
        }
      ]
    }
  ]
};

// The other catalogue entries only need enough shape for the manager's Courses / Completions views.
const DEMO_OTHER_COURSES = [
  { id: 'demo-safety', icon: '🦺', title: 'Workplace Safety Fundamentals',
    description: 'Identify hazards, follow emergency procedures, and use personal protective equipment safely.',
    modules: ['Hazard Identification & Risk Assessment', 'Emergency Procedures & Evacuation', 'Personal Protective Equipment (PPE)'] },
  { id: 'demo-hipaa', icon: '🔒', title: 'HIPAA Compliance & Patient Privacy',
    description: 'Understand your obligations under HIPAA and how to respond if a breach occurs.',
    modules: ['Understanding HIPAA', 'Handling Patient Data Securely', 'Breach Prevention & Response'] },
  { id: 'demo-infection', icon: '🧼', title: 'Infection Control & Hand Hygiene',
    description: 'Evidence-based hand hygiene, transmission routes, and isolation precautions.',
    modules: ['Understanding Infectious Disease Transmission', 'Hand Hygiene Protocols', 'Isolation Precautions'] },
];

const Demo = {
  role: null,
  S: null,
  _saved: null,
  _noted: false,

  // ─── Fixtures ───
  _build() {
    const now = Math.floor(Date.now() / 1000), DAY = 86400;
    const ago = d => now - d * DAY;
    const iso = d => new Date((now + d * DAY) * 1000).toISOString().slice(0, 10);
    const TEAM = { id: 1, name: 'Patient Services' };
    const people = [
      ['dl-alex', 'Alex Rivera'], ['dl-jordan', 'Jordan Kim'], ['dl-taylor', 'Taylor Brooks'],
      ['dl-sam', 'Sam Patel'], ['dl-casey', 'Casey Morgan'], ['dl-jamie', 'Jamie Lee'],
    ].map(([id, name]) => ({ id, name, team_id: TEAM.id, role: 'learner' }));
    const [S, H, C, I] = ['demo-safety', 'demo-hipaa', 'demo-cse', 'demo-infection'];
    const assignments = [], completions = [];
    const assign = (lid, cid, due) => assignments.push({ course_id: cid, learner_id: lid, due_at: due ? iso(due) : null });
    let n = 0;
    const done = (lid, cid, score, passed, d) => completions.push({
      id: 'dc-' + (++n), course_id: cid, learner_id: lid, score, passed, completed_at: ago(d),
      cert_id: passed ? 'DEMO-' + String(1000 + n) : null,
    });
    // Alex — all four, all passed
    [[S, 92, 30], [H, 88, 24], [C, 96, 12], [I, 90, 5]].forEach(([c, s, d]) => { assign('dl-alex', c, c === C || c === I ? -d + 14 : 0); done('dl-alex', c, s, true, d); });
    // Jordan — three passed
    [[S, 85, 27], [H, 94, 20], [C, 90, 9]].forEach(([c, s, d]) => { assign('dl-jordan', c, c === C ? -d + 14 : 0); done('dl-jordan', c, s, true, d); });
    // Taylor — one passed, one failed, one overdue, one upcoming
    assign('dl-taylor', S, 0); done('dl-taylor', S, 81, true, 22);
    assign('dl-taylor', H, 0); done('dl-taylor', H, 67, false, 15);
    assign('dl-taylor', C, -2);
    assign('dl-taylor', I, 6);
    // Sam — two passed, failed customer service
    assign('dl-sam', S, 0); done('dl-sam', S, 100, true, 21);
    assign('dl-sam', H, 0); done('dl-sam', H, 83, true, 14);
    assign('dl-sam', C, 5); done('dl-sam', C, 72, false, 3);
    // Casey — newest on the team
    assign('dl-casey', S, 0); done('dl-casey', S, 87, true, 8);
    assign('dl-casey', H, 0);
    // Jamie — the demo learner: one course waiting
    assign('dl-jamie', C, 7);
    return {
      team: TEAM, people, assignments, completions,
      courses: [DEMO_COURSE, ...DEMO_OTHER_COURSES.map(c => ({
        id: c.id, icon: c.icon, title: c.title, description: c.description,
        modules: c.modules.map((t, i) => ({ id: `${c.id}-m${i + 1}`, title: t, content: '', questions: [] })),
      }))],
      answers: {},     // question_id -> selected_index (latest), like quiz_answers
      progress: {},    // course_id -> { course_id, module_idx, modules, updated_at }
    };
  },

  // ─── Entry points ───
  openPicker() { $$('demo-overlay').classList.remove('hidden'); },
  closePicker() { $$('demo-overlay').classList.add('hidden'); },

  start(role) {
    Demo.closePicker();
    if (!isDemo) {
      Demo._saved = { brand: brandCache };
      Demo.S = Demo._build();
      isDemo = true;
    }
    brandCache = { name: CONFIG.DEFAULT_BRAND_NAME + ' Demo', tagline: 'Explore the platform with sample training', logo: '', c1: CONFIG.DEFAULT_C1, c2: CONFIG.DEFAULT_C2, c3: CONFIG.DEFAULT_C3, pass: CONFIG.DEFAULT_PASS, font: CONFIG.DEFAULT_FONT, fontUrl: '' };
    applyBrand();
    Demo.role = role;
    Demo._noted = false;
    curCourse = null; curModIdx = 0; quizSt = {};
    if (role === 'manager') {
      curLearner = null;
      curManager = { id: 'dm-sarah', name: 'Sarah Chen', team_id: Demo.S.team.id, team_name: Demo.S.team.name };
      Manager.init();
    } else {
      curManager = null;
      curLearner = { id: 'dl-jamie', name: 'Jamie Lee' };
      Learner.init();
    }
    Demo._bar();
  },

  switchRole() { Demo.start(Demo.role === 'manager' ? 'learner' : 'manager'); },

  exit() {
    isDemo = false; Demo.role = null; Demo.S = null;
    curLearner = null; curManager = null; curCourse = null; curModIdx = 0; quizSt = {};
    if (Demo._saved) { brandCache = Demo._saved.brand; applyBrand(); }
    const bar = $$('demo-bar'); if (bar) bar.remove();
    App.show('screen-landing');
  },

  _bar() {
    let bar = $$('demo-bar');
    if (!bar) { bar = document.createElement('div'); bar.id = 'demo-bar'; bar.setAttribute('role', 'region'); bar.setAttribute('aria-label', 'Demo controls'); document.body.appendChild(bar); }
    const other = Demo.role === 'manager' ? 'learner' : 'manager';
    bar.innerHTML = `<span class="demo-bar-tag">Demo</span>
      <span class="demo-bar-text">Sample data · nothing is saved</span>
      <button type="button" class="demo-bar-btn" onclick="Demo.switchRole()">View as ${other}</button>
      <button type="button" class="demo-bar-btn demo-bar-exit" onclick="Demo.exit()">Exit</button>`;
  },

  // ─── Fake API ───
  _err(msg, status = 400) { return Object.assign(new Error(msg), { status }); },

  _learnerCourse(c) {
    // Learners never receive the answer key; grading happens in /api/quiz/answer.
    return { ...c, modules: (c.modules || []).map(m => ({ ...m, questions: (m.questions || []).map(({ correct_index, explanation, ...q }) => q) })) };
  },

  _findQ(qid) {
    for (const m of DEMO_COURSE.modules) { const q = m.questions.find(x => x.id === qid); if (q) return q; }
    return null;
  },

  _title(cid) { return (Demo.S.courses.find(c => c.id === cid) || {}).title || 'Course'; },

  _teamRows() {
    const S = Demo.S, now = Date.now();
    return S.people.map(p => {
      const asg = S.assignments.filter(a => a.learner_id === p.id);
      const comps = S.completions.filter(c => c.learner_id === p.id);
      const passedIds = new Set(comps.filter(c => c.passed).map(c => c.course_id));
      const overdue = asg.filter(a => a.due_at && !passedIds.has(a.course_id) && new Date(a.due_at + 'T23:59:59').getTime() < now).length;
      return { ...p, assignment_count: asg.length, completion_count: comps.length, overdue_count: overdue,
        pass_rate: comps.length ? Math.round(comps.filter(c => c.passed).length / comps.length * 100) : null };
    });
  },

  _completionRows(learnerId) {
    const S = Demo.S;
    const nameOf = id => (S.people.find(p => p.id === id) || {}).name || '';
    return S.completions.filter(c => !learnerId || c.learner_id === learnerId)
      .map(c => ({ ...c, user_name: nameOf(c.learner_id), learner_name: nameOf(c.learner_id), course_title: Demo._title(c.course_id) }))
      .sort((a, z) => z.completed_at - a.completed_at);
  },

  async handle(path, opts = {}) {
    const S = Demo.S;
    if (!S) throw Demo._err('Demo is not running.');
    const method = (opts.method || 'GET').toUpperCase();
    const [route, qs] = path.split('?');
    const q = new URLSearchParams(qs || '');
    const body = opts.body ? (() => { try { return JSON.parse(opts.body); } catch { return {}; } })() : {};
    const manager = Demo.role === 'manager';
    const me = 'dl-jamie';
    let m;
    const now = Math.floor(Date.now() / 1000);
    await new Promise(r => setTimeout(r, 120)); // a touch of latency so skeletons and spinners behave as in production

    if (method === 'GET') {
      if (route === '/api/courses') return manager ? S.courses.map(c => ({ ...c, modules: c.modules.map(m => ({ ...m, questions: [] })) })) : [Demo._learnerCourse(DEMO_COURSE)];
      m = route.match(/^\/api\/courses\/(.+)$/);
      if (m) { const c = S.courses.find(x => x.id === m[1]); if (!c) throw Demo._err('Course not found', 404); return Demo._learnerCourse(c); }
      if (route === '/api/sections') return [];
      if (route === '/api/brand') return {};
      if (route === '/api/learners') return Demo._teamRows();
      if (route === '/api/learners/me') return { id: me, name: 'Jamie Lee' };
      if (route === '/api/admin/teams') return [{ ...S.team, member_count: S.people.length }];
      if (route === '/api/admin/completions') return Demo._completionRows().filter(c => !q.get('course_id') || c.course_id === q.get('course_id'));
      if (route === '/api/admin/trouble-spots') return [];
      if (route === '/api/assignments') return S.assignments.map(a => ({ ...a, course_title: Demo._title(a.course_id) }));
      if (route === '/api/assignments/me') return S.assignments.filter(a => a.learner_id === me).map(a => ({ ...a, course_title: Demo._title(a.course_id) }));
      if (route === '/api/completions/me') return Demo._completionRows(me);
      if (route === '/api/progress/me') return Object.values(S.progress);
      if (route === '/api/invites') return [];
      return [];
    }

    // ── Learner actions that genuinely work in the sandbox ──
    if (route === '/api/quiz/answer' && method === 'POST') {
      const qn = Demo._findQ(body.question_id);
      if (!qn) throw Demo._err('Question not found', 404);
      S.answers[qn.id] = body.selected_index;
      return { correct: body.selected_index === qn.correct_index, correct_index: qn.correct_index, explanation: qn.explanation };
    }
    if (route === '/api/progress' && method === 'POST') {
      S.progress[body.course_id] = { course_id: body.course_id, module_idx: body.module_idx, modules: body.modules, updated_at: now };
      return { ok: true };
    }
    if ((m = route.match(/^\/api\/progress\/(.+)$/)) && method === 'DELETE') { delete S.progress[m[1]]; return { ok: true }; }
    if (route === '/api/completions' && method === 'POST') {
      const qs_ = DEMO_COURSE.modules.flatMap(x => x.questions);
      if (qs_.some(x => !(x.id in S.answers))) throw Demo._err('Answer every question in the course before finishing.');
      const right = qs_.filter(x => S.answers[x.id] === x.correct_index).length;
      const score = Math.round(right / qs_.length * 100);
      const passed = score >= (brandCache.pass || CONFIG.DEFAULT_PASS);
      const cert_id = passed ? 'DEMO-' + Math.random().toString(36).slice(2, 8).toUpperCase() : null;
      S.completions.push({ id: 'dc-' + (S.completions.length + 1), course_id: body.course_id, learner_id: me, score, passed, completed_at: now, cert_id });
      qs_.forEach(x => { delete S.answers[x.id]; });
      return { cert_id, score, passed };
    }

    // ── Team management in the manager view: update the sandbox where it is cheap ──
    if (route === '/api/assignments/bulk' && method === 'POST') {
      const ids = new Set([...(body.learner_ids || []), ...(body.team_ids || []).flatMap(() => S.people.map(p => p.id))]);
      let added = 0;
      ids.forEach(id => {
        if (S.assignments.some(a => a.course_id === body.course_id && a.learner_id === id)) return;
        S.assignments.push({ course_id: body.course_id, learner_id: id, due_at: body.due_at || null }); added++;
      });
      return { added };
    }
    if (route === '/api/invites' && method === 'POST') {
      return { id: 1, code: 'DEMO-JOIN', role: 'learner', max_uses: body.max_uses || 25, use_count: 0, expires_at: new Date(Date.now() + (body.expires_in_days || 7) * 86400000).toISOString() };
    }
    if (route === '/api/learners/bulk' && method === 'POST') { Demo._note(); return { created: 0, errors: [], created_learners: [] }; }

    // Anything else (resets, renames, deletes…) is accepted but not persisted.
    Demo._note();
    return { ok: true };
  },

  _note() {
    if (Demo._noted) return;
    Demo._noted = true;
    Toast.info('Demo mode — that change isn’t saved.');
  },
};
