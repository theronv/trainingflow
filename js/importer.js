// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — AI Course Importer
// ══════════════════════════════════════════════════════════

const Importer = {
  fileModules: [],
  parsedModules: [],
  generatedCourse: null,
  isGenerating: false,
  MODULE_CHAR_LIMIT: 12000, // per-module text sent to the AI (merged pages run long)

  // AI Settings persistence
  saveAiKeys() {
    const claude = $$('claude-api-key').value.trim();
    const gemini = $$('gemini-api-key').value.trim();
    if (claude) sessionStorage.setItem('trainflow_claude_key', claude);
    if (gemini) sessionStorage.setItem('trainflow_gemini_key', gemini);
    Importer.toggleAiEdit(false);
    Toast.ok('Keys saved for this session.');
  },

  requestAiEdit() {
    const token = sessionStorage.getItem('tf_token');
    if (!token) { Toast.err("Admin session not found. Please log in again."); return; }
    Importer.toggleAiEdit(true);
  },

  toggleAiEdit(show) {
    $$('ai-keys-edit').classList.toggle('hidden', !show);
    $$('ai-keys-display').classList.toggle('hidden', show);
    $$('btn-ai-edit').classList.toggle('hidden', show);
    if (!show) {
      const c = sessionStorage.getItem('trainflow_claude_key');
      const g = sessionStorage.getItem('trainflow_gemini_key');
      $$('claude-key-masked').textContent = c ? '••••••••••••••••' : 'Not set';
      $$('claude-key-masked').style.color = c ? 'var(--pass)' : 'var(--ink-4)';
      $$('gemini-key-masked').textContent = g ? '••••••••••••••••' : 'Not set';
      $$('gemini-key-masked').style.color = g ? 'var(--pass)' : 'var(--ink-4)';
    }
  },

  loadSavedAiKeys() {
    const c = sessionStorage.getItem('trainflow_claude_key');
    const g = sessionStorage.getItem('trainflow_gemini_key');
    if (c || g) {
      if (c) $$('claude-api-key').value = c;
      if (g) $$('gemini-api-key').value = g;
      Importer.toggleAiEdit(false);
    }
  },

  async callAI(prompt, systemPrompt = '', maxTokens = 1000) {
    const claudeKey = sessionStorage.getItem('trainflow_claude_key');
    const geminiKey = sessionStorage.getItem('trainflow_gemini_key');
    const reqBody = { prompt, system_prompt: systemPrompt, max_tokens: maxTokens };
    if (claudeKey) reqBody.claude_key = claudeKey;
    if (geminiKey) reqBody.gemini_key = geminiKey;
    const data = await adminApi('/api/ai/generate', { method: 'POST', body: JSON.stringify(reqBody) });
    return { text: data.text, provider: data._provider };
  },

  async autofillCourseDetails() {
    const btn = $$('btn-ai-autofill');
    const orig = btn.innerHTML;
    btn.innerHTML = '<div class="spinner" style="width:12px;height:12px"></div>';
    btn.disabled = true;
    try {
      const combined = Importer.parsedModules.slice(0, 3).map(m => m.content.slice(0, 1000)).join('\n\n');
      const prompt = `Based on this content, suggest a Course Title, a short Description (max 150 chars), and a single relevant emoji.\n\nCONTENT:\n${combined}\n\nReturn JSON only: {"title": "...", "description": "...", "icon": "..."}`;
      const res = await Importer.callAI(prompt, "You are a senior instructional designer. Return JSON only.");
      const json = JSON.parse(res.text.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim());
      if (json.title) $$('ai-course-title').value = json.title;
      if (json.description) $$('ai-course-desc').value = json.description;
      if (json.icon) $$('ai-course-icon').value = json.icon;
      Toast.ok('Course details auto-filled.');
    } catch (e) { Toast.err(e.message); }
    finally { btn.innerHTML = orig; btn.disabled = false; }
  },

  // ── Import a course authored in Claude.ai (JSON) ──────────────────────────
  CLAUDE_PROMPT: `Create a training course as a downloadable file named course.json. Topic and audience: [DESCRIBE YOUR TOPIC AND AUDIENCE HERE]

OUTPUT RULES (save tokens):
- Create the file and reply with ONE short sentence. Do not print the JSON in chat, and add no preview, summary or explanation.
- Write the JSON compactly: no indentation or pretty-printing, no comments.
- Do not research or ask questions; use your own knowledge.
- If you cannot create a file, output the JSON once inside a single code block (never as plain text, which corrupts the quotes).

JSON format:
{"title":"","icon":"💻","description":"1-2 sentences on what learners gain","modules":[{"title":"","summary":"one-sentence takeaway, max 200 chars","learning_objectives":["Learners will be able to ..."],"content":"Lesson in Markdown (## headings, short paragraphs, bullets, numbered steps)","questions":[{"question":"","options":["","","",""],"correct_index":0,"explanation":"one sentence"}]}]}

CONTENT RULES:
- 3-6 modules, each 300-500 words of practical, specific Markdown content.
- 3-4 questions per module that test understanding, not trivia. Exactly 4 options; correct_index is 0-3 and varies.
- "icon" is a single emoji.
- Valid JSON only: double quotes, no trailing commas, newlines in strings written as \\n.`,

  async copyClaudePrompt() {
    try { await navigator.clipboard.writeText(Importer.CLAUDE_PROMPT); Toast.ok('Prompt copied — paste it into Claude.ai.'); }
    catch { Toast.err('Could not access the clipboard. Select and copy manually.'); }
  },

  loadCourseJsonFile(e) {
    const f = e.target.files && e.target.files[0]; if (!f) return;
    const r = new FileReader();
    r.onload = () => { $$('course-json-input').value = String(r.result || ''); Importer.previewCourseJson(); };
    r.readAsText(f);
    e.target.value = '';
  },

  clearCourseJson() {
    const t = $$('course-json-input'); if (t) { t.value = ''; t.focus(); }
    const st = $$('course-json-status'); if (st) st.textContent = '';
  },

  // Returns { course, errors }. Tolerates code fences / surrounding prose.
  parseCourseJson(text) {
    const errors = [];
    const { data, error } = Importer.extractJson(text);
    if (error || !data || Array.isArray(data)) return { course: null, errors: [error || 'No JSON object found.'] };

    const str = Importer.str;
    if (!str(data.title)) errors.push('Missing course "title".');
    if (!Array.isArray(data.modules) || !data.modules.length) { errors.push('"modules" must be a non-empty array.'); return { course: null, errors }; }

    const modules = data.modules.map((m, mi) => {
      const label = `Module ${mi + 1}`;
      if (!str(m.title)) errors.push(`${label}: missing "title".`);
      if (!str(m.content)) errors.push(`${label}: missing "content".`);
      const questions = (Array.isArray(m.questions) ? m.questions : []).map((q, qi) => Importer.normalizeQuestion(q, `${label}, question ${qi + 1}`, errors));
      if (!questions.length) errors.push(`${label}: no questions.`);
      return {
        title: str(m.title), content: str(m.content), summary: str(m.summary) || null,
        learning_objectives: Array.isArray(m.learning_objectives) ? m.learning_objectives.map(str).filter(Boolean) : [],
        reference_url: str(m.reference_url) || null, questions
      };
    });
    return { course: { title: str(data.title), icon: str(data.icon) || '📋', description: str(data.description), modules }, errors };
  },

  previewCourseJson() {
    const status = $$('course-json-status');
    const { course, errors } = Importer.parseCourseJson($$('course-json-input').value);
    if (errors.length || !course) {
      const shown = errors.slice(0, 5).join(' ') + (errors.length > 5 ? ` (+${errors.length - 5} more)` : '');
      if (status) { status.textContent = shown; status.style.color = 'var(--fail)'; }
      return;
    }
    if (status) { status.textContent = ''; }
    Importer.generatedCourse = course;
    $$('btn-edit-prompt')?.classList.add('hidden');
    Importer.renderReview();
    Importer.goPhase(4);
  },

  // ── Claude.ai question flow (no API key) ──────────────────────────────────
  // Lessons stay exactly as imported. The app builds prompts that contain the lesson text and
  // asks Claude only for summaries, objectives and questions, matched back to modules by id.
  DEFAULT_SETTINGS: { count: 5, difficulty: 'applied', focus: 'howto' },
  PROMPT_CHAR_BUDGET: 30000, // lesson text per prompt; keeps each paste comfortably inside a chat window
  FOCUS: {
    general: 'Test comprehension of the key concepts.',
    howto: 'Product how-to: ask scenario and procedure questions (which feature achieves a goal, what to do next, what order the steps go in, where an option lives). Avoid trivia.',
    support: 'Focus on support scenarios and customer interactions.',
    process: 'Focus on the correct sequence of steps and procedures.',
    technical: 'Focus on specific values, limits, and technical requirements.'
  },
  DIFFICULTY: {
    foundational: 'Test basic recall and recognition.',
    applied: 'Test application of knowledge in scenarios.',
    analytical: 'Test judgment and nuanced understanding.'
  },
  settings: null,
  phase: 1,

  str(v) { return typeof v === 'string' ? v.trim() : ''; },

  // Pulls the first JSON object/array out of a chat reply. Tolerates code fences, surrounding
  // prose, and the smart quotes chat windows sometimes substitute when text is copied.
  extractJson(text) {
    const raw = String(text || '').replace(/```json\s*/gi, '').replace(/```/g, '').trim();
    const starts = [raw.indexOf('{'), raw.indexOf('[')].filter(n => n >= 0);
    const a = starts.length ? Math.min(...starts) : -1;
    const b = Math.max(raw.lastIndexOf('}'), raw.lastIndexOf(']'));
    if (a < 0 || b <= a) return { data: null, error: 'No JSON found in that text.' };
    const body = raw.slice(a, b + 1);
    try { return { data: JSON.parse(body), error: '' }; }
    catch (e) {
      try { return { data: JSON.parse(body.replace(/[“”„‟″]/g, '"')), error: '' }; }
      catch { return { data: null, error: 'Invalid JSON: ' + e.message }; }
    }
  },

  // Validates one question and returns it in canonical form; problems are appended to `errors`.
  normalizeQuestion(q, label, errors) {
    const str = Importer.str;
    q = q || {};
    const opts = Array.isArray(q.options) ? q.options.map(str) : [q.option_a, q.option_b, q.option_c, q.option_d].map(str);
    if (!str(q.question)) errors.push(`${label}: missing "question".`);
    if (opts.length < 4 || opts.slice(0, 4).some(o => !o)) errors.push(`${label}: needs 4 non-empty options.`);
    let ci = q.correct_index;
    if (typeof ci === 'string' && /^[a-d]$/i.test(ci.trim())) ci = 'abcd'.indexOf(ci.trim().toLowerCase());
    ci = ci === null || ci === undefined || ci === '' ? NaN : Number(ci);
    if (!Number.isInteger(ci) || ci < 0 || ci > 3) { errors.push(`${label}: "correct_index" must be 0-3.`); ci = 0; }
    return { question: str(q.question), options: opts.slice(0, 4), correct_index: ci, explanation: str(q.explanation) };
  },

  // Models favour A/B for the right answer; reorder so position gives nothing away. Options that
  // refer to their neighbours ("All of the above", "Both A and B") keep their order.
  shuffleOptions(q, rand = Math.random) {
    if (q.options.some(o => /\b(all|none|both|neither) of (the above|these)\b|^(both|a and b)\b/i.test(o))) return q;
    const order = [0, 1, 2, 3];
    for (let i = 3; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      [order[i], order[j]] = [order[j], order[i]];
    }
    return { ...q, options: order.map(i => q.options[i]), correct_index: order.indexOf(q.correct_index) };
  },

  // Lesson text as Claude sees it: screenshots become "[Screenshot: alt]" and links keep only
  // their text, so image URLs don't eat the token budget. The saved lesson keeps the originals.
  plainLesson(md) {
    return String(md || '')
      .replace(/!\[([^\]]*)\]\([^)]*\)/g, (_, alt) => (alt.trim() ? `[Screenshot: ${alt.trim()}]` : ''))
      .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  },

  // Splits modules into prompt-sized groups. A module larger than the budget gets a group of its own.
  batchModules(modules, budget = Importer.PROMPT_CHAR_BUDGET) {
    const batches = []; let cur = [], size = 0;
    for (const m of modules) {
      const len = Importer.plainLesson(m.content).length;
      if (cur.length && size + len > budget) { batches.push(cur); cur = []; size = 0; }
      cur.push(m); size += len;
    }
    if (cur.length) batches.push(cur);
    return batches;
  },

  buildQuestionsPrompt(modules, { count, difficulty, focus }) {
    const lessons = modules.map(m => `=== LESSON ${m._rid}: ${m.title} ===\n${Importer.plainLesson(m.content)}`).join('\n\n');
    return `Write quiz material for a training course from the lessons below. Use ONLY facts stated in the lessons; add nothing from outside knowledge.

For each lesson return a one-sentence summary (max 200 chars), 3-5 learning objectives, and up to ${count} multiple-choice questions (2-3 for lessons under 150 words).

QUESTION RULES:
- ${Importer.FOCUS[focus] || Importer.FOCUS.general}
- ${Importer.DIFFICULTY[difficulty] || Importer.DIFFICULTY.applied}
- Exactly 4 options: one clearly correct, three plausible but wrong. Vary which position is correct (correct_index 0-3). Never use "all of the above" or "none of the above".
- Every question must be answerable from its own lesson. [Screenshot: ...] markers stand for images; ask about what they show only if the surrounding text says it.
- "explanation": one sentence on why the answer is right.

OUTPUT RULES (save tokens):
- Create a file named questions.json and reply with ONE short sentence. Do not print the JSON in chat.
- Write compact JSON: no indentation, no comments, double quotes, no trailing commas.
- If you cannot create a file, output the JSON once inside a single code block (never as plain text, which corrupts the quotes).

JSON format (one entry per lesson, using the lesson's id):
{"modules":[{"id":"m1","summary":"","learning_objectives":["Learners will be able to ..."],"questions":[{"question":"","options":["","","",""],"correct_index":0,"explanation":""}]}]}

LESSONS

${lessons}`;
  },

  // Merges Claude's reply into the course. A module's entry is applied only if all of it is valid.
  applyQuestionsReply(course, text) {
    const { data, error } = Importer.extractJson(text);
    if (error) return { applied: [], errors: [error] };
    const list = Array.isArray(data) ? data : data.modules;
    if (!Array.isArray(list)) return { applied: [], errors: ['Expected a "modules" list in the reply.'] };
    const applied = [], errors = [];
    for (const entry of list) {
      const mod = course.modules.find(m => m._rid === String(entry?.id));
      if (!mod) { errors.push(`Unknown module id "${entry?.id}".`); continue; }
      const label = `"${mod.title}"`, local = [];
      const questions = (Array.isArray(entry.questions) ? entry.questions : [])
        .map((q, qi) => Importer.shuffleOptions(Importer.normalizeQuestion(q, `${label}, question ${qi + 1}`, local)));
      if (!questions.length) local.push(`${label}: no questions in the reply.`);
      if (local.length) { errors.push(...local); continue; }
      mod.questions = questions;
      mod.summary = Importer.str(entry.summary).slice(0, 250) || mod.summary || null;
      mod.learning_objectives = Array.isArray(entry.learning_objectives) ? entry.learning_objectives.map(Importer.str).filter(Boolean) : [];
      applied.push(mod._rid);
    }
    return { applied, errors };
  },

  readSettings() {
    const d = Importer.DEFAULT_SETTINGS;
    return {
      count: parseInt($$('q-per-mod')?.value || d.count, 10),
      difficulty: $$('q-difficulty')?.value || d.difficulty,
      focus: $$('q-focus')?.value || d.focus
    };
  },

  courseFromParsed() {
    return {
      title: $$('ai-course-title').value.trim(),
      icon: $$('ai-course-icon').value || '📋',
      description: $$('ai-course-desc').value.trim(),
      modules: Importer.parsedModules.map((m, i) => ({
        title: m.title, content: m.content, reference_url: m.reference_url || '',
        summary: null, learning_objectives: [], questions: [], _rid: `m${i + 1}`
      }))
    };
  },

  startClaudeFlow() {
    const existing = Importer.generatedCourse;
    if (existing?.modules.some(m => m.questions?.length) && !confirm('Building new prompts discards the questions already added. Continue?')) return;
    Importer.settings = Importer.readSettings();
    Importer.generatedCourse = Importer.courseFromParsed();
    Importer.showClaudePanel();
    Importer.goPhase(3);
  },

  showClaudePanel() {
    $$('gen-claude').classList.remove('hidden');
    $$('gen-api').classList.add('hidden');
    Importer.renderClaudePanel();
  },

  renderClaudePanel() {
    const c = Importer.generatedCourse, list = $$('gen-batches');
    if (!c || !list) return;
    const batches = Importer.batchModules(c.modules);
    list.innerHTML = batches.map((b, i) => {
      const done = b.filter(m => m.questions.length).length;
      const names = b.slice(0, 3).map(m => m.title).join(', ') + (b.length > 3 ? ', …' : '');
      return `<div class="gen-batch">
        <div class="gen-batch-info"><strong>Prompt ${i + 1} of ${batches.length}</strong><span>${b.length} lesson${b.length !== 1 ? 's' : ''}: ${esc(names)}</span></div>
        <span class="chip ${done === b.length ? 'chip-green' : 'chip-gray'}">${done} of ${b.length} done</span>
        <button class="btn btn-outline btn-sm" onclick="Importer.copyBatch(${i})">Copy prompt</button>
      </div>`;
    }).join('');
    const ready = c.modules.filter(m => m.questions.length).length;
    $$('gen-claude-summary').textContent = `${ready} of ${c.modules.length} lessons have questions.`;
    $$('btn-claude-review').disabled = !ready;
  },

  async copyText(text, okMsg) {
    try { await navigator.clipboard.writeText(text); Toast.ok(okMsg); }
    catch { Toast.err('Could not access the clipboard. Allow clipboard access and try again.'); }
  },
  copyBatch(i) {
    const batch = Importer.batchModules(Importer.generatedCourse.modules)[i];
    Importer.copyText(Importer.buildQuestionsPrompt(batch, Importer.settings || Importer.readSettings()), `Prompt ${i + 1} copied. Paste it into a new Claude.ai chat.`);
  },
  copyModulePrompt(mi) {
    const m = Importer.generatedCourse.modules[mi];
    Importer.copyText(Importer.buildQuestionsPrompt([m], Importer.settings || Importer.readSettings()), 'Prompt copied. Paste it into Claude.ai, then paste the reply in the box at the top.');
    $$('rv-reply').open = true;
  },

  // Shared by the Generate screen and the Review screen.
  addReply(inputId, statusId) {
    const input = $$(inputId), status = $$(statusId);
    const { applied, errors } = Importer.applyQuestionsReply(Importer.generatedCourse, input.value);
    if (applied.length) input.value = '';
    const shown = errors.slice(0, 4).join(' ') + (errors.length > 4 ? ` (+${errors.length - 4} more)` : '');
    status.textContent = [applied.length ? `Added questions for ${applied.length} lesson${applied.length !== 1 ? 's' : ''}.` : '', shown].filter(Boolean).join(' ');
    status.style.color = errors.length ? 'var(--fail)' : 'var(--pass)';
    if (!applied.length && !errors.length) status.textContent = 'Nothing to add. Paste Claude’s reply first.';
    Importer.saveDraft();
    Importer.renderClaudePanel();
    if (Importer.phase === 4) Importer.renderReview();
  },
  loadReplyFile(e, inputId, statusId) {
    const f = e.target.files && e.target.files[0]; if (!f) return;
    const r = new FileReader();
    r.onload = () => { $$(inputId).value = String(r.result || ''); Importer.addReply(inputId, statusId); };
    r.readAsText(f);
    e.target.value = '';
  },
  reviewFromClaude() { Importer.renderReview(); Importer.goPhase(4); },

  goPhase(n) {
    Importer.phase = n;
    if (n === 1) { Importer.loadSavedAiKeys(); Importer.renderDraftBanner(); }
    if (n === 2) { $$('gen-claude')?.classList.remove('hidden'); $$('gen-api')?.classList.add('hidden'); }
    if (n !== 4) $$('btn-edit-prompt')?.classList.remove('hidden');
    [1,2,3,4].forEach(i => {
      const pg = $$(`phase-${['upload','configure','generate','export'][i-1]}`);
      if(pg) pg.classList.toggle('hidden', i !== n);
      const s = $$(`step-${i}`);
      if(s) {
        const numEl = s.querySelector('.step-num');
        s.classList.remove('active','done');
        if (i < n) { s.classList.add('done'); if(numEl) numEl.textContent = '✓'; }
        else if (i === n) { s.classList.add('active'); if(numEl) numEl.textContent = i; }
        else { if(numEl) numEl.textContent = i; }
      }
    });
    if (n > 1) Importer.saveDraft();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  },

  handleDrop(e) {
    e.preventDefault();
    const dz = $$('imp-drop-zone'); if(dz) dz.classList.remove('drag-active');
    const files = Array.from(e.dataTransfer.files).filter(f => /\.(md|markdown|txt)$/i.test(f.name));
    if (!files.length) { Toast.err('Drop .md files only.'); return; }
    files.forEach(f => Importer.readAndAddFile(f));
  },
  // Fetch a page as Markdown. Tries Jina Reader straight from the browser first (the
  // visitor's own IP isn't rate-limited like the Worker's shared egress), then falls
  // back to the Worker proxy.
  async fetchPage(rawUrl) {
    let u;
    try { u = new URL(rawUrl); } catch { throw new Error('Not a valid URL'); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('Only http(s) URLs are supported');
    try {
      const res = await fetch('https://r.jina.ai/' + u.href, {
        headers: { Accept: 'text/plain' },
        signal: AbortSignal.timeout(25000),
      });
      if (res.ok) {
        const markdown = await res.text();
        if (markdown.trim()) return { markdown, url: u.href };
      }
    } catch { /* fall through to the Worker proxy */ }
    return adminApi('/api/scrape?url=' + encodeURIComponent(u.href));
  },
  // Blank lines split the textarea into groups. A group with 2+ URLs is merged into ONE
  // module (its first "# Name" comment line, if any, becomes the module title); a
  // single-URL group imports as before (split into modules by headings).
  parseUrlGroups(raw) {
    const groups = []; let cur = { name: '', urls: [] };
    const flush = () => { if (cur.urls.length) groups.push(cur); cur = { name: '', urls: [] }; };
    for (const line of raw.split('\n').map(l => l.trim())) {
      if (!line) { flush(); continue; }
      if (line.startsWith('#')) { if (!cur.name && !cur.urls.length) cur.name = line.replace(/^#+\s*/, ''); continue; }
      if (!cur.urls.includes(line)) cur.urls.push(line);
    }
    flush();
    return groups;
  },
  async importFromUrls() {
    const groups = Importer.parseUrlGroups($$('imp-url-input').value);
    const total = groups.reduce((n, g) => n + g.urls.length, 0);
    if (!total) return Toast.err('Paste at least one URL.');
    if (total > 40) return Toast.err('Import up to 40 pages at a time.');
    const btn = $$('btn-imp-urls'), list = $$('imp-url-results'), status = $$('imp-url-status');
    btn.disabled = true;
    let n = 0;
    list.innerHTML = groups.map((g, gi) => (g.urls.length > 1 ? `<li style="margin-top:8px;font-weight:600;">${esc(g.name || 'Merged module')} (${g.urls.length} pages → 1 module)</li>` : '') +
      g.urls.map((u, ui) => `<li id="imp-url-${gi}-${ui}">⏳ ${esc(u)}</li>`).join('')).join('');
    let ok = 0, done = 0;
    for (let gi = 0; gi < groups.length; gi++) {
      const g = groups[gi], merge = g.urls.length > 1, pages = [];
      for (let ui = 0; ui < g.urls.length; ui++) {
        const row = $$(`imp-url-${gi}-${ui}`);
        status.textContent = `Fetching ${++done} of ${total}…`;
        try {
          const data = await Importer.fetchPage(g.urls[ui]);
          const slug = decodeURIComponent(new URL(data.url).pathname.split('/').filter(Boolean).pop() || new URL(data.url).hostname).replace(/^\d+[-_]/, '').replace(/\.\w+$/, '');
          if (merge) {
            const parsed = Importer.parseMdToModules(data.markdown, slug, { single: true });
            if (!parsed.modules.length) throw new Error('No readable content');
            pages.push({ title: parsed.docTitle, content: parsed.modules[0].content, url: parsed.docUrl || data.url });
          } else {
            Importer.addFileModule(data.markdown, slug);
          }
          row.innerHTML = `<span style="color:var(--pass)">✓</span> ${esc(g.urls[ui])}`;
          ok++;
        } catch (err) {
          row.innerHTML = `<span style="color:var(--fail)">✗</span> ${esc(g.urls[ui])} — ${esc(err.message)}`;
        }
        if (done < total) await new Promise(r => setTimeout(r, 1000)); // be polite to the source
      }
      if (merge && pages.length) {
        const name = g.name || pages[0].title;
        Importer.fileModules.push({
          id: Date.now() + Math.random(), name, description: '', icon: '', sourceUrl: pages[0].url,
          subModules: [{ title: name, content: Importer.combinePages(pages), reference_url: pages[0].url }]
        });
        Importer.renderFileModuleList();
      }
    }
    status.textContent = ok ? `${ok} of ${total} pages imported.` : 'Nothing imported.';
    btn.disabled = false;
    if (ok) $$('imp-url-input').value = '';
  },
  // Join several pages into one module body: each page keeps its title as a "##" heading.
  combinePages(pages) {
    return pages.map(p => `## ${p.title}\n\n${p.content}`).join('\n\n');
  },
  handleFileSelect(e) {
    Array.from(e.target.files).forEach(f => Importer.readAndAddFile(f));
    e.target.value = '';
  },
  readAndAddFile(file) {
    const MAX_BYTES = 2 * 1024 * 1024; // 2MB
    if (file.size > MAX_BYTES) {
      const mb = (file.size / 1024 / 1024).toFixed(1);
      Toast.err(`"${file.name}" is ${mb}MB — max 2MB. Split the file or trim content before uploading.`);
      return;
    }
    const reader = new FileReader();
    reader.onload = ev => Importer.addFileModule(ev.target.result, file.name.replace(/\.[^.]+$/, ''));
    reader.readAsText(file);
  },
  addFileModule(rawMd, defaultName) {
    const result = Importer.parseMdToModules(rawMd, defaultName);
    const id = Date.now() + Math.random();
    Importer.fileModules.push({
      id,
      name: result.docTitle,
      subModules: result.modules,
      description: result.docDesc,
      icon: result.docIcon,
      sourceUrl: result.docUrl
    });
    Importer.renderFileModuleList();
  },
  cleanTitle(s) {
    if (!s) return '';
    if (/^[\w-]+$/.test(s) && (s.includes('_') || s.includes('-') || s === s.toLowerCase() || s === s.toUpperCase())) {
      s = s.replace(/[-_]/g, ' ').replace(/\s+/g, ' ').trim();
    }
    return s.replace(/\w\S*/g, w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
  },
  parseMdToModules(raw, defaultTitle, { single = false } = {}) {
    let lines = raw.split('\n');
    let docTitle = defaultTitle, docDesc = '', docIcon = '', docUrl = '';

    // Extract metadata
    let i = 0;
    while (i < lines.length && i < 15) {
      const line = lines[i].trim();
      if (!line) { i++; continue; }
      const tm = line.match(/^(Title|Course Title):\s*(.+)/i);
      const dm = line.match(/^(Description):\s*(.+)/i);
      const im = line.match(/^(Icon):\s*(.+)/i);
      const um = line.match(/^URL Source:\s*(.+)/i);
      if (tm) { docTitle = tm[2].trim(); lines[i] = ''; }
      else if (dm) { docDesc = dm[2].trim(); lines[i] = ''; }
      else if (im) { docIcon = im[2].trim(); lines[i] = ''; }
      else if (um) { docUrl = um[1].trim(); lines[i] = ''; }
      else if (line.match(/^Markdown Content:/i)) lines[i] = '';
      else if (!line.match(/^([-* ]){3,}$/)) break;
      i++;
    }

    const isNavLink = l => {
      const t = l.trim();
      if (/^[-*]\s*\[[ x]\]\s*\[/.test(t)) return true;
      if (/^[-*]?\s*\[.+\]\(https?:\/\/[^)]+\)[\s.,;]*$/.test(t)) return true;
      if (/^https?:\/\/\S+$/.test(t)) return true;
      return false;
    };
    const isAnchorOnlyHeading = l => /^#{1,6}\s+\[.+\]\(https?:\/\/.+\)\s*$/.test(l);
    const isBoilerplate = l => /^(©|\(c\)|copyright|all rights reserved|privacy policy|terms of (use|service)|cookie)/i.test(l.trim());

    const contentLines = lines.slice(i);
    const paragraphs = [];
    let curPara = [];
    for (const l of contentLines) {
      if (!l.trim()) { if (curPara.length) { paragraphs.push(curPara); curPara = []; } paragraphs.push(['']); }
      else curPara.push(l);
    }
    if (curPara.length) paragraphs.push(curPara);

    const filteredContent = paragraphs.flatMap(para => {
      if (para.length === 1 && !para[0].trim()) return para;
      const nonEmpty = para.filter(l => l.trim());
      if (nonEmpty.length >= 3 && nonEmpty.filter(isNavLink).length / nonEmpty.length > 0.7) return [];
      return para.filter(l => !isAnchorOnlyHeading(l) && !isBoilerplate(l));
    });

    const metaLines = lines.slice(0, i).filter(l => l.trim() !== '');
    const cleanLines = [...metaLines, ...filteredContent];

    // single: keep the whole page as ONE module (used when several pages are merged)
    if (single) {
      const body = filteredContent.filter(l => !/^URL Source:/i.test(l.trim())).join('\n').trim();
      return {
        docTitle: Importer.cleanTitle(docTitle), docDesc: '', docIcon, docUrl,
        modules: body ? [{ title: Importer.cleanTitle(docTitle), content: body, reference_url: docUrl }] : []
      };
    }

    const hasH2 = cleanLines.some(l => l.startsWith('## '));
    const hasH3 = !hasH2 && cleanLines.some(l => l.startsWith('### '));
    const hasHR = !hasH2 && !hasH3 && cleanLines.some(l => /^([-* ]){3,}$/.test(l.trim()));

    const modules = []; let cur = null;
    if (hasH2) {
      for (const line of cleanLines) {
        const h2 = line.match(/^##\s+(.+)/);
        if (h2) {
          if (cur) modules.push(cur);
          cur = { title: Importer.cleanTitle(h2[1].trim()), rawLines: [] };
        } else if (cur) cur.rawLines.push(line);
        else if (line.trim() && !docDesc) docDesc += line + ' ';
      }
    } else if (hasH3) {
      for (const line of cleanLines) {
        const h3 = line.match(/^###\s+(.+)/);
        if (h3) {
          if (cur) modules.push(cur);
          cur = { title: Importer.cleanTitle(h3[1].trim()), rawLines: [] };
        } else if (cur) cur.rawLines.push(line);
        else if (line.trim() && !docDesc) docDesc += line + ' ';
      }
    } else if (hasHR) {
      cur = { title: Importer.cleanTitle(docTitle), rawLines: [] };
      let sectionIdx = 1;
      for (const line of cleanLines) {
        if (/^([-* ]){3,}$/.test(line.trim())) {
          if (cur.rawLines.some(l => l.trim())) {
            modules.push(cur);
            sectionIdx++;
            cur = { title: `${Importer.cleanTitle(docTitle)} - Part ${sectionIdx}`, rawLines: [] };
          }
        } else cur.rawLines.push(line);
      }
    }
    if (cur && cur.rawLines.some(l => l.trim())) modules.push(cur);
    if (!modules.length) modules.push({ title: Importer.cleanTitle(docTitle), rawLines: cleanLines });

    const contentWords = text => text.replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/[#*_`>~]/g, ' ').split(/\s+/).filter(w => w.length > 2).length;

    return {
      docTitle: Importer.cleanTitle(docTitle),
      docDesc: docDesc.trim(),
      docIcon: docIcon,
      docUrl: docUrl,
      modules: modules
        .filter(m => contentWords(m.rawLines.join('\n')) >= 40)
        .map(m => {
          let sectionUrl = '';
          const filteredLines = m.rawLines.filter(line => {
            const um = line.match(/^URL Source:\s*(.+)/i);
            if (um) { sectionUrl = um[1].trim(); return false; }
            return true;
          });
          return { title: m.title, content: filteredLines.join('\n'), reference_url: sectionUrl || docUrl };
        })
    };
  },
  renderFileModuleList() {
    const el = $$('file-module-list');
    const actEl = $$('upload-actions');
    const countEl = $$('upload-module-count');
    if(!el) return;
    if (!Importer.fileModules.length) { el.innerHTML = ''; if(actEl) actEl.classList.add('hidden'); return; }
    const totalMods = Importer.fileModules.reduce((s, f) => s + f.subModules.length, 0);
    if(countEl) countEl.textContent = `${Importer.fileModules.length} files · ${totalMods} modules total`;
    if(actEl) actEl.classList.remove('hidden');
    el.innerHTML = Importer.fileModules.map((fm, fi) => `
      <div class="card" style="margin-bottom:var(--space-3);padding:var(--space-3) var(--space-4);">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <div style="font-weight:600;">${esc(fm.name)} (${fm.subModules.length} sections)</div>
          <button class="btn btn-ghost btn-sm" style="color:var(--fail)" onclick="Importer.removeFileModule(${fi})">✕</button>
        </div>
      </div>`).join('');
  },
  removeFileModule(i) { Importer.fileModules.splice(i, 1); Importer.renderFileModuleList(); },
  proceedFromUpload() {
    if (!Importer.fileModules.length) return Toast.err('Add at least one file first.');
    const totalMods = Importer.fileModules.reduce((s, f) => s + f.subModules.length, 0);
    const MAX_MODS = 20;
    if (totalMods > MAX_MODS) {
      Toast.err(`${totalMods} modules detected — max is ${MAX_MODS}. Remove ${totalMods - MAX_MODS} module(s) from the list above before proceeding.`);
      return;
    }
    Importer.parsedModules = [];
    Importer.fileModules.forEach(fm => fm.subModules.forEach(sm => Importer.parsedModules.push({ ...sm, reference_url: sm.reference_url || fm.sourceUrl || '' })));

    const first = Importer.fileModules[0];
    $$('ai-course-title').value = first.name;
    $$('ai-course-desc').value = first.description || '';
    $$('ai-course-icon').value = first.icon || '📋';

    Importer.renderModulePreview();
    Importer.goPhase(2);
  },
  renderModulePreview() {
    const el = $$('module-preview'); if(!el) return;
    el.innerHTML = `
      <div style="font-size:var(--text-sm);font-weight:600;color:var(--ink-2);margin-bottom:var(--space-3);">
        Review and edit module titles and source URLs before generating.
      </div>
      <div style="display:flex;align-items:center;gap:var(--space-3);margin-bottom:var(--space-3);">
        <button class="btn btn-secondary btn-sm" id="btn-merge-modules" onclick="Importer.mergeSelected()" disabled>Merge selected</button>
        <span style="font-size:var(--text-xs);color:var(--ink-3);">Tick short modules on the same topic to combine them into one.</span>
      </div>` +
    Importer.parsedModules.map((m, i) => {
      const wc = (m.content || '').trim().split(/\s+/).length;
      return `
      <div class="card" style="margin-bottom:var(--space-2);padding:var(--space-3);">
        <div style="display:flex;align-items:center;gap:var(--space-2);margin-bottom:var(--space-2);">
          <input type="checkbox" class="merge-chk" data-i="${i}" onchange="Importer.updateMergeBtn()" aria-label="Select module ${i+1} to merge">
          <span style="font-size:var(--text-xs);font-weight:700;color:var(--ink-4);white-space:nowrap;">MODULE ${i+1}</span>
          <span style="font-size:10px;color:var(--ink-4);margin-left:auto;">~${wc} words</span>
        </div>
        <input type="text" value="${esc(m.title)}"
          style="width:100%;font-weight:600;border:1px solid var(--border);border-radius:4px;padding:5px 8px;background:var(--bg);color:var(--ink-1);font-size:var(--text-sm);"
          placeholder="Module title"
          onchange="Importer.parsedModules[${i}].title = this.value">
        <input type="url" value="${esc(m.reference_url || '')}"
          style="width:100%;margin-top:6px;font-size:11px;border:1px solid var(--border);border-radius:4px;padding:4px 8px;background:var(--bg);color:var(--ink-3);"
          placeholder="Source URL (auto-detected from scraper)"
          onchange="Importer.parsedModules[${i}].reference_url = this.value">
      </div>`;
    }).join('');
  },

  updateMergeBtn() {
    const n = document.querySelectorAll('.merge-chk:checked').length;
    const btn = $$('btn-merge-modules');
    if (btn) { btn.disabled = n < 2; btn.textContent = n >= 2 ? `Merge ${n} selected` : 'Merge selected'; }
  },
  mergeSelected() {
    const idx = [...document.querySelectorAll('.merge-chk:checked')].map(c => +c.dataset.i).sort((a, b) => a - b);
    if (idx.length < 2) return Toast.err('Select at least two modules to merge.');
    const picked = idx.map(i => Importer.parsedModules[i]);
    const merged = {
      title: picked[0].title,
      content: Importer.combinePages(picked.map(m => ({ title: m.title, content: m.content }))),
      reference_url: picked.map(m => m.reference_url).find(Boolean) || ''
    };
    Importer.parsedModules = Importer.parsedModules.filter((_, i) => !idx.includes(i) || i === idx[0]);
    Importer.parsedModules[idx[0]] = merged;
    Importer.renderModulePreview();
    Toast.ok(`Merged ${idx.length} modules. Rename it if needed.`);
  },

  async startGeneration() {
    if (Importer.isGenerating) return;
    const claudeInput = $$('claude-api-key')?.value.trim();
    const geminiInput = $$('gemini-api-key')?.value.trim();
    if (claudeInput) sessionStorage.setItem('trainflow_claude_key', claudeInput);
    if (geminiInput) sessionStorage.setItem('trainflow_gemini_key', geminiInput);

    const CHAR_LIMIT = Importer.MODULE_CHAR_LIMIT;
    const longMods = Importer.parsedModules.filter(m => (m.content || '').length > CHAR_LIMIT);
    if (longMods.length > 0) {
      Toast.info(`${longMods.length} module(s) exceed ${CHAR_LIMIT} characters — only the first ${CHAR_LIMIT} chars will be used for AI generation. Consider trimming long modules for best results.`);
    }

    Importer.isGenerating = true;
    try {
    $$('gen-claude').classList.add('hidden');
    $$('gen-api').classList.remove('hidden');
    Importer.generatedCourse = null;
    Importer.goPhase(3);

    const qCount   = parseInt($$('q-per-mod')?.value   || '5');
    const difficulty = $$('q-difficulty')?.value || 'applied';
    const focus      = $$('q-focus')?.value      || 'howto';
    const total = Importer.parsedModules.length;

    const listEl = $$('gen-module-list'); if(!listEl) return;
    listEl.innerHTML = Importer.parsedModules.map((m, i) => `
      <div style="padding:10px 0;border-bottom:1px solid var(--rule-2);">
        <div style="display:flex;align-items:center;gap:12px;">
          <div id="gendot-${i}" class="gen-dot" style="background:var(--ink-4);width:8px;height:8px;border-radius:50%;flex-shrink:0;"></div>
          <div style="flex:1">
            <div style="font-weight:600;font-size:13px" id="gentitle-${i}">${esc(m.title)}</div>
            <div style="display:flex;gap:12px;margin-top:2px">
              <span id="genstatus-q-${i}" style="font-size:10px;color:var(--ink-4)">Content: waiting</span>
              <span id="genstatus-s-${i}" style="font-size:10px;color:var(--ink-4)">Summary: waiting</span>
            </div>
          </div>
        </div>
      </div>`).join('');

    const generatedModules = [];

    // PASS 1: QUESTIONS
    $$('gen-pass-label').textContent = 'Pass 1: Writing Questions';
    for (let i = 0; i < total; i++) {
      const mod = Importer.parsedModules[i];
      const dot = $$(`gendot-${i}`);
      const qStatus = $$(`genstatus-q-${i}`);
      if(dot) dot.style.background = 'var(--brand-1)';
      qStatus.innerHTML = '<span style="color:var(--brand-1)">Generating…</span>';
      $$('gen-progress-label').textContent = `${i + 1} of ${total}`;
      $$('gen-prog-bar').style.width = `${(i / total) * 50}%`;

      try {
        const prompt = Importer._buildQuestionPrompt(mod.title, mod.content, qCount, difficulty, focus);
        const res = await Importer.callAI(prompt, "You are an expert instructional designer. Return JSON only, no markdown.", 3000);
        const parsed = JSON.parse(res.text.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim());
        const problems = [];
        const questions = (Array.isArray(parsed.questions) ? parsed.questions : Array.isArray(parsed) ? parsed : [])
          .map((q, qi) => Importer.shuffleOptions(Importer.normalizeQuestion(q, `question ${qi + 1}`, problems)));
        if (problems.length || !questions.length) throw new Error(problems[0] || 'No questions returned');
        const aiTitle = parsed.title || mod.title;
        const objectives = Array.isArray(parsed.learning_objectives) ? parsed.learning_objectives : [];
        const titleEl = $$(`gentitle-${i}`);
        if (titleEl && aiTitle !== mod.title) titleEl.textContent = aiTitle;
        generatedModules.push({ ...mod, title: aiTitle, learning_objectives: objectives, questions, _provider: res.provider });
        qStatus.innerHTML = `<span style="color:var(--pass)">✓ ${questions.length} q · ${objectives.length} objectives</span>`;
      } catch(err) {
        console.error(err);
        qStatus.innerHTML = `<span style="color:var(--fail)">✗ Failed</span>`;
        generatedModules.push({ ...mod, questions: [], learning_objectives: [], failed: true });
      }
    }

    // PASS 2: SUMMARIES
    $$('gen-pass-label').textContent = 'Pass 2: Creating Summaries';
    for (let i = 0; i < generatedModules.length; i++) {
      const mod = generatedModules[i];
      const sStatus = $$(`genstatus-s-${i}`);
      const dot = $$(`gendot-${i}`);
      sStatus.innerHTML = '<span style="color:var(--brand-1)">Writing…</span>';
      $$('gen-progress-label').textContent = `${i + 1} of ${total}`;
      $$('gen-prog-bar').style.width = `${50 + (i / total) * 50}%`;

      try {
        const prompt = `Write a learner-friendly summary of this training module.
        MODULE: ${mod.title}
        CONTENT: ${mod.content.slice(0, Importer.MODULE_CHAR_LIMIT)}

        Return a single string (max 250 chars) that provides a clear overview of the key takeaways.`;
        const res = await Importer.callAI(prompt, "You are a senior instructional designer.", 500);
        generatedModules[i].summary = res.text.trim();
        sStatus.innerHTML = `<span style="color:var(--pass)">✓ Ready</span>`;
        if(dot) dot.style.background = 'var(--pass)';
      } catch(err) {
        sStatus.innerHTML = `<span style="color:var(--ink-4)">✗ Skipped</span>`;
        if(dot && !mod.failed) dot.style.background = 'var(--pass)';
      }
    }

    $$('gen-pass-label').textContent = 'Generation complete!';
    $$('gen-prog-bar').style.width = '100%';
    Importer.generatedCourse = {
      title: $$('ai-course-title').value.trim(),
      icon:  $$('ai-course-icon').value || '📋',
      description: $$('ai-course-desc').value.trim(),
      modules: generatedModules
    };
    Importer.renderReview();
    Importer.goPhase(4);
    Importer.isGenerating = false;
    } catch(fatalErr) {
      console.error('Generation failed:', fatalErr);
      Importer.isGenerating = false;
      Importer.generatedCourse = null;
      Importer.goPhase(2);
      Toast.err('Generation failed: ' + fatalErr.message + '. Please try again.');
    }
  },

  _buildQuestionPrompt(title, content, qCount, difficulty, focus) {
    return `You are an expert instructional designer. Analyze this training module and return a JSON object.

MODULE TITLE (may be generic): ${title}
CONTENT:
${content.slice(0, Importer.MODULE_CHAR_LIMIT)}

Return ONLY this JSON structure (no markdown, no extra text):
{
  "title": "A concise, descriptive module title (max 8 words, derived from the actual content)",
  "learning_objectives": ["Learners will be able to ...", "Understand ...", "Apply ..."],
  "questions": [
    {"question": "...", "options": ["A", "B", "C", "D"], "correct_index": 0, "explanation": "Why this answer is correct..."}
  ]
}

RULES:
- Write exactly ${qCount} questions
- ${Importer.FOCUS[focus] || Importer.FOCUS.general}
- ${Importer.DIFFICULTY[difficulty] || Importer.DIFFICULTY.applied}
- Each question must have exactly 4 options
- learning_objectives: 3-5 bullet points starting with action verbs
- title: must reflect the actual content, not be generic like "Part 2"`;
  },

  // ── Review (editable) ─────────────────────────────────────────────────────
  // Every module carries a stable `_rid` ("m1", "m2"…) that Claude's reply is matched on.
  ensureRids(c) {
    const used = new Set(c.modules.map(m => m._rid).filter(Boolean));
    let n = 0;
    c.modules.forEach(m => {
      if (m._rid) return;
      do { n++; } while (used.has(`m${n}`));
      m._rid = `m${n}`; used.add(m._rid);
    });
  },

  renderReview() {
    const el = $$('review-modules'); if (!el || !Importer.generatedCourse) return;
    const c = Importer.generatedCourse;
    Importer.ensureRids(c);
    const letters = ['A', 'B', 'C', 'D'];
    const total = c.modules.reduce((s, m) => s + (m.questions?.length || 0), 0);

    const header = `<div class="card rv-head">
      <div class="rv-eyebrow">Course preview</div>
      <div class="rv-course-title">${esc(c.icon || '📋')} ${esc(c.title || 'Untitled')}</div>
      ${c.description ? `<div class="rv-course-desc">${esc(c.description)}</div>` : ''}
      <div class="rv-meta">${c.modules.length} module${c.modules.length !== 1 ? 's' : ''} · ${total} question${total !== 1 ? 's' : ''} · every field below is editable</div>
    </div>`;

    const questionHtml = (m, mi, q, qi) => `
      <fieldset class="rv-q">
        <legend>Question ${qi + 1}</legend>
        <input type="text" aria-label="Question ${qi + 1} text" value="${esc(q.question)}" onchange="Importer.setQ(${mi},${qi},'question',this.value)">
        ${[0, 1, 2, 3].map(oi => `
          <div class="rv-opt">
            <input type="radio" name="rv-c-${mi}-${qi}" ${oi === q.correct_index ? 'checked' : ''} aria-label="Option ${letters[oi]} is the correct answer" onchange="Importer.setCorrect(${mi},${qi},${oi})">
            <span class="rv-letter" aria-hidden="true">${letters[oi]}</span>
            <input type="text" aria-label="Option ${letters[oi]}" value="${esc((q.options || [])[oi] || '')}" onchange="Importer.setOpt(${mi},${qi},${oi},this.value)">
          </div>`).join('')}
        <input type="text" aria-label="Explanation" placeholder="Why the correct answer is right" value="${esc(q.explanation)}" onchange="Importer.setQ(${mi},${qi},'explanation',this.value)">
        <button class="btn btn-danger-ghost btn-sm" onclick="Importer.removeQuestion(${mi},${qi})">Remove question</button>
      </fieldset>`;

    const modulesHtml = c.modules.map((m, mi) => {
      const qs = m.questions || [];
      const words = (m.content || '').trim().split(/\s+/).filter(Boolean).length;
      return `<section class="card rv-mod">
        <div class="rv-mod-head">
          <span class="rv-eyebrow">Module ${mi + 1}</span>
          <span class="chip ${qs.length ? 'chip-green' : 'chip-red'}">${qs.length ? `${qs.length} question${qs.length !== 1 ? 's' : ''}` : 'No questions yet'}</span>
          <div class="rv-actions">
            <button class="btn btn-outline btn-sm" onclick="Importer.copyModulePrompt(${mi})">Redo with Claude</button>
            <button class="btn btn-danger-ghost btn-sm" onclick="Importer.removeModule(${mi})" aria-label="Remove module ${mi + 1}">Remove</button>
          </div>
        </div>
        <div class="field"><label for="rv-t-${mi}">Title</label>
          <input id="rv-t-${mi}" type="text" value="${esc(m.title)}" onchange="Importer.setMod(${mi},'title',this.value)"></div>
        <div class="field"><label for="rv-s-${mi}">Summary</label>
          <textarea id="rv-s-${mi}" rows="2" onchange="Importer.setMod(${mi},'summary',this.value)">${esc(m.summary || '')}</textarea></div>
        <div class="field"><label for="rv-o-${mi}">Learning objectives (one per line)</label>
          <textarea id="rv-o-${mi}" rows="3" onchange="Importer.setObjectives(${mi},this.value)">${esc((m.learning_objectives || []).join('\n'))}</textarea></div>
        ${m.reference_url ? `<div class="rv-source"><span class="rv-source-icon">${ICON.link}</span><span>Source:</span><a href="${esc(m.reference_url)}" target="_blank" rel="noopener noreferrer">${esc(m.reference_url)}</a></div>` : ''}
        <details class="rv-lesson"><summary>Lesson content (~${words} words)</summary>
          <textarea rows="12" aria-label="Lesson content for module ${mi + 1}" onchange="Importer.setMod(${mi},'content',this.value)">${esc(m.content || '')}</textarea></details>
        ${qs.map((q, qi) => questionHtml(m, mi, q, qi)).join('')}
        <button class="btn btn-outline btn-sm" onclick="Importer.addQuestion(${mi})">+ Add question</button>
      </section>`;
    }).join('');

    el.innerHTML = header + modulesHtml;
  },

  setMod(mi, key, value) {
    Importer.generatedCourse.modules[mi][key] = key === 'content' ? value : value.trim();
    Importer.saveDraft();
  },
  setObjectives(mi, text) {
    Importer.generatedCourse.modules[mi].learning_objectives = text.split('\n').map(s => s.trim()).filter(Boolean);
    Importer.saveDraft();
  },
  setQ(mi, qi, key, value) { Importer.generatedCourse.modules[mi].questions[qi][key] = value.trim(); Importer.saveDraft(); },
  setOpt(mi, qi, oi, value) { Importer.generatedCourse.modules[mi].questions[qi].options[oi] = value.trim(); Importer.saveDraft(); },
  setCorrect(mi, qi, oi) { Importer.generatedCourse.modules[mi].questions[qi].correct_index = oi; Importer.saveDraft(); },
  addQuestion(mi) {
    Importer.generatedCourse.modules[mi].questions.push({ question: '', options: ['', '', '', ''], correct_index: 0, explanation: '' });
    Importer.saveDraft(); Importer.renderReview();
  },
  removeQuestion(mi, qi) {
    Importer.generatedCourse.modules[mi].questions.splice(qi, 1);
    Importer.saveDraft(); Importer.renderReview();
  },
  removeModule(mi) {
    const c = Importer.generatedCourse;
    if (!confirm(`Remove module "${c.modules[mi].title}" from this course?`)) return;
    c.modules.splice(mi, 1);
    Importer.saveDraft(); Importer.renderReview();
  },

  // Returns a list of problems that must be fixed before the course can be saved.
  validateCourse(c) {
    const errors = [];
    if (!Importer.str(c.title)) errors.push('The course needs a title (go back to Configure).');
    if (!c.modules.length) errors.push('The course has no modules.');
    c.modules.forEach((m, mi) => {
      const label = `Module ${mi + 1}${m.title ? ` "${m.title}"` : ''}`;
      if (!Importer.str(m.title)) errors.push(`${label}: missing title.`);
      if (!Importer.str(m.content)) errors.push(`${label}: lesson content is empty.`);
      if (!(m.questions || []).length) errors.push(`${label}: needs at least one question.`);
      (m.questions || []).forEach((q, qi) => Importer.normalizeQuestion(q, `${label}, question ${qi + 1}`, errors));
    });
    return errors;
  },

  // ── Draft recovery (survives a refresh or closed tab) ─────────────────────
  DRAFT_KEY: 'trainflow_import_draft',
  saveDraft() {
    if (!Importer.parsedModules.length && !Importer.generatedCourse) return;
    try {
      localStorage.setItem(Importer.DRAFT_KEY, JSON.stringify({
        ts: Date.now(), phase: Importer.phase, parsedModules: Importer.parsedModules,
        generatedCourse: Importer.generatedCourse, settings: Importer.settings,
        form: { title: $$('ai-course-title')?.value || '', icon: $$('ai-course-icon')?.value || '', desc: $$('ai-course-desc')?.value || '' }
      }));
    } catch { /* storage full or blocked: drafts are a convenience only */ }
  },
  loadDraft() {
    try { return JSON.parse(localStorage.getItem(Importer.DRAFT_KEY) || 'null'); } catch { return null; }
  },
  clearDraft() {
    try { localStorage.removeItem(Importer.DRAFT_KEY); } catch { /* nothing to clear */ }
    $$('imp-draft-banner')?.classList.add('hidden');
  },
  renderDraftBanner() {
    const el = $$('imp-draft-banner'); if (!el) return;
    const d = Importer.loadDraft();
    const fresh = !Importer.fileModules.length && !Importer.parsedModules.length && !Importer.generatedCourse;
    if (!d || !fresh) { el.classList.add('hidden'); return; }
    const title = d.form?.title || d.generatedCourse?.title || 'Untitled course';
    $$('imp-draft-text').textContent = `Unfinished import: "${title}", saved ${new Date(d.ts).toLocaleString()}.`;
    el.classList.remove('hidden');
  },
  resumeDraft() {
    const d = Importer.loadDraft(); if (!d) return;
    Importer.parsedModules = d.parsedModules || [];
    Importer.generatedCourse = d.generatedCourse || null;
    Importer.settings = { ...Importer.DEFAULT_SETTINGS, ...(d.settings || {}) };
    $$('ai-course-title').value = d.form?.title || '';
    $$('ai-course-icon').value = d.form?.icon || '';
    $$('ai-course-desc').value = d.form?.desc || '';
    $$('q-per-mod').value = String(Importer.settings.count);
    $$('q-difficulty').value = Importer.settings.difficulty;
    $$('q-focus').value = Importer.settings.focus;
    $$('imp-draft-banner')?.classList.add('hidden');
    Importer.renderModulePreview();
    if (d.phase === 4 && Importer.generatedCourse) { Importer.renderReview(); Importer.goPhase(4); }
    else if (d.phase === 3 && Importer.generatedCourse) { Importer.showClaudePanel(); Importer.goPhase(3); }
    else Importer.goPhase(2);
  },

  async saveAiCourse() {
    const btn = document.querySelector('[onclick="App.saveAiCourse()"]');
    const errBox = $$('review-errors');
    const errors = Importer.validateCourse(Importer.generatedCourse);
    if (errBox) {
      errBox.classList.toggle('hidden', !errors.length);
      errBox.innerHTML = errors.length ? `<strong>Fix these before saving:</strong><ul>${errors.map(e => `<li>${esc(e)}</li>`).join('')}</ul>` : '';
    }
    if (errors.length) { errBox?.scrollIntoView({ behavior: 'smooth', block: 'center' }); return; }

    // Internal bookkeeping (_rid, _provider) and `failed` flags never go to the server.
    const payload = JSON.stringify(Importer.generatedCourse, (k, v) => (k.startsWith('_') || k === 'failed' ? undefined : v));
    const payloadKB = Math.round(payload.length / 1024);
    if (payloadKB > 500) {
      const ok = confirm(`This course is large (~${payloadKB}KB). Saving may take a moment. Continue?`);
      if (!ok) return;
    }

    if(btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    try {
      await api('/api/courses', { method: 'POST', body: payload, signal: controller.signal });
      Toast.ok('Course saved!');
      Importer.fileModules = []; Importer.parsedModules = []; Importer.generatedCourse = null; Importer.isGenerating = false;
      Importer.clearDraft();
      Admin.nav('courses');
    } catch(e) {
      const msg = e.name === 'AbortError'
        ? 'Save timed out — the course may be too large. Try reducing the number of modules and retry.'
        : e.message;
      Toast.err(msg);
    } finally {
      clearTimeout(timeout);
      if(btn) { btn.disabled = false; btn.textContent = 'Save to Database'; }
    }
  }
};
