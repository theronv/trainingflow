// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — AI Course Importer
// ══════════════════════════════════════════════════════════

const Importer = {
  fileModules: [],
  parsedModules: [],
  generatedCourse: null,
  isGenerating: false,

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

  // Returns { course, errors }. Tolerates code fences / surrounding prose.
  parseCourseJson(text) {
    const errors = [];
    let raw = String(text || '').replace(/```json\s*/gi, '').replace(/```/g, '').trim();
    const a = raw.indexOf('{'), b = raw.lastIndexOf('}');
    if (a < 0 || b <= a) return { course: null, errors: ['No JSON object found.'] };
    let data;
    const body = raw.slice(a, b + 1);
    try { data = JSON.parse(body); }
    catch (e) {
      // Chat windows often "smart-quote" copied text (“ ” instead of "); repair and retry.
      try { data = JSON.parse(body.replace(/[\u201C\u201D\u201E\u201F\u2033]/g, '"')); }
      catch (e2) { return { course: null, errors: ['Invalid JSON: ' + e.message] }; }
    }

    const str = v => (typeof v === 'string' ? v.trim() : '');
    if (!str(data.title)) errors.push('Missing course "title".');
    if (!Array.isArray(data.modules) || !data.modules.length) { errors.push('"modules" must be a non-empty array.'); return { course: null, errors }; }

    const modules = data.modules.map((m, mi) => {
      const label = `Module ${mi + 1}`;
      if (!str(m.title)) errors.push(`${label}: missing "title".`);
      if (!str(m.content)) errors.push(`${label}: missing "content".`);
      const questions = (Array.isArray(m.questions) ? m.questions : []).map((q, qi) => {
        const ql = `${label}, question ${qi + 1}`;
        const opts = Array.isArray(q.options) ? q.options.map(str)
          : [q.option_a, q.option_b, q.option_c, q.option_d].map(str);
        if (!str(q.question)) errors.push(`${ql}: missing "question".`);
        if (opts.filter(Boolean).length < 2 || opts.slice(0, 4).some(o => !o)) errors.push(`${ql}: needs 4 non-empty options.`);
        let ci = q.correct_index;
        if (typeof ci === 'string' && /^[a-d]$/i.test(ci.trim())) ci = 'abcd'.indexOf(ci.trim().toLowerCase());
        ci = Number(ci);
        if (!Number.isInteger(ci) || ci < 0 || ci > 3) { errors.push(`${ql}: "correct_index" must be 0-3.`); ci = 0; }
        return { question: str(q.question), options: opts.slice(0, 4), correct_index: ci, explanation: str(q.explanation) };
      });
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

  goPhase(n) {
    if (n === 1) Importer.loadSavedAiKeys();
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
  async importFromUrls() {
    const raw = $$('imp-url-input').value;
    const urls = [...new Set(raw.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')))];
    if (!urls.length) return Toast.err('Paste at least one URL.');
    if (urls.length > 20) return Toast.err('Import up to 20 pages at a time.');
    const btn = $$('btn-imp-urls'), list = $$('imp-url-results'), status = $$('imp-url-status');
    btn.disabled = true;
    list.innerHTML = urls.map((u, i) => `<li id="imp-url-${i}">⏳ ${esc(u)}</li>`).join('');
    let ok = 0;
    for (let i = 0; i < urls.length; i++) {
      const row = $$(`imp-url-${i}`);
      status.textContent = `Fetching ${i + 1} of ${urls.length}…`;
      try {
        const data = await Importer.fetchPage(urls[i]);
        const slug = decodeURIComponent(new URL(data.url).pathname.split('/').filter(Boolean).pop() || new URL(data.url).hostname);
        Importer.addFileModule(data.markdown, slug.replace(/^\d+[-_]/, '').replace(/\.\w+$/, ''));
        row.innerHTML = `<span style="color:var(--pass)">✓</span> ${esc(urls[i])}`;
        ok++;
      } catch (err) {
        row.innerHTML = `<span style="color:var(--fail)">✗</span> ${esc(urls[i])} — ${esc(err.message)}`;
      }
      if (i < urls.length - 1) await new Promise(r => setTimeout(r, 1000)); // be polite to the source
    }
    status.textContent = ok ? `${ok} of ${urls.length} imported.` : 'Nothing imported.';
    btn.disabled = false;
    if (ok) $$('imp-url-input').value = '';
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
  parseMdToModules(raw, defaultTitle) {
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
      </div>` +
    Importer.parsedModules.map((m, i) => {
      const wc = (m.content || '').trim().split(/\s+/).length;
      return `
      <div class="card" style="margin-bottom:var(--space-2);padding:var(--space-3);">
        <div style="display:flex;align-items:center;gap:var(--space-2);margin-bottom:var(--space-2);">
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

  async startGeneration() {
    if (Importer.isGenerating) return;
    const claudeInput = $$('claude-api-key')?.value.trim();
    const geminiInput = $$('gemini-api-key')?.value.trim();
    if (claudeInput) sessionStorage.setItem('trainflow_claude_key', claudeInput);
    if (geminiInput) sessionStorage.setItem('trainflow_gemini_key', geminiInput);

    const CHAR_LIMIT = 4000;
    const longMods = Importer.parsedModules.filter(m => (m.content || '').length > CHAR_LIMIT);
    if (longMods.length > 0) {
      Toast.info(`${longMods.length} module(s) exceed ${CHAR_LIMIT} characters — only the first ${CHAR_LIMIT} chars will be used for AI generation. Consider trimming long modules for best results.`);
    }

    Importer.isGenerating = true;
    try {
    Importer.goPhase(3);

    const qCount   = parseInt($$('q-per-mod')?.value   || '5');
    const difficulty = $$('q-difficulty')?.value || 'applied';
    const focus      = $$('q-focus')?.value      || 'general';
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
        const questions = parsed.questions || parsed;
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
        CONTENT: ${mod.content.slice(0, 4000)}

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
    const focusInstr = {
      general: 'Test comprehension of the key concepts.',
      support: 'Focus on support scenarios and customer interactions.',
      process: 'Focus on the correct sequence of steps and procedures.',
      technical: 'Focus on specific values, limits, and technical requirements.'
    };
    const diffInstr = {
      foundational: 'Test basic recall and recognition.',
      applied: 'Test application of knowledge in scenarios.',
      analytical: 'Test judgment and nuanced understanding.'
    };
    return `You are an expert instructional designer. Analyze this training module and return a JSON object.

MODULE TITLE (may be generic): ${title}
CONTENT:
${content.slice(0, 4000)}

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
- ${focusInstr[focus]}
- ${diffInstr[difficulty]}
- Each question must have exactly 4 options
- learning_objectives: 3-5 bullet points starting with action verbs
- title: must reflect the actual content, not be generic like "Part 2"`;
  },

  renderReview() {
    const el = $$('review-modules'); if(!el) return;
    const c = Importer.generatedCourse;
    const letters = ['A','B','C','D'];

    const header = `<div class="card" style="margin-bottom:var(--space-5);background:var(--bg-2);border:1px solid var(--border);">
      <div style="font-size:var(--text-xs);font-weight:700;color:var(--ink-4);text-transform:uppercase;letter-spacing:.06em;">Course Preview</div>
      <div style="font-size:var(--text-lg);font-weight:700;margin-top:2px;">${esc(c.icon || '📋')} ${esc(c.title || 'Untitled')}</div>
      ${c.description ? `<div style="font-size:var(--text-sm);color:var(--ink-3);margin-top:4px;">${esc(c.description)}</div>` : ''}
      <div style="font-size:11px;color:var(--ink-4);margin-top:var(--space-3);">${c.modules.length} module${c.modules.length !== 1 ? 's' : ''} · ${c.modules.reduce((s,m) => s + (m.questions?.length || 0), 0)} questions total</div>
    </div>`;

    const modulesHtml = c.modules.map((m, mi) => {
      const qCount = m.questions?.length || 0;
      const failed = m.failed;
      const objectives = Array.isArray(m.learning_objectives) ? m.learning_objectives : [];

      const objectivesHtml = objectives.length ? `
        <div style="margin-top:var(--space-3);">
          <div style="font-size:10px;font-weight:700;color:var(--ink-4);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">Learning Objectives</div>
          <ul style="margin:0;padding-left:var(--space-5);">
            ${objectives.map(o => `<li style="font-size:12px;color:var(--ink-2);margin-bottom:3px;">${esc(o)}</li>`).join('')}
          </ul>
        </div>` : '';

      const sourceHtml = m.reference_url ? `
        <div style="margin-top:var(--space-3);display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg-2);border-radius:6px;border:1px solid var(--border);">
          <span style="display:inline-flex;width:14px;height:14px;color:var(--ink-3);">${ICON.link}</span>
          <span style="font-size:11px;color:var(--ink-4);">Source:</span>
          <a href="${esc(m.reference_url)}" target="_blank" rel="noopener noreferrer" style="font-size:11px;color:var(--brand-1);text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(m.reference_url)}</a>
        </div>` : '';

      const questionsHtml = qCount ? m.questions.map((q, qi) => `
        <div style="margin-top:var(--space-4);padding-top:var(--space-3);border-top:1px solid var(--rule-2);">
          <div style="font-weight:600;font-size:var(--text-sm);margin-bottom:var(--space-2);">Q${qi + 1}. ${esc(q.question)}</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
            ${(q.options || []).map((opt, oi) => opt ? `
              <div style="font-size:var(--text-xs);padding:var(--space-2) var(--space-3);border-radius:var(--radius-md);border:1px solid var(--border);${oi === q.correct_index ? 'background:var(--pass-lt);border-color:var(--pass-border);color:var(--pass);font-weight:600;' : 'color:var(--ink-3);'}">
                <span style="opacity:.5;margin-right:4px">${letters[oi]}</span> ${esc(opt)}
              </div>` : '').join('')}
          </div>
          ${q.explanation ? `<div style="font-size:11px;color:var(--ink-4);margin-top:var(--space-2);padding:8px;background:var(--bg-2);border-radius:4px"><strong>Explanation:</strong> ${esc(q.explanation)}</div>` : ''}
        </div>`).join('') : '';

      return `<div class="card" style="margin-bottom:var(--space-4);">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:var(--space-3);">
          <div style="flex:1;min-width:0;">
            <div style="font-size:var(--text-xs);font-weight:700;color:var(--ink-4);text-transform:uppercase;letter-spacing:.06em;">Module ${mi + 1}</div>
            <div style="font-weight:700;margin-top:2px;">${esc(m.title)}</div>
            ${m.summary ? `<div style="font-size:var(--text-sm);color:var(--ink-2);margin-top:8px;line-height:1.5;padding-left:12px;border-left:2px solid var(--pass)">${esc(m.summary)}</div>` : ''}
            ${objectivesHtml}
            ${sourceHtml}
          </div>
          <div style="flex-shrink:0;">
            ${failed
              ? '<span class="chip chip-red">✗ Failed</span>'
              : `<span class="chip chip-green" style="font-size:10px">✓ ${qCount} questions</span> <span class="chip" style="background:var(--bg-2);color:var(--brand-1);font-size:9px;">${esc(m._provider || 'AI')}</span>`}
          </div>
        </div>
        ${questionsHtml}
      </div>`;
    }).join('');

    el.innerHTML = header + modulesHtml;
  },

  async saveAiCourse() {
    const btn = document.querySelector('[onclick="App.saveAiCourse()"]');

    const payload = JSON.stringify(Importer.generatedCourse);
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
