// ══════════════════════════════════════════════════════════
//  TRAINFLOW — Core Utilities & State
// ══════════════════════════════════════════════════════════

// Shared inline icon set (stroke icons; sized via CSS)
const ICON = {
  moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>',
  sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/></svg>',
  book: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>',
  clip: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="8" y="2" width="8" height="4" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="M9 12h6"/><path d="M9 16h4"/></svg>',
  award: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="6"/><path d="M15.477 12.89 17 22l-5-3-5 3 1.523-9.11"/></svg>',
  chart: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>',
  upload: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/></svg>',
  spark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/></svg>',
  print: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>',
  link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>',
  bulb: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/></svg>',
  alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>',
};

const CONFIG = {
  WORKER_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8787'
    : 'https://trainflow-worker.theronv.workers.dev',
  DEFAULT_BRAND_NAME: 'TrainFlow',
  DEFAULT_TAGLINE: 'Assign, track, and certify your team\'s training — in one place.',
  DEFAULT_C1: '#1B78F2',
  DEFAULT_C2: '#241C59',
  DEFAULT_C3: '#D9631E',
  DEFAULT_PASS: 80,
  DEFAULT_FONT: 'Inter',
  DEFAULT_ICON: '📋',
  MIN_PW_LEN: 8,
  TOAST_MS: 3200,
  FOCUS_DELAY: 80,
};

// Google Fonts query strings for each preset (null = no load needed)
const GFONTS = {
  'Inter':            null,
  'Roboto':           'Roboto:wght@400;500;600;700',
  'Open Sans':        'Open+Sans:ital,wght@0,400;0,500;0,600;0,700',
  'Lato':             'Lato:wght@400;700',
  'Poppins':          'Poppins:wght@400;500;600;700',
  'DM Sans':          'DM+Sans:wght@400;500;600;700',
  'Nunito':           'Nunito:wght@400;500;600;700',
  'Playfair Display': 'Playfair+Display:wght@400;600;700',
  'Merriweather':     'Merriweather:wght@400;700',
};

const WORKER_URL = CONFIG.WORKER_URL;

const StorageUtils = {
  get(key) { try { return sessionStorage.getItem(key); } catch (e) { return null; } },
  set(key, val) { try { sessionStorage.setItem(key, val); } catch (e) { } },
  remove(key) { try { sessionStorage.removeItem(key); } catch (e) { } }
};

function getToken()          { return StorageUtils.get('tf_token'); }
function setToken(t)         { StorageUtils.set('tf_token', t); }
function clearToken()        { StorageUtils.remove('tf_token'); }
function getManagerToken()   { return StorageUtils.get('tf_manager_token'); }
function setManagerToken(t)  { StorageUtils.set('tf_manager_token', t); }
function clearManagerToken() { StorageUtils.remove('tf_manager_token'); }
function getManagerUser()    { try { return JSON.parse(StorageUtils.get('tf_manager_user')); } catch(e){ return null; } }
function setManagerUser(u)   { StorageUtils.set('tf_manager_user', JSON.stringify(u)); }
function clearManagerUser()  { StorageUtils.remove('tf_manager_user'); }
function getLearnerToken()   { return StorageUtils.get('tf_learner_token'); }
function setLearnerToken(t)  { StorageUtils.set('tf_learner_token', t); }
function clearLearnerToken() { StorageUtils.remove('tf_learner_token'); }

function makeApi(getTokenFn, on401) {
  return async function(path, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    const token = getTokenFn();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(WORKER_URL + path, { ...opts, headers });
    if (res.status === 401 && token) { on401(); throw new Error('Session expired'); }
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: res.statusText }));
      throw Object.assign(new Error(body.error || res.statusText), { status: res.status, detail: body.detail });
    }
    return res.json();
  };
}

const adminApi = makeApi(getToken, () => {
  clearToken(); curCourse = null; curModIdx = 0; quizSt = {};
  Toast.err('Session expired. Please sign in again.'); App.show('screen-landing');
});
const managerApi = makeApi(getManagerToken, () => {
  clearManagerToken(); clearManagerUser(); curManager = null; curCourse = null; curModIdx = 0; quizSt = {};
  Toast.err('Session expired. Please sign in again.'); App.show('screen-landing');
});
const learnerApi = makeApi(getLearnerToken, () => {
  clearLearnerToken(); curLearner = null; curCourse = null; curModIdx = 0; quizSt = {};
  Toast.err('Session expired. Please sign in again.'); App.show('screen-landing');
});
// Backward-compat alias — prefer adminApi for admin-scoped calls
const api = adminApi;

let curLearner   = null;
let curManager   = null;
let curCourse    = null;
let curModIdx    = 0;
let quizSt       = {};
let cbState      = { editId: null, mods: [] };
let csvParsed    = null;
const COMP_LIMIT = 50;
let _allLearners = [];
let teamsCache   = [];
let coursesCache = [];
let assignCache  = [];
let sectionsCache = [];
let isDemo       = false;
let brandCache   = { name: CONFIG.DEFAULT_BRAND_NAME, tagline: CONFIG.DEFAULT_TAGLINE, logo: '', c1: CONFIG.DEFAULT_C1, c2: CONFIG.DEFAULT_C2, c3: CONFIG.DEFAULT_C3, pass: CONFIG.DEFAULT_PASS, font: CONFIG.DEFAULT_FONT, fontUrl: '' };

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2,6); }
function $$(id) { return document.getElementById(id); }

const Toast = {
  show(msg, type='info') {
    const el = document.createElement('div');
    el.className = `toast t-${type}`;
    el.textContent = msg;
    document.getElementById('toast-root').appendChild(el);
    setTimeout(() => { el.style.transition='opacity 0.3s'; el.style.opacity='0'; setTimeout(()=>el.remove(),300); }, CONFIG.TOAST_MS);
  },
  ok(m)   { Toast.show(m,'success'); },
  err(m)  { Toast.show(m,'error'); },
  info(m) { Toast.show(m,'info'); }
};

function normCourse(c) {
  return {
    id: c.id, icon: c.icon || CONFIG.DEFAULT_ICON, title: c.title, desc: c.description || '', refUrl: c.reference_url || '',
    mods: (c.modules || []).map(m => ({
      id: m.id, title: m.title, content: m.content || '',
      summary: m.summary || '',
      refUrl: m.reference_url || '',
      objectives: (() => { try { return m.learning_objectives ? JSON.parse(m.learning_objectives) : []; } catch { return []; } })(),
      questions: (m.questions || []).map(q => ({
        id: q.id,
        question: q.question,
        options: [q.option_a, q.option_b, q.option_c, q.option_d],
        correct_index: q.correct_index,
        explanation: q.explanation || '',
      }))
    }))
  };
}
function normRecord(r) { return { cid: r.course_id, learner: r.learner_name, score: r.score, passed: Boolean(r.passed), date: (r.completed_at || 0) * 1000, cid2: r.cert_id || '', }; }
function normBrand(b) { return { name: b.org_name || CONFIG.DEFAULT_BRAND_NAME, tagline: b.tagline || CONFIG.DEFAULT_TAGLINE, logo: b.logo_url || '', c1: b.primary_color || CONFIG.DEFAULT_C1, c2: b.secondary_color || CONFIG.DEFAULT_C2, c3: b.accent_color || CONFIG.DEFAULT_C3, pass: b.pass_threshold ?? CONFIG.DEFAULT_PASS, font: b.font_family || CONFIG.DEFAULT_FONT, fontUrl: b.font_url || '' }; }

// ─── Color Utilities ─────────────────────────────────────
function hexToRgba(hex, alpha) {
  const r = parseInt(hex.slice(1,3),16);
  const g = parseInt(hex.slice(3,5),16);
  const b = parseInt(hex.slice(5,7),16);
  return `rgba(${r},${g},${b},${alpha})`;
}
function darken(hex, percent) {
  let r = parseInt(hex.slice(1,3),16);
  let g = parseInt(hex.slice(3,5),16);
  let b = parseInt(hex.slice(5,7),16);
  r = Math.max(0, Math.floor(r * (1 - percent/100)));
  g = Math.max(0, Math.floor(g * (1 - percent/100)));
  b = Math.max(0, Math.floor(b * (1 - percent/100)));
  return `#${r.toString(16).padStart(2,'0')}${g.toString(16).padStart(2,'0')}${b.toString(16).padStart(2,'0')}`;
}

function applyBrand() {
  const b = brandCache;
  const validHex = (h, def) => (h && /^#[0-9a-fA-F]{6}$/.test(h)) ? h : def;
  const root = document.documentElement.style;

  // --- Primary ---
  const c1 = validHex(b.c1, CONFIG.DEFAULT_C1);
  root.setProperty('--brand',        c1);
  root.setProperty('--brand-dark',   darken(c1, 15));
  root.setProperty('--brand-glow',   hexToRgba(c1, 0.15));
  root.setProperty('--shadow-brand', `0 0 0 3px ${hexToRgba(c1, 0.2)}`);
  root.setProperty('--brand-1', c1); // legacy

  // --- Secondary ---
  const c2 = validHex(b.c2, CONFIG.DEFAULT_C2);
  root.setProperty('--brand-secondary',      c2);
  root.setProperty('--brand-secondary-dark', darken(c2, 15));
  root.setProperty('--brand-secondary-glow', hexToRgba(c2, 0.10));
  root.setProperty('--brand-2', c2); // fix legacy alias

  // --- Accent ---
  const c3 = validHex(b.c3, CONFIG.DEFAULT_C3);
  root.setProperty('--brand-accent',      c3);
  root.setProperty('--brand-accent-dark', darken(c3, 12));
  root.setProperty('--brand-accent-glow', hexToRgba(c3, 0.12));

  // Org name across all surfaces
  ['ldg-brand', 'l-brand', 'a-brand', 'm-brand'].forEach(id => { const el = $$(id); if(el) el.textContent = b.name; });
  const certSig = $$('c-sig-dept');
  if(certSig) certSig.textContent = b.name + ' Training Department';

  // Tagline (dynamic)
  const taglineEl = $$('ldg-tagline');
  if (taglineEl) taglineEl.textContent = b.tagline || CONFIG.DEFAULT_TAGLINE;

  // Logo across all surfaces (topbars + landing + course header)
  const logoSrc = b.logo || '';
  ['l-logo', 'a-logo', 'm-logo', 'ldg-logo', 'ch-logo'].forEach(id => {
    const img = $$(id); if(!img) return;
    if(logoSrc) { img.src = logoSrc; img.classList.remove('hidden'); }
    else { img.src = ''; img.classList.add('hidden'); }
  });

  // Cert logo
  const cLogo = $$('c-logo'); const cLogoWrap = $$('c-logo-wrap');
  if (cLogo && cLogoWrap) {
    if (logoSrc) { cLogo.src = logoSrc; cLogoWrap.classList.remove('hidden'); }
    else { cLogo.src = ''; cLogoWrap.classList.add('hidden'); }
  }

  // Hide/show the diamond accent on topbar brand when logo is present
  document.querySelectorAll('.brand').forEach(el => el.classList.toggle('has-logo', !!logoSrc));

  // Landing: show logo image + name together, or just name (in brand color when no logo)
  const ldgWrap = $$('ldg-logo-wrap');
  if (ldgWrap) ldgWrap.classList.toggle('hidden', !logoSrc);
  const ldgBrand = $$('ldg-brand');
  if (ldgBrand) { ldgBrand.style.display = ''; ldgBrand.style.color = logoSrc ? '' : c1; }

  // Mobile browser theme color
  const themeMeta = document.querySelector('meta[name="theme-color"]');
  if (themeMeta) themeMeta.content = c1;

  // --- Font ---
  const fontFamily = b.font || CONFIG.DEFAULT_FONT;
  const fontUrl    = b.fontUrl || '';

  // Remove any previously injected font elements
  const prevLink  = document.getElementById('brand-font-link');
  const prevStyle = document.getElementById('brand-font-face');
  if (prevLink)  prevLink.remove();
  if (prevStyle) prevStyle.remove();

  if (fontUrl) {
    // Custom uploaded font (base64 data URL)
    const style = document.createElement('style');
    style.id = 'brand-font-face';
    style.textContent = `@font-face { font-family: 'BrandCustomFont'; src: url('${fontUrl}'); font-weight: 100 900; font-style: normal; }`;
    document.head.appendChild(style);
    root.setProperty('--font-body', "'BrandCustomFont', system-ui, sans-serif");
  } else if (fontFamily !== 'Inter' && GFONTS[fontFamily]) {
    const link = document.createElement('link');
    link.id   = 'brand-font-link';
    link.rel  = 'stylesheet';
    link.href = `https://fonts.googleapis.com/css2?family=${GFONTS[fontFamily]}&display=swap`;
    document.head.appendChild(link);
    root.setProperty('--font-body', `'${fontFamily}', system-ui, sans-serif`);
  } else {
    root.setProperty('--font-body', "'Inter', system-ui, sans-serif");
  }
}

function showPage(id) { 
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  const el = $$(id); if(el) el.classList.remove('hidden');
}

const App = {
  async baseInit() {
    const lt = getLearnerToken();
    if (lt) { try { const me = await learnerApi('/api/learners/me'); curLearner = { id: me.id, name: me.name }; } catch { clearLearnerToken(); } }
    const mt = getManagerToken();
    if (mt) { curManager = getManagerUser(); }
    try { const b = await api('/api/brand'); brandCache = normBrand(b); } catch { }
    applyBrand();
  },

  show(id) {
    // 🔐 RBAC / Access Control
    if (id === 'screen-admin' && !getToken()) {
      Toast.err('Unauthorized: Admin access required.');
      return App.show('screen-login');
    }
    if (id === 'screen-manager' && !getManagerToken()) {
      Toast.err('Unauthorized: Manager access required.');
      return App.show('screen-manager-login');
    }
    if (id === 'screen-course' && !getLearnerToken() && !isDemo && !window._adminPreview) {
      Toast.err('Please sign in to view courses.');
      return App.show('screen-landing');
    }

    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    const el = $$(id); if(el) el.classList.add('active');
  },

  startDemo() {
    isDemo = true;
    curLearner = { id: 'demo-id', name: 'Demo Learner' };
    brandCache = { name: 'TrainFlow Demo', tagline: 'Experience the new UI/UX', logo: '', c1: CONFIG.DEFAULT_C1, c2: CONFIG.DEFAULT_C2, c3: CONFIG.DEFAULT_C3, pass: CONFIG.DEFAULT_PASS, font: CONFIG.DEFAULT_FONT, fontUrl: '' };
    applyBrand();
    Toast.ok('Demo mode activated');
    Learner.init();
  },

  goLearner() { App.show('screen-learner'); applyBrand(); if(curLearner) Learner.init(); else showPage('lp-name'); },
  goManager() { App.show('screen-manager-login'); Auth.toggleManagerReg(false); setTimeout(()=>$$('m-login-name').focus(),CONFIG.FOCUS_DELAY); },
  goAdmin()   { App.show('screen-login'); setTimeout(()=>$$('pw-input').focus(),CONFIG.FOCUS_DELAY); },
};
