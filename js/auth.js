// ══════════════════════════════════════════════════════════
//  PREGAME ACADEMY — Authentication Logic
// ══════════════════════════════════════════════════════════

function scheduleExpiryWarning(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    if (!payload.exp) return;
    const msUntilWarn = (payload.exp * 1000) - Date.now() - 5 * 60 * 1000;
    if (msUntilWarn > 0) {
      setTimeout(() => Toast.info('Your session expires in 5 minutes. Save your work and sign in again to continue.'), msUntilWarn);
    }
  } catch(e) { /* ignore */ }
}

// ─── CLERK (email sign-in) ───
// Clerk handles the email/code UI. We exchange its session token at the Worker for the app's
// own JWT, so everything after sign-in is identical to name + password login.
const ClerkAuth = {
  _loading: null,
  load() {
    if (window.Clerk?.loaded) return Promise.resolve(window.Clerk);
    if (ClerkAuth._loading) return ClerkAuth._loading;
    ClerkAuth._loading = new Promise((resolve, reject) => {
      const sc = document.createElement('script');
      sc.src = `${CONFIG.CLERK_FRONTEND_API}/npm/@clerk/clerk-js@5/dist/clerk.browser.js`;
      sc.async = true; sc.crossOrigin = 'anonymous';
      sc.setAttribute('data-clerk-publishable-key', CONFIG.CLERK_PUBLISHABLE_KEY);
      sc.onload = async () => { try {
        // Match Clerk's sign-in modal to the app's brand.
        const cs = getComputedStyle(document.documentElement);
        await window.Clerk.load({ appearance: {
          variables: { colorPrimary: (cs.getPropertyValue('--brand') || '#1565ff').trim(), borderRadius: '6px', fontFamily: 'inherit' },
          layout: { logoImageUrl: new URL(brandCache?.logo || CONFIG.DEFAULT_LOGO, location.href).href, logoPlacement: 'inside' }
        } });
        resolve(window.Clerk);
      } catch (e) { reject(e); } };
      sc.onerror = () => { ClerkAuth._loading = null; reject(new Error('Could not load email sign-in. Check your connection.')); };
      document.head.appendChild(sc);
    });
    return ClerkAuth._loading;
  },
  // Resolves with a fresh Clerk session token once the person has signed in (opens Clerk's modal if needed).
  async token(mode = 'signin') {
    const clerk = await ClerkAuth.load();
    ClerkTrace.add('clerk-loaded', clerk.session ? 'has-session' : 'no-session');
    if (!clerk.session) {
      await new Promise(resolve => {
        const off = clerk.addListener(({ session }) => { if (session) { off(); clerk.closeSignIn(); resolve(); } });
        // Google/social sign-in is a full-page redirect; bring the person back to this exact page.
        const back = location.origin + location.pathname;
        ClerkTrace.add('modal-open', mode);
        if (mode === 'signup') clerk.openSignUp({ forceRedirectUrl: back, signInForceRedirectUrl: back });
        // Sign-in popup: no "Sign up" link. New people use Request access or an invite code.
        else clerk.openSignIn({ forceRedirectUrl: back, signUpForceRedirectUrl: back, appearance: { elements: { footerAction: { display: 'none' } } } });
      });
    }
    return clerk.session.getToken();
  },
  async signOut() { try { if (window.Clerk?.session) await window.Clerk.signOut(); } catch (e) { /* ignore */ } }
};

// Breadcrumbs for sign-in attempts. Kept in localStorage (survives the Google redirect) so that,
// if an attempt dies silently, the landing page can say where.
const ClerkTrace = {
  KEY: 'trainflow_clerk_trace',
  get() { try { return JSON.parse(localStorage.getItem(ClerkTrace.KEY)) || []; } catch (e) { return []; } },
  add(stage, info = '') {
    try {
      const t = ClerkTrace.get().slice(-14);
      t.push(`${new Date().toISOString().slice(11, 19)} ${stage}${info ? ' ' + info : ''}`);
      localStorage.setItem(ClerkTrace.KEY, JSON.stringify(t));
    } catch (e) { /* ignore */ }
  },
  clear() { try { localStorage.removeItem(ClerkTrace.KEY); } catch (e) { /* ignore */ } },
  // An attempt that never reached "done" is shown on the landing page.
  unfinished() { const t = ClerkTrace.get(); return t.length && !/ done$/.test(t[t.length - 1]) ? t : null; }
};

const ClerkPending = {
  KEY: 'trainflow_clerk_pending',
  set(v) { try { sessionStorage.setItem(ClerkPending.KEY, JSON.stringify(v)); } catch (e) { /* ignore */ } },
  get() { try { return JSON.parse(sessionStorage.getItem(ClerkPending.KEY)); } catch (e) { return null; } },
  clear() { try { sessionStorage.removeItem(ClerkPending.KEY); } catch (e) { /* ignore */ } }
};

const Auth = {
  // Sign-in failures stay on screen (a toast vanishes before you can read it).
  _landingNotice(msg) {
    App.show('screen-landing');
    const el = $$('ldg-notice'); if (!el) return Toast.err(msg);
    el.textContent = msg; el.classList.remove('hidden');
  },
  showUnfinishedTrace() {
    const t = ClerkTrace.unfinished();
    if (t && !location.hash.startsWith('#invite')) Auth._landingNotice('Your last sign-in did not finish. Steps recorded: ' + t.join(' → '));
  },
  _clearLandingNotice() { $$('ldg-notice')?.classList.add('hidden'); },
  // ─── REQUEST ACCESS (new learners) ───
  async submitRequestAccess() {
    const name = $$('ra-name').value.trim(), email = $$('ra-email').value.trim();
    if (!name) return Toast.err('Please enter your full name.');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return Toast.err('Please enter a valid email address.');
    const btn = $$('ra-submit'); btn.disabled = true; btn.textContent = 'Sending…';
    try {
      await api('/api/access-requests', { method: 'POST', body: JSON.stringify({ name, email, message: $$('ra-msg').value.trim(), website: $$('ra-website').value }) });
      $$('ra-form').classList.add('hidden'); $$('ra-done').classList.remove('hidden');
      btn.classList.add('hidden'); $$('ra-cancel').textContent = 'Close';
    } catch (e) { Toast.err(e.message || 'Could not send your request.'); }
    finally { btn.disabled = false; btn.textContent = 'Send request'; }
  },
  // ─── EMAIL SIGN-IN (learners + managers; role comes from the account) ───
  async emailSignIn() {
    Auth._clearLandingNotice();
    ClerkTrace.clear(); ClerkTrace.add('click');
    ClerkPending.set({ mode: 'login' });
    try {
      const token = await ClerkAuth.token();
      ClerkTrace.add('token-in-page');
      await Auth._clerkLogin(token);
    } catch (e) {
      await ClerkAuth.signOut();
      Auth._landingNotice(e.message || 'Email sign-in failed.');
    } finally { ClerkPending.clear(); }
  },
  async _clerkLogin(token) {
    ClerkTrace.add('exchange-start');
    const data = await api('/api/auth/clerk/login', { method: 'POST', body: JSON.stringify({ token }) });
    ClerkTrace.add('exchange-ok', data.user?.role);
    Auth._enter(data);
    ClerkTrace.add('done');
  },
  // Google sign-in leaves the page and comes back, losing in-memory state. Remember what the person
  // was doing, and finish it once Clerk has restored their session. Returns true if it took over.
  async resumeClerk() {
    const returning = /[?&]__clerk/.test(location.search);
    // Coming back from Clerk's redirect always means "finish signing in", even if sessionStorage was lost.
    const pending = ClerkPending.get() || (returning ? { mode: 'login' } : null);
    if (!pending) return false;
    ClerkTrace.add('resume-check', `pending=${ClerkPending.get() ? 'y' : 'n'} returning=${returning ? 'y' : 'n'} hash=${location.hash.slice(0, 20)}`);
    const cleanUrl = () => {
      const u = new URL(location.href);
      [...u.searchParams.keys()].filter(k => k.startsWith('__clerk')).forEach(k => u.searchParams.delete(k));
      history.replaceState(null, '', u.pathname + (u.search || '') + u.hash);
    };
    if (!pending) { cleanUrl(); return false; } // handshake only; no sign-in was in progress
    try {
      // Clerk must load BEFORE the handshake params leave the URL: it reads them to restore the session.
      const clerk = await ClerkAuth.load();
      ClerkTrace.add('resume-clerk-loaded', clerk.session ? 'has-session' : 'no-session');
      cleanUrl();
      if (!clerk.session) { Auth._landingNotice('Sign-in did not complete (no session came back from Clerk). Please try again.'); return false; }
      const token = await clerk.session.getToken();
      if (pending.mode === 'join') {
        const data = await api('/api/auth/register', { method: 'POST', body: JSON.stringify({ name: pending.name, code: pending.code, clerk_token: token }) });
        Toast.ok(`Welcome, ${data.user.name}!`);
        Auth._enter(data);
      } else {
        await Auth._clerkLogin(token);
      }
      return true;
    } catch (e) {
      ClerkTrace.add('resume-error', e.message);
      await ClerkAuth.signOut();
      Auth._landingNotice(e.message || 'Email sign-in failed.');
      return false;
    } finally { ClerkPending.clear(); }
  },
  _enter(data) {
    scheduleExpiryWarning(data.token);
    if (data.user.role === 'admin') {
      setToken(data.token); applyBrand(); App.show('screen-admin'); Admin.init();
    } else if (data.user.role === 'manager') {
      setManagerToken(data.token); setManagerUser(data.user); curManager = data.user;
      Manager.init();
    } else {
      setLearnerToken(data.token); curLearner = { id: data.user.id, name: data.user.name };
      Learner.init();
    }
  },
  // Invite sign-up with email instead of a password
  async joinWithEmail() {
    const code = $$('join-code').value.trim(), name = $$('join-name').value.trim();
    if (!code) return Toast.err('Please enter your invite code.');
    if (!name) return Toast.err('Please enter your full name.');
    const btn = $$('join-email-btn'); btn.disabled = true;
    ClerkPending.set({ mode: 'join', code, name });
    try {
      const token = await ClerkAuth.token('signup');
      const data = await api('/api/auth/register', { method: 'POST', body: JSON.stringify({ name, code, clerk_token: token }) });
      ['join-code','join-name'].forEach(id => { $$(id).value = ''; });
      Toast.ok(`Welcome, ${data.user.name}!`);
      Auth._enter(data);
    } catch (e) {
      await ClerkAuth.signOut();
      Toast.err(e.message || 'Email sign-up failed.');
    } finally { btn.disabled = false; ClerkPending.clear(); }
  },

  // ─── ADMIN ───
  async doLogin() {
    const password = $$('pw-input').value;
    try {
      const { token } = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ password }) });
      setToken(token);
      scheduleExpiryWarning(token);
      $$('pw-input').value = '';
      applyBrand();
      App.show('screen-admin');
      Admin.init();
    } catch (e) {
      if (e.status === 503) $$('first-run-overlay').classList.remove('hidden');
      else Toast.err(e.message);
    }
  },
  adminLogout() { ClerkAuth.signOut(); clearToken(); curCourse = null; curModIdx = 0; quizSt = {}; App.show('screen-landing'); },

  // ─── MANAGER ───
  toggleManagerReg(show) {
    if (show) return App.openJoin();
    $$('m-login-sub').textContent = 'Sign in to manage your team.';
  },
  async doManagerLogin() {
    const name = $$('m-login-name').value.trim(), password = $$('m-login-pw').value;
    if(!name || !password) return Toast.err('Enter name and password.');
    try {
      const data = await api('/api/auth/manager/login', { method: 'POST', body: JSON.stringify({ name, password }) });
      setManagerToken(data.token); scheduleExpiryWarning(data.token); setManagerUser(data.user); curManager = data.user;
      Manager.init();
    } catch(e) { Toast.err(e.message); }
  },
  // ─── INVITES (managers + learners) ───
  async loadInvitePreview() {
    const code = ($$('join-code').value || '').trim();
    const title = $$('join-title'), sub = $$('join-sub');
    if (code.length < 6) { title.textContent = 'Join your team'; sub.textContent = 'Enter your invite code to create your account.'; return; }
    try {
      const inv = await api(`/api/auth/invite/${encodeURIComponent(code)}`);
      const role = inv.role === 'learner' ? 'learner' : 'manager';
      title.textContent = inv.team_name ? `Join ${inv.team_name}` : 'Join your team';
      sub.textContent = `You're being invited as a ${role}. Choose your name and password to continue.`;
    } catch (e) {
      title.textContent = 'Join your team';
      sub.textContent = e.message || 'That invite code is not valid.';
    }
  },
  async doJoin() {
    const code = $$('join-code').value.trim(), name = $$('join-name').value.trim();
    const pw1 = $$('join-pw1').value, pw2 = $$('join-pw2').value;
    if (!code) return Toast.err('Please enter your invite code.');
    if (!name) return Toast.err('Please enter your full name.');
    if (pw1.length < CONFIG.MIN_PW_LEN) return Toast.err(`Password must be at least ${CONFIG.MIN_PW_LEN} characters.`);
    if (pw1 !== pw2) return Toast.err('Passwords do not match.');
    const btn = $$('join-btn'); btn.disabled = true; btn.textContent = 'Creating account…';
    try {
      const data = await api('/api/auth/register', { method: 'POST', body: JSON.stringify({ name, password: pw1, code }) });
      ['join-code','join-name','join-pw1','join-pw2'].forEach(id => { $$(id).value = ''; });
      scheduleExpiryWarning(data.token);
      if (data.user.role === 'learner') {
        setLearnerToken(data.token); curLearner = { id: data.user.id, name: data.user.name };
        Toast.ok(`Welcome, ${data.user.name}!`);
        Learner.init();
      } else {
        setManagerToken(data.token); setManagerUser(data.user); curManager = data.user;
        Toast.ok(`Welcome, ${data.user.name}!`);
        Manager.init();
      }
    } catch (e) { Toast.err(e.message); }
    finally { btn.disabled = false; btn.textContent = 'Create account'; }
  },
  managerLogout() { ClerkAuth.signOut(); clearManagerToken(); clearManagerUser(); curManager = null; curCourse = null; curModIdx = 0; quizSt = {}; App.show('screen-landing'); },

  // ─── LEARNER ───
  async doLearnerLogin() {
    const name = $$('learner-name-input').value.trim(), password = $$('learner-pw-input').value;
    try {
      const data = await api('/api/learners/login', { method: 'POST', body: JSON.stringify({ name, password }) });
      setLearnerToken(data.token); curLearner = { id: data.user.id, name: data.user.name };
      Learner.init();
    } catch(e) { $$('l-login-error').textContent = e.message; $$('l-login-error').style.display='block'; }
  },
  learnerLogout() { if (Learner._preview) return Learner.exitPreview(); ClerkAuth.signOut(); clearLearnerToken(); curLearner = null; curCourse = null; curModIdx = 0; quizSt = {}; App.show('screen-landing'); }
};
