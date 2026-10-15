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

const Auth = {
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
  adminLogout() { clearToken(); curCourse = null; curModIdx = 0; quizSt = {}; App.show('screen-landing'); },

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
  managerLogout() { clearManagerToken(); clearManagerUser(); curManager = null; curCourse = null; curModIdx = 0; quizSt = {}; App.show('screen-landing'); },

  // ─── LEARNER ───
  async doLearnerLogin() {
    const name = $$('learner-name-input').value.trim(), password = $$('learner-pw-input').value;
    try {
      const data = await api('/api/learners/login', { method: 'POST', body: JSON.stringify({ name, password }) });
      setLearnerToken(data.token); curLearner = { id: data.user.id, name: data.user.name };
      Learner.init();
    } catch(e) { $$('l-login-error').textContent = e.message; $$('l-login-error').style.display='block'; }
  },
  learnerLogout() { if (Learner._preview) return Learner.exitPreview(); clearLearnerToken(); curLearner = null; curCourse = null; curModIdx = 0; quizSt = {}; App.show('screen-landing'); }
};
