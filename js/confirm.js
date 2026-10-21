// Shared confirmation dialog: replaces native confirm() so every destructive
// action looks, reads and behaves the same (themed, keyboard-safe, Esc cancels).
function confirmMarkup({ title, body, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false }) {
  return `<div class="modal modal-sm" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-body">
    <div class="modal-head"><div class="modal-title" id="confirm-title">${esc(title)}</div></div>
    <div class="modal-body"><p id="confirm-body">${esc(body)}</p></div>
    <div class="modal-foot">
      <button type="button" class="btn btn-ghost" data-confirm="cancel">${esc(cancelLabel)}</button>
      <button type="button" class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-confirm="ok">${esc(confirmLabel)}</button>
    </div>
  </div>`;
}

const Confirm = {
  _resolve: null,
  _opener: null,

  // Resolves true on confirm, false on cancel / Esc / backdrop click.
  // Danger dialogs focus Cancel first so a stray Enter never destroys data.
  ask(opts) {
    if (Confirm._resolve) Confirm._settle(false);
    let ov = $$('confirm-overlay');
    if (!ov) {
      ov = document.createElement('div');
      ov.id = 'confirm-overlay';
      ov.className = 'overlay hidden';
      ov.addEventListener('click', (e) => {
        if (e.target === ov) Confirm._settle(false);
        else if (e.target.dataset?.confirm) Confirm._settle(e.target.dataset.confirm === 'ok');
      });
      ov.addEventListener('keydown', Confirm._trapTab);
      document.body.appendChild(ov);
    }
    ov.innerHTML = confirmMarkup(opts);
    Confirm._opener = document.activeElement;
    ov.classList.remove('hidden');
    ov.querySelector(`[data-confirm="${opts.danger ? 'cancel' : 'ok'}"]`).focus();
    return new Promise((resolve) => { Confirm._resolve = resolve; });
  },

  cancel() { Confirm._settle(false); },

  _settle(result) {
    const resolve = Confirm._resolve;
    Confirm._resolve = null;
    $$('confirm-overlay')?.classList.add('hidden');
    Confirm._opener?.focus?.();
    Confirm._opener = null;
    resolve?.(result);
  },

  _trapTab(e) {
    if (e.key !== 'Tab') return;
    const btns = [...e.currentTarget.querySelectorAll('button')];
    const first = btns[0], last = btns[btns.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  },
};
