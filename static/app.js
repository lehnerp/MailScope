(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];

  // ---- theme toggle -------------------------------------------------------
  const themeBtns = $$('[data-theme-set]');
  const markTheme = () => {
    const cur = window.MailScopeTheme ? window.MailScopeTheme.get() : 'auto';
    themeBtns.forEach(b => b.setAttribute('aria-pressed', String(b.dataset.themeSet === cur)));
  };
  themeBtns.forEach(b => b.addEventListener('click', () => {
    if (window.MailScopeTheme) window.MailScopeTheme.set(b.dataset.themeSet);
    markTheme();
  }));
  markTheme();

  // ---- drag & drop upload ------------------------------------------------
  const drop = $('#drop'), input = $('#file-input'), list = $('#drop-files'), form = $('#upload-form');
  if (drop && input) {
    const show = () => { list.textContent = [...input.files].map(f => f.name).join(' · '); };
    input.addEventListener('change', show);
    ['dragenter', 'dragover'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add('over'); }));
    ['dragleave', 'drop'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove('over'); }));
    drop.addEventListener('drop', ev => {
      if (ev.dataTransfer.files.length) { input.files = ev.dataTransfer.files; show(); form.requestSubmit(); }
    });
    form.addEventListener('submit', () => { const b = $('button[type=submit]', form); b.disabled = true; b.textContent = 'Analysing…'; });
  }

  // ---- clickable rows ----------------------------------------------------
  $$('.rowlink').forEach(tr => tr.addEventListener('click', e => {
    if (e.target.closest('a')) return;
    location.href = tr.dataset.href;
  }));

  // ---- tabs (remember via hash) -----------------------------------------
  const tabs = $$('.tab');
  const open = name => {
    tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === name));
    $$('.panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
  };
  tabs.forEach(t => t.addEventListener('click', () => { open(t.dataset.tab); history.replaceState(null, '', '#' + t.dataset.tab); }));
  if (location.hash && $('#tab-' + location.hash.slice(1))) open(location.hash.slice(1));

  // ---- copy to clipboard -------------------------------------------------
  const toast = msg => {
    let t = $('#toast');
    if (!t) { t = document.createElement('div'); t.id = 'toast'; document.body.appendChild(t); }
    t.textContent = msg; t.classList.add('on'); clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('on'), 1400);
  };
  const copy = txt => (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject())
    .then(() => toast('Copied'), () => {
      const ta = document.createElement('textarea'); ta.value = txt; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); toast('Copied'); } catch (_) { toast('Copy failed'); } ta.remove();
    });
  document.addEventListener('click', e => {
    const el = e.target.closest('[data-copy]');
    if (el) copy(el.dataset.copy);
    const all = e.target.closest('[data-copy-all]');
    if (all) copy($$('#' + all.dataset.copyAll + ' tbody tr').map(tr => tr.dataset.type + '\t' + tr.dataset.def).join('\n'));
  });

  // ---- header filter -----------------------------------------------------
  const hf = $('#hfilter');
  if (hf) hf.addEventListener('input', () => {
    const q = hf.value.toLowerCase();
    $$('#htable tr').forEach(tr => { tr.hidden = q && !tr.textContent.toLowerCase().includes(q); });
  });

  // ---- body view switch --------------------------------------------------
  $$('[data-body]').forEach(b => b.addEventListener('click', () => {
    $$('[data-body]').forEach(x => x.classList.toggle('active', x === b));
    ['text', 'html', 'src'].forEach(k => { const el = $('#body-' + k); if (el) el.hidden = k !== b.dataset.body; });
  }));

  // ---- confirm forms -----------------------------------------------------
  $$('form.confirm').forEach(f => f.addEventListener('submit', e => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));
})();
