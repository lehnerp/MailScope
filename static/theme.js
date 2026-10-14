// Loaded in <head> before the stylesheet paints, so the chosen theme applies
// without a white flash. Choice is "auto" (follow Windows/OS), "light" or "dark".
(function () {
  var KEY = 'mailscope-theme';
  function get() { try { return localStorage.getItem(KEY) || 'auto'; } catch (e) { return 'auto'; } }
  function apply(mode) {
    var root = document.documentElement;
    if (mode === 'light' || mode === 'dark') root.setAttribute('data-theme', mode);
    else root.removeAttribute('data-theme');
  }
  apply(get());

  window.MailScopeTheme = {
    get: get,
    set: function (mode) {
      try { localStorage.setItem(KEY, mode); } catch (e) { /* private window: still applies for this page */ }
      apply(mode);
    }
  };
})();
