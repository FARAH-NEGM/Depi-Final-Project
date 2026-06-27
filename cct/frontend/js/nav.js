/* Shared site navigation — injected into every page via a <div id="site-nav">
   placeholder, so the nav markup lives in one place instead of being
   duplicated across index.html / dashboard.html / incidents.html. */

(function () {
  const path = window.location.pathname;

  function isActive(href) {
    if (href === '/' && path === '/') return true;
    if (href !== '/' && path.startsWith(href)) return true;
    return false;
  }

  const links = [
    { href: '/', label: 'Overview' },
    { href: '/dashboard', label: 'Dashboard' },
    { href: '/incidents', label: 'Incidents' },
  ];

  const navHtml = `
    <nav class="site-nav">
      <a href="/" class="site-nav-brand">
        <span class="brand-mark">⛭</span>
        <span class="site-nav-brand-text">CYBER CONTROL TOWER</span>
      </a>
      <div class="site-nav-links">
        ${links
          .map(
            (l) =>
              `<a href="${l.href}" class="site-nav-link ${isActive(l.href) ? 'active' : ''}">${l.label}</a>`
          )
          .join('')}
      </div>
      <div class="site-nav-status">
        <span class="status-dot"></span>
        <span>System Online</span>
      </div>
    </nav>
  `;

  document.addEventListener('DOMContentLoaded', () => {
    const mount = document.getElementById('site-nav');
    if (mount) mount.outerHTML = navHtml;
  });
})();
