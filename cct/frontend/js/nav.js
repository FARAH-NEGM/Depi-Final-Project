/* Shared site navigation — injected into every page via a <div id="site-nav">
   placeholder. Used by the landing page; the console (console.html) has
   its own sidebar nav (see js/console/router.js) since it's a different
   layout entirely.
   Also auth-aware: shows the logged-in analyst/manager + Sign Out, or a
   Sign In link if no session exists. */

(function () {
  const path = window.location.pathname;

  function isActive(href) {
    if (href === '/' && path === '/') return true;
    if (href !== '/' && path.startsWith(href)) return true;
    return false;
  }

  const links = [
    { href: '/', label: 'Overview' },
    { href: '/console', label: 'Console' },
  ];

  function authBlockHtml(user) {
    if (user) {
      return `
        <div class="site-nav-status">
          <span class="status-dot"></span>
          <span>${user.username} · ${user.role}</span>
          <button class="page-btn" id="nav-logout-btn" style="margin-left:8px;">Sign Out</button>
        </div>`;
    }
    return `
      <div class="site-nav-status">
        <a href="/login" class="btn-secondary" style="padding:7px 14px;font-size:12px;">Sign In</a>
      </div>`;
  }

  function navHtml(user) {
    return `
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
        ${authBlockHtml(user)}
      </nav>
    `;
  }

  async function mountNav() {
    const mount = document.getElementById('site-nav');
    if (!mount) return;

    // Render logged-out state immediately so nav isn't blank while we check.
    mount.outerHTML = navHtml(null);

    try {
      const res = await fetch('/api/auth/me');
      const data = await res.json();
      if (data.user) {
        const refreshed = document.querySelector('.site-nav');
        if (refreshed) refreshed.outerHTML = navHtml(data.user);
      }
    } catch (err) {
      console.error('Failed to check auth state:', err);
    }

    const logoutBtn = document.getElementById('nav-logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', async () => {
        await fetch('/api/auth/logout', { method: 'POST' });
        window.location.href = '/login';
      });
    }
  }

  document.addEventListener('DOMContentLoaded', mountNav);
})();
