/* Console Router — boots the console shell: checks auth (redirects to
   /login if not signed in), renders role-based sidebar navigation, and
   switches between the 7 sections without full page reloads. */

(function () {
  const SECTIONS = {
    command: {
      label: 'Command Center', icon: '◉', module: CommandSection,
      title: 'Command Center', subtitle: 'Real-time overview of your security posture',
      roles: ['Security Analyst', 'SOC Manager'],
    },
    triage: {
      label: 'Incident Triage', icon: '▤', module: TriageSection,
      title: 'Incident Triage', subtitle: 'Work incidents through the response lifecycle',
      roles: ['Security Analyst'],
    },
    correlation: {
      label: 'Correlation Engine', icon: '◈', module: CorrelationSection,
      title: 'Correlation Engine', subtitle: 'How raw events become incidents and behavioral threads',
      roles: ['Security Analyst', 'SOC Manager'],
    },
    hunting: {
      label: 'Threat Hunting', icon: '⌖', module: HuntingSection,
      title: 'Threat Hunting', subtitle: 'Run saved queries against the real ingested event log',
      roles: ['Security Analyst'],
    },
    playbooks: {
      label: 'Response Playbooks', icon: '⚡', module: PlaybooksSection,
      title: 'Response Playbooks', subtitle: 'Real rule-based containment decision logic',
      roles: ['Security Analyst'],
    },
    assets: {
      label: 'Assets', icon: '▦', module: AssetsSection,
      title: 'Asset Inventory', subtitle: 'Devices and servers observed in your environment',
      roles: ['Security Analyst', 'SOC Manager'],
    },
    audit: {
      label: 'Audit Trail', icon: '≡', module: AuditSection,
      title: 'Audit Trail', subtitle: 'Org-wide history of every recorded action',
      roles: ['SOC Manager'],
    },
  };

  let currentUser = null;
  let activeSection = 'command';

  function sectionsForRole(role) {
    return Object.entries(SECTIONS).filter(([, cfg]) => cfg.roles.includes(role));
  }

  function renderNav() {
    const nav = document.getElementById('console-nav');
    const available = sectionsForRole(currentUser.role);

    nav.innerHTML = available.map(([key, cfg]) => `
      <button class="console-nav-link ${key === activeSection ? 'active' : ''}" data-section="${key}">
        <span class="console-nav-label">
          <span class="console-nav-icon">${cfg.icon}</span>
          ${cfg.label}
        </span>
      </button>
    `).join('');

    nav.querySelectorAll('[data-section]').forEach((btn) => {
      btn.addEventListener('click', () => navigate(btn.dataset.section));
    });
  }

  function renderRoleNote() {
    document.getElementById('console-role-label').textContent = `${currentUser.username} · ${currentUser.role}`;
    document.getElementById('console-role-desc').textContent =
      currentUser.role === 'SOC Manager'
        ? 'You can view audit history org-wide and simulate attack propagation on any incident.'
        : 'You can triage incidents, hunt threats, and run response playbooks.';
  }

  async function navigate(sectionKey) {
    const cfg = SECTIONS[sectionKey];
    if (!cfg) return;

    if (!cfg.roles.includes(currentUser.role)) {
      renderRoleGate(cfg);
      return;
    }

    activeSection = sectionKey;
    history.replaceState(null, '', `/console/${sectionKey}`);
    renderNav();

    document.getElementById('console-page-title').textContent = cfg.title;
    document.getElementById('console-page-subtitle').textContent = cfg.subtitle;

    const content = document.getElementById('console-content');
    content.innerHTML = '<div class="console-loading">Loading…</div>';

    try {
      await cfg.module.render(content, { user: currentUser, navigate });
    } catch (err) {
      console.error(`Failed to render section ${sectionKey}:`, err);
      content.innerHTML = `<div class="empty-state"><h4 style="color:var(--sev-critical);">Failed to load this section</h4><p>${err.message}</p></div>`;
    }
  }

  function renderRoleGate(cfg) {
    document.getElementById('console-page-title').textContent = cfg.title;
    document.getElementById('console-page-subtitle').textContent = 'Restricted section';
    document.getElementById('console-content').innerHTML = `
      <div class="role-gate-notice">
        <h3>Not available for ${currentUser.role}</h3>
        <p>"${cfg.label}" is restricted to ${cfg.roles.join(' / ')} accounts. This matches the project's
        access model — different roles see different parts of the console, not just different buttons.</p>
      </div>
    `;
  }

  function onIncidentChanged(updated) {
    if (activeSection === 'triage' && TriageSection.onIncidentChanged) {
      TriageSection.onIncidentChanged(updated);
    }
  }

  async function boot() {
    try {
      const { user } = await API.me();
      if (!user) {
        window.location.href = '/login';
        return;
      }
      currentUser = user;
    } catch (err) {
      window.location.href = '/login';
      return;
    }

    document.getElementById('console-shell').style.display = 'flex';
    renderNav();
    renderRoleNote();

    Drawer.init(currentUser, onIncidentChanged);

    document.getElementById('console-logout-btn').addEventListener('click', async () => {
      await API.logout();
      window.location.href = '/login';
    });

    // Route from the URL path (/console/<section>) if present and valid
    // for this role; otherwise default to Command Center.
    const pathMatch = window.location.pathname.match(/^\/console\/([a-z]+)/);
    const requested = pathMatch ? pathMatch[1] : 'command';
    const validForRole = sectionsForRole(currentUser.role).some(([key]) => key === requested);
    await navigate(validForRole ? requested : 'command');
  }

  boot();
})();
