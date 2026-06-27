/* Shared detail drawer — used by Triage, Correlation, Assets, and Audit
   sections to show incident/asset detail without each section
   reimplementing the same open/close/render plumbing. */

const Drawer = (() => {
  const VALID_TRANSITIONS = {
    New: ['Under Analysis'],
    'Under Analysis': ['Confirmed', 'New'],
    Confirmed: ['Resolved'],
    Resolved: ['Confirmed'],
  };

  const STATUS_COLOR = { New: '#7C8798', 'Under Analysis': '#5B9BD5', Confirmed: '#F5A623', Resolved: '#3FB68B' };

  let currentUser = null;
  let onChangeCallback = null;

  function init(user, onChange) {
    currentUser = user;
    onChangeCallback = onChange;

    document.getElementById('drawer-close').onclick = close;
    document.getElementById('drawer-backdrop').onclick = close;
  }

  function open(title) {
    document.getElementById('drawer-title').textContent = title;
    document.getElementById('drawer').classList.add('open');
    document.getElementById('drawer-backdrop').classList.add('open');
  }

  function close() {
    document.getElementById('drawer').classList.remove('open');
    document.getElementById('drawer-backdrop').classList.remove('open');
  }

  function body() {
    return document.getElementById('drawer-body');
  }

  async function showIncident(inc) {
    const techniques = (inc.mitre_techniques || [])
      .map((t) => `${t.technique_id} (${t.technique_name})`)
      .join(', ');

    open(`Incident — ${inc.incident_id}`);
    const b = body();
    b.innerHTML = '';

    const color = STATUS_COLOR[inc.status] || '#7C8798';
    const statusRow = Util.el('div', { style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;' }, [
      Util.el('span', { class: 'risk-badge', style: `background:${color}22;color:${color};font-size:11px;padding:5px 10px;` }, [inc.status]),
      inc.assigned_to ? Util.el('span', { style: 'font-size:11px;color:var(--text-dim);' }, [`Assigned: ${inc.assigned_to}`]) : null,
    ]);
    b.appendChild(statusRow);

    const rows = [
      ['User', inc.user || inc.subject_user],
      ['Attack Type', inc.attack_type],
      ['Severity', inc.severity],
      ['Network Segment', inc.network_segment],
      ['Source IP', inc.source_ip],
      ['Destination IP', inc.dst_ip],
      ['Occurred', Util.fmtTime(inc.occurred_at)],
      ['Detected', Util.fmtTime(inc.detected_at)],
      ['Resolved', inc.resolved_at ? Util.fmtTime(inc.resolved_at) : '— not yet resolved'],
      ['MTTD', Util.fmtMinutes(inc.mttd_minutes)],
      ['MTTR', inc.mttr_minutes != null ? Util.fmtMinutes(inc.mttr_minutes) : '— pending resolution'],
      ['Action Taken (logged)', inc.action_taken],
      ['MITRE Technique(s)', techniques || '—'],
    ];
    rows.forEach(([k, v]) => {
      b.appendChild(
        Util.el('div', { class: 'drawer-row' }, [
          Util.el('span', { class: 'k' }, [k]),
          Util.el('span', { class: 'v' }, [String(v)]),
        ])
      );
    });

    b.appendChild(Util.el('div', { class: 'drawer-section-title' }, ['Incident Workflow']));

    if (!currentUser) {
      b.appendChild(Util.el('div', { class: 'drawer-explain-item' }, ['Sign in to manage this incident.']));
      b.appendChild(Util.el('a', { href: '/login', class: 'btn-secondary', style: 'display:inline-block;margin-top:6px;padding:8px 14px;font-size:12px;' }, ['Sign In']));
    } else {
      const nextStates = VALID_TRANSITIONS[inc.status] || [];
      const btnRow = Util.el('div', { style: 'display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px;' });
      nextStates.forEach((next) => {
        const label = next === 'New' ? 'Re-assign (→ New)' : (next === 'Confirmed' && inc.status === 'Resolved') ? 'Escalate (→ Confirmed)' : `→ ${next}`;
        btnRow.appendChild(Util.el('button', { class: 'page-btn', onclick: () => handleTransition(inc.incident_id, next) }, [label]));
      });
      b.appendChild(btnRow);

      if (inc.status === 'Confirmed') {
        b.appendChild(Util.el('button', {
          class: 'btn-primary',
          style: 'display:block;width:100%;text-align:center;margin-bottom:8px;border:none;cursor:pointer;font-size:12px;padding:10px;',
          onclick: () => handleRespond(inc.incident_id),
        }, ['Run Response Engine']));
      }

      if (currentUser.role === 'SOC Manager') {
        b.appendChild(Util.el('button', {
          class: 'btn-secondary',
          style: 'display:block;width:100%;text-align:center;margin-bottom:8px;cursor:pointer;font-size:12px;padding:10px;',
          onclick: () => handleSimulateAttack(inc.incident_id),
        }, ['Simulate Attack (Propagation)']));
      } else {
        b.appendChild(Util.el('div', { style: 'font-size:11px;color:var(--text-faint);margin-top:4px;' }, ['Simulate Attack is restricted to SOC Manager accounts.']));
      }
    }

    try {
      const responses = await API.incidentResponses(inc.incident_id);
      if (responses.length) {
        b.appendChild(Util.el('div', { class: 'drawer-section-title' }, ['Response Engine Decisions']));
        responses.forEach((r) => {
          b.appendChild(
            Util.el('div', { class: 'drawer-explain-item' }, [
              Util.el('b', {}, [r.action]), ` — ${r.rationale} `,
              Util.el('span', { style: 'color:var(--text-faint);' }, [`[${r.playbook}]`]),
            ])
          );
        });
      }
    } catch (err) {
      console.error('Failed to load responses:', err);
    }
  }

  async function handleTransition(incidentId, toStatus) {
    try {
      const updated = await API.transitionIncident(incidentId, toStatus);
      await showIncident(updated);
      if (onChangeCallback) onChangeCallback(updated);
    } catch (err) {
      alert(`Transition failed: ${err.message}`);
    }
  }

  async function handleRespond(incidentId) {
    try {
      await API.respondToIncident(incidentId);
      const updated = await API.incident(incidentId);
      await showIncident(updated);
      if (onChangeCallback) onChangeCallback(updated);
    } catch (err) {
      alert(`Response Engine failed: ${err.message}`);
    }
  }

  async function handleSimulateAttack(incidentId) {
    try {
      const hops = await API.simulateAttack(incidentId);
      alert(`Simulated propagation: ${hops.length} node(s) in the blast radius. See console log for details.`);
      console.log('Propagation result:', hops);
    } catch (err) {
      alert(`Simulate Attack failed: ${err.message}`);
    }
  }

  function showRows(title, rows) {
    open(title);
    const b = body();
    b.innerHTML = '';
    rows.forEach(([k, v]) => {
      b.appendChild(
        Util.el('div', { class: 'drawer-row' }, [
          Util.el('span', { class: 'k' }, [k]),
          Util.el('span', { class: 'v' }, [String(v)]),
        ])
      );
    });
  }

  return { init, showIncident, showRows, open, close };
})();
