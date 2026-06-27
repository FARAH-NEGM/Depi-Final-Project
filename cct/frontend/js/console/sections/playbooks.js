/* Response Playbooks — documents the real rule-based decision logic from
   backend/response/engine.py (not fabricated text) and shows the actual
   response history so far. Security Analyst section. */

const PlaybooksSection = (() => {
  // Mirrors response/engine.py's decide() function rules exactly — kept
  // in sync manually since these are the actual conditions the backend
  // evaluates; the backend remains the source of truth for what fires.
  const RULES = [
    {
      name: 'CRITICAL_REPEAT_OFFENDER',
      action: 'Disable Account + Isolate Host',
      condition: 'Severity = Critical AND subject user has a High/Critical Trust Score risk rating',
      rationale: 'Combined signal (severity + repeat behavioral risk) warrants the most aggressive automated containment available.',
    },
    {
      name: 'CRITICAL_SEVERITY',
      action: 'Isolate Host',
      condition: 'Severity = Critical (user has no elevated risk history)',
      rationale: 'Host isolation prevents further damage while the incident is investigated.',
    },
    {
      name: 'HIGH_SEVERITY_KNOWN_ATTACK',
      action: 'Block Source IP',
      condition: 'Severity = High AND attack type in {DDoS, Intrusion, SQL Injection}',
      rationale: 'These are network-layer attacks with a well-understood countermeasure: blocking the source IP stops the attack path.',
    },
    {
      name: 'MEDIUM_SEVERITY',
      action: 'Quarantine Host',
      condition: 'Severity = High or Medium, without a clean network-layer countermeasure',
      rationale: 'Limits blast radius while remaining reversible pending manual review.',
    },
    {
      name: 'DEFAULT_LOW',
      action: 'Log and Notify Analyst',
      condition: 'Anything else (typically Low severity)',
      rationale: 'No automated containment action is warranted; logged for analyst awareness and trend tracking.',
    },
  ];

  async function render(container, ctx) {
    container.innerHTML = `
      <div class="console-grid cols-2">
        <div class="cpanel">
          <div class="cpanel-head"><div><h3>Playbook Rules</h3><p>Evaluated in order, first match wins — this is the real decision logic, not a mockup</p></div></div>
          <div class="cpanel-body" id="playbook-rules"></div>
        </div>
        <div class="cpanel">
          <div class="cpanel-head"><div><h3>Confirmed Incidents Ready for Response</h3><p>Click one to open it and run the Response Engine</p></div></div>
          <div class="cpanel-body flush" id="playbook-confirmed"></div>
        </div>
      </div>
      <div class="cpanel" style="margin-top:16px;">
        <div class="cpanel-head"><div><h3>Recent Response Decisions</h3><p>Real, persisted Response Engine output</p></div></div>
        <div class="cpanel-body flush" id="playbook-history"></div>
      </div>
    `;

    document.getElementById('playbook-rules').innerHTML = RULES.map((r) => `
      <div class="playbook-rule">
        <div class="playbook-rule-head">
          <span class="playbook-rule-name">${r.name}</span>
        </div>
        <div class="playbook-rule-action">→ ${r.action}</div>
        <div class="playbook-rule-condition"><b style="color:var(--text-main);">If:</b> ${r.condition}</div>
        <div class="playbook-rule-condition" style="margin-top:4px;"><b style="color:var(--text-main);">Why:</b> ${r.rationale}</div>
      </div>
    `).join('');

    const incidents = await API.incidents('Confirmed');
    renderConfirmed(incidents);
    await renderHistory();
  }

  function renderConfirmed(incidents) {
    const wrap = document.getElementById('playbook-confirmed');
    if (!incidents.length) {
      wrap.innerHTML = `<div class="empty-state"><div class="empty-state-icon">◌</div><h4>No Confirmed incidents waiting</h4><p>Move an incident to "Confirmed" from Incident Triage to act on it here.</p></div>`;
      return;
    }
    wrap.innerHTML = incidents.map((inc) => `
      <div class="crow" data-id="${inc.incident_id}">
        <div class="crow-main">
          <span class="sev-pill ${Util.severityClass(inc.severity)}" style="color:${Util.SEVERITY_COLOR[inc.severity]}">${inc.severity}</span>
          <span class="crow-title">${inc.attack_type} — ${inc.user}</span>
        </div>
        <div class="crow-right"><span class="crow-meta">${inc.incident_id}</span></div>
      </div>
    `).join('');

    wrap.querySelectorAll('.crow').forEach((row) => {
      row.addEventListener('click', async () => {
        const inc = await API.incident(row.dataset.id);
        await Drawer.showIncident(inc);
      });
    });
  }

  async function renderHistory() {
    const wrap = document.getElementById('playbook-history');
    try {
      const allResponses = await API.allResponses();
      if (!allResponses.length) {
        wrap.innerHTML = `<div class="empty-state"><div class="empty-state-icon">◌</div><h4>No responses recorded yet</h4><p>Run the Response Engine on a Confirmed incident to see it here.</p></div>`;
        return;
      }
      wrap.innerHTML = allResponses.slice(0, 10).map((r) => `
        <div class="crow not-clickable">
          <div class="crow-main">
            <span class="crow-title"><b>${r.action}</b> on ${r.incident_id}</span>
          </div>
          <div class="crow-right">
            <span class="crow-meta">${r.playbook}</span>
            <span class="crow-meta">${Util.fmtTime(r.executed_at)}</span>
          </div>
        </div>
      `).join('');
    } catch (err) {
      wrap.innerHTML = `<div class="empty-state"><p>Failed to load: ${err.message}</p></div>`;
    }
  }

  return { render };
})();
