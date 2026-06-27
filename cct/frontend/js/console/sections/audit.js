/* Audit Trail — org-wide history of every status transition and Response
   Engine decision (see backend/audit/trail.py). SOC Manager section. */

const AuditSection = (() => {
  async function render(container, ctx) {
    container.innerHTML = `
      <div class="console-grid cols-4" id="audit-kpis"></div>
      <div class="cpanel" style="margin-top:16px;">
        <div class="cpanel-head">
          <div><h3>Audit Trail</h3><p>Every recorded action across the system, most recent first</p></div>
        </div>
        <div class="cpanel-body flush" id="audit-list" style="max-height:560px;overflow-y:auto;"></div>
      </div>
    `;

    const [summary, trail] = await Promise.all([API.auditSummary(), API.auditTrail(150)]);
    renderKpis(summary);
    renderTrail(trail);
  }

  function renderKpis(summary) {
    const topActor = Object.entries(summary.actions_by_user).sort((a, b) => b[1] - a[1])[0];
    const wrap = document.getElementById('audit-kpis');
    wrap.innerHTML = `
      <div class="kpi-card"><div class="kpi-card-label">Status Transitions</div><div class="kpi-card-value">${summary.total_transitions}</div></div>
      <div class="kpi-card"><div class="kpi-card-label">Response Decisions</div><div class="kpi-card-value">${summary.total_responses}</div></div>
      <div class="kpi-card"><div class="kpi-card-label">Most Active Analyst</div><div class="kpi-card-value" style="font-size:18px;">${topActor ? topActor[0] : '—'}</div></div>
      <div class="kpi-card"><div class="kpi-card-label">Their Actions</div><div class="kpi-card-value accent">${topActor ? topActor[1] : 0}</div></div>
    `;
  }

  function renderTrail(trail) {
    const wrap = document.getElementById('audit-list');
    if (!trail.length) {
      wrap.innerHTML = `<div class="empty-state"><div class="empty-state-icon">◌</div><h4>No audit history yet</h4></div>`;
      return;
    }

    wrap.innerHTML = trail.map((entry) => {
      const isResponse = entry.event_kind === 'response_decision';
      const label = isResponse ? `Response: ${entry.detail}` : `Status → ${entry.detail}`;
      return `
        <div class="audit-row">
          <span class="audit-time">${Util.fmtTime(entry.occurred_at)}</span>
          <span class="audit-actor">${entry.actor}</span>
          <div class="audit-detail">
            <b>${label}</b>
            <p>${entry.incident_id} — ${entry.attack_type} (${entry.severity})${entry.note ? ' · ' + entry.note : ''}</p>
          </div>
        </div>
      `;
    }).join('');
  }

  return { render };
})();
