/* Command Center — the overview section. Real KPIs, a live Cyber Digital
   Twin graph, top-risk users, and the most recent incidents. Visible to
   both Security Analyst and SOC Manager roles. */

const CommandSection = (() => {
  async function render(container, ctx) {
    container.innerHTML = `
      <div class="console-grid cols-4" id="cmd-kpis"></div>
      <div class="console-grid sidebar-right" style="margin-top:16px;">
        <div class="cpanel" style="height:420px;">
          <div class="cpanel-head">
            <div><h3>Cyber Digital Twin</h3><p>Live network/user/segment graph</p></div>
            <span class="panel-tag"><span id="twin-node-count">—</span> · <span id="twin-edge-count">—</span></span>
          </div>
          <div id="cmd-twin" style="flex:1;min-height:0;"></div>
        </div>
        <div class="cpanel">
          <div class="cpanel-head"><div><h3>Top Risk Users</h3><p>Trust Score leaderboard</p></div></div>
          <div class="cpanel-body flush" id="cmd-trust-list"></div>
        </div>
      </div>
      <div class="cpanel" style="margin-top:16px;">
        <div class="cpanel-head"><div><h3>Recent Incidents</h3><p>Most recently occurred, across all statuses</p></div></div>
        <div class="cpanel-body flush" id="cmd-recent-incidents"></div>
      </div>
    `;

    const [summary, trustBoard, incidents] = await Promise.all([
      API.summary(),
      API.trustScores('ascending'),
      API.incidents(),
    ]);

    renderKpis(summary);
    renderTrustList(trustBoard.slice(0, 6));
    renderRecentIncidents([...incidents].reverse().slice(0, 8));

    try {
      await Twin.init('cmd-twin', (data) => {
        Drawer.showRows(
          data.type === 'segment' ? `Segment — ${data.label}` : `${data.type === 'user' ? 'User' : 'Host'} — ${data.label}`,
          [
            ['Type', data.type === 'segment' ? 'Network Segment' : data.type === 'user' ? 'User Account' : 'IP Address'],
            ['Risk Score', data.risk_score],
            ['Events Involving Node', data.event_count],
          ]
        );
      });
    } catch (err) {
      document.getElementById('cmd-twin').innerHTML = `<div class="empty-state"><p>Graph failed to load: ${err.message}</p></div>`;
    }
  }

  function renderKpis(s) {
    const kpis = [
      { label: 'Total Events', value: s.total_events },
      { label: 'Incidents', value: s.total_incidents },
      { label: 'Repeat Offenders', value: s.repeat_offenders, tone: 'critical' },
      { label: 'Avg MTTD', value: Util.fmtMinutes(s.overall_mttd_mttr.mttd_mean), tone: 'accent' },
    ];
    const wrap = document.getElementById('cmd-kpis');
    wrap.innerHTML = kpis.map((k) => `
      <div class="kpi-card">
        <div class="kpi-card-label">${k.label}</div>
        <div class="kpi-card-value ${k.tone || ''}">${k.value}</div>
      </div>
    `).join('');
  }

  function renderTrustList(users) {
    const wrap = document.getElementById('cmd-trust-list');
    wrap.innerHTML = users.map((u) => {
      const color = Util.RISK_COLOR[u.risk_level] || '#7C8798';
      return `
        <div class="crow" data-user="${encodeURIComponent(u.user)}">
          <div class="crow-main">
            <span class="risk-badge" style="background:${color}22;color:${color};">${u.risk_level.replace(' Risk', '')}</span>
            <span class="crow-title">${u.user}</span>
          </div>
          <div class="crow-right">
            <span class="crow-meta">${u.trust_score.toFixed(1)}</span>
          </div>
        </div>
      `;
    }).join('');

    wrap.querySelectorAll('.crow').forEach((row) => {
      row.addEventListener('click', async () => {
        const user = decodeURIComponent(row.dataset.user);
        const score = await API.trustScoreUser(user);
        Drawer.showRows(`Trust Score — ${score.user}`, [
          ['Trust Score', score.trust_score.toFixed(1)],
          ['Risk Level', score.risk_level],
          ['Incidents', score.incident_count],
          ['Severity Risk', score.severity_risk.toFixed(1)],
          ['Response Risk', score.response_risk.toFixed(1)],
          ['Anomaly Risk', score.anomaly_risk.toFixed(1)],
          ['Frequency Risk', score.frequency_risk.toFixed(1)],
        ]);
        Twin.highlightUser(user);
      });
    });
  }

  function renderRecentIncidents(incidents) {
    const wrap = document.getElementById('cmd-recent-incidents');
    if (!incidents.length) {
      wrap.innerHTML = `<div class="empty-state"><div class="empty-state-icon">◌</div><h4>No incidents yet</h4></div>`;
      return;
    }
    wrap.innerHTML = incidents.map((inc) => {
      const color = Util.SEVERITY_COLOR[inc.severity] || '#7C8798';
      return `
        <div class="crow" data-id="${inc.incident_id}">
          <div class="crow-main">
            <span class="sev-pill ${Util.severityClass(inc.severity)}" style="color:${color}">${inc.severity}</span>
            <span class="crow-title">${inc.attack_type} — ${inc.user}</span>
          </div>
          <div class="crow-right">
            <span class="crow-meta">${inc.status}</span>
            <span class="crow-meta">${Util.fmtTime(inc.occurred_at)}</span>
          </div>
        </div>
      `;
    }).join('');

    wrap.querySelectorAll('.crow').forEach((row) => {
      row.addEventListener('click', async () => {
        const inc = await API.incident(row.dataset.id);
        Drawer.showIncident(inc);
      });
    });
  }

  return { render };
})();
