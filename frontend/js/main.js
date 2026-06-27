/* Main orchestrator: boots every module, wires mode switching (Full
   Analysis <-> Live Feed), the top KPI bar, the clock, and the detail
   drawer shared by the graph and the incident feed. */

(async function main() {
  let summary = null;

  // ---------------- Clock ----------------
  function tickClock() {
    document.getElementById('clock').textContent = Util.fmtClock(new Date());
  }
  tickClock();
  setInterval(tickClock, 1000);

  // ---------------- Drawer ----------------
  const drawer = document.getElementById('drawer');
  const backdrop = document.getElementById('drawer-backdrop');

  function openDrawer(title, rows, explanation) {
    document.getElementById('drawer-title').textContent = title;
    const body = document.getElementById('drawer-body');
    body.innerHTML = '';

    rows.forEach(([k, v]) => {
      body.appendChild(
        Util.el('div', { class: 'drawer-row' }, [
          Util.el('span', { class: 'k' }, [k]),
          Util.el('span', { class: 'v' }, [String(v)]),
        ])
      );
    });

    if (explanation && explanation.length) {
      body.appendChild(Util.el('div', { class: 'drawer-section-title' }, ['Why this score']));
      explanation.forEach((line) => {
        body.appendChild(Util.el('div', { class: 'drawer-explain-item' }, [line]));
      });
    }

    drawer.classList.add('open');
    backdrop.classList.add('open');
  }

  function closeDrawer() {
    drawer.classList.remove('open');
    backdrop.classList.remove('open');
  }

  document.getElementById('drawer-close').onclick = closeDrawer;
  backdrop.onclick = closeDrawer;

  // ---------------- Click handlers ----------------
  function onTrustCardClick(score) {
    openDrawer(
      `Trust Score — ${score.user}`,
      [
        ['Trust Score', score.trust_score.toFixed(1)],
        ['Risk Level', score.risk_level],
        ['Incidents', score.incident_count],
        ['Most Recent', Util.fmtTime(score.most_recent_incident_at)],
        ['Severity Risk', score.severity_risk.toFixed(1)],
        ['Response Risk', score.response_risk.toFixed(1)],
        ['Anomaly Risk', score.anomaly_risk.toFixed(1)],
        ['Frequency Risk', score.frequency_risk.toFixed(1)],
      ],
      score.explanation
    );
    Twin.highlightUser(score.user);
  }

  function onIncidentClick(inc) {
    const techniques = (inc.mitre_techniques || [])
      .map((t) => `${t.technique_id} (${t.technique_name})`)
      .join(', ');

    openDrawer(
      `Incident — ${inc.incident_id}`,
      [
        ['User', inc.user],
        ['Attack Type', inc.attack_type],
        ['Severity', inc.severity],
        ['Network Segment', inc.network_segment],
        ['Source IP', inc.source_ip],
        ['Destination IP', inc.dst_ip],
        ['Occurred', Util.fmtTime(inc.occurred_at)],
        ['Detected', Util.fmtTime(inc.detected_at)],
        ['Resolved', Util.fmtTime(inc.resolved_at)],
        ['MTTD', Util.fmtMinutes(inc.mttd_minutes)],
        ['MTTR', Util.fmtMinutes(inc.mttr_minutes)],
        ['Action Taken', inc.action_taken],
        ['MITRE Technique(s)', techniques || '—'],
      ],
      []
    );
  }

  function onNodeClick(data) {
    if (data.type === 'segment') {
      openDrawer(
        `Segment — ${data.label}`,
        [
          ['Type', 'Network Segment'],
          ['Events Observed', data.event_count],
        ],
        []
      );
      return;
    }

    openDrawer(
      `${data.type === 'user' ? 'User' : 'Host'} — ${data.label}`,
      [
        ['Type', data.type === 'user' ? 'User Account' : 'IP Address'],
        ['Risk Score', data.risk_score],
        ['Events Involving Node', data.event_count],
      ],
      []
    );
  }

  // ---------------- KPI bar ----------------
  function renderKpis(s) {
    const kpis = [
      { label: 'Events', value: s.total_events },
      { label: 'Incidents', value: s.total_incidents },
      { label: 'Users', value: s.total_users },
      { label: 'Repeat Offenders', value: s.repeat_offenders, accent: true },
      { label: 'Avg MTTD', value: Util.fmtMinutes(s.overall_mttd_mttr.mttd_mean) },
      { label: 'Avg MTTR', value: Util.fmtMinutes(s.overall_mttd_mttr.mttr_mean) },
    ];

    const bar = document.getElementById('topbar-kpis');
    bar.innerHTML = '';
    kpis.forEach((k) => {
      bar.appendChild(
        Util.el('div', { class: 'kpi' }, [
          Util.el('span', { class: `kpi-value ${k.accent ? 'accent' : ''}` }, [String(k.value)]),
          Util.el('span', { class: 'kpi-label' }, [k.label]),
        ])
      );
    });
  }

  // ---------------- Mode switching ----------------
  const btnAnalysis = document.getElementById('btn-mode-analysis');
  const btnLive = document.getElementById('btn-mode-live');

  function setMode(mode) {
    document.body.classList.toggle('mode-live', mode === 'live');
    btnAnalysis.classList.toggle('active', mode === 'analysis');
    btnLive.classList.toggle('active', mode === 'live');

    if (mode === 'live') {
      Feed.startLive(onIncidentClick);
    } else {
      Feed.stopLive();
      Feed.initFullAnalysis(onIncidentClick);
    }
  }

  btnAnalysis.onclick = () => setMode('analysis');
  btnLive.onclick = () => setMode('live');

  // ---------------- Wait for CDN libraries (with fallback already
  // triggered in index.html) before touching them ----------------
  function waitFor(checkFn, timeoutMs = 6000, intervalMs = 100) {
    return new Promise((resolve, reject) => {
      const start = Date.now();
      const tick = () => {
        if (checkFn()) return resolve();
        if (Date.now() - start > timeoutMs) return reject(new Error('Timed out waiting for library to load'));
        setTimeout(tick, intervalMs);
      };
      tick();
    });
  }

  // ---------------- Boot sequence ----------------
  try {
    await waitFor(() => typeof cytoscape !== 'undefined', 6000).catch(() => {
      throw new Error(
        'Cytoscape.js failed to load from both CDNs (cdnjs and jsDelivr). ' +
        'This usually means your network is blocking external CDN requests. ' +
        'Check your firewall/antivirus, or try a different network.'
      );
    });
    await waitFor(() => typeof Chart !== 'undefined', 6000).catch(() => {
      throw new Error(
        'Chart.js failed to load from both CDNs (cdnjs and jsDelivr). ' +
        'This usually means your network is blocking external CDN requests. ' +
        'Check your firewall/antivirus, or try a different network.'
      );
    });

    summary = await API.summary();
    renderKpis(summary);

    await Promise.all([
      Twin.init('cy', onNodeClick),
      Trust.init(onTrustCardClick),
      Mitre.init(),
      Metrics.init(),
      Feed.initFullAnalysis(onIncidentClick),
    ]);
  } catch (err) {
    console.error('Dashboard failed to load:', err);
    document.body.innerHTML = `<div style="padding:40px;font-family:monospace;color:#E5484D;">
      Failed to load dashboard data: ${err.message}<br>
      Check that the Flask backend is running and reachable.
    </div>`;
  }
})();
