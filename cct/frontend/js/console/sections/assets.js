/* Assets — real device/server inventory derived from actual ingested
   events (see backend/assets/inventory.py). Visible to both roles. */

const AssetsSection = (() => {
  let assets = [];

  async function render(container, ctx) {
    container.innerHTML = `
      <div class="console-grid cols-4" id="assets-kpis"></div>
      <div class="cpanel" style="margin-top:16px;">
        <div class="cpanel-head">
          <div><h3>Asset Inventory</h3><p>Every device/server IP actually observed in the ingested logs</p></div>
        </div>
        <div class="table-wrap" style="border:none;">
          <table class="incidents-table">
            <thead>
              <tr><th>Asset</th><th>Type</th><th>IP Address</th><th>Max Severity Seen</th><th>Incidents</th><th>Open</th></tr>
            </thead>
            <tbody id="assets-tbody"></tbody>
          </table>
        </div>
      </div>
    `;

    const [summary, assetList] = await Promise.all([API.assetsSummary(), API.assets()]);
    assets = assetList;

    renderKpis(summary);
    renderTable(assets.slice(0, 60)); // cap rows rendered for performance; data behind it is complete
  }

  function renderKpis(summary) {
    const wrap = document.getElementById('assets-kpis');
    wrap.innerHTML = `
      <div class="kpi-card"><div class="kpi-card-label">Total Assets</div><div class="kpi-card-value">${summary.total_assets}</div></div>
      <div class="kpi-card"><div class="kpi-card-label">Devices</div><div class="kpi-card-value">${summary.by_type.device || 0}</div></div>
      <div class="kpi-card"><div class="kpi-card-label">Servers</div><div class="kpi-card-value">${summary.by_type.server || 0}</div></div>
      <div class="kpi-card"><div class="kpi-card-label">High Risk Assets</div><div class="kpi-card-value critical">${summary.high_risk_assets}</div></div>
    `;
  }

  function renderTable(rows) {
    const tbody = document.getElementById('assets-tbody');
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state"><h4>No assets found</h4></div></td></tr>`;
      return;
    }
    tbody.innerHTML = rows.map((a) => {
      const color = a.max_severity ? Util.SEVERITY_COLOR[a.max_severity] : '#7C8798';
      return `
        <tr data-ip="${a.ip_address}">
          <td>${a.name}</td>
          <td class="mono">${a.asset_type}</td>
          <td class="mono">${a.ip_address}</td>
          <td>${a.max_severity ? `<span class="sev-pill ${Util.severityClass(a.max_severity)}" style="color:${color}">${a.max_severity}</span>` : '<span style="color:var(--text-faint);">none</span>'}</td>
          <td class="mono">${a.incident_count}</td>
          <td class="mono">${a.open_incident_count}</td>
        </tr>
      `;
    }).join('');

    tbody.querySelectorAll('tr').forEach((tr) => {
      tr.style.cursor = 'pointer';
      tr.addEventListener('click', async () => {
        const ip = tr.dataset.ip;
        const asset = assets.find((a) => a.ip_address === ip);
        const incidents = await API.assetIncidents(ip);

        Drawer.open(`Asset — ${asset.name}`);
        const body = document.getElementById('drawer-body');
        body.innerHTML = '';
        [
          ['IP Address', asset.ip_address],
          ['Type', asset.asset_type],
          ['Max Severity Seen', asset.max_severity || 'none'],
          ['Total Incidents', asset.incident_count],
          ['Open Incidents', asset.open_incident_count],
        ].forEach(([k, v]) => {
          body.appendChild(Util.el('div', { class: 'drawer-row' }, [
            Util.el('span', { class: 'k' }, [k]),
            Util.el('span', { class: 'v' }, [String(v)]),
          ]));
        });

        if (incidents.length) {
          body.appendChild(Util.el('div', { class: 'drawer-section-title' }, ['Incidents Touching This Asset']));
          incidents.forEach((inc) => {
            body.appendChild(Util.el('div', { class: 'drawer-explain-item' }, [
              `${inc.incident_id} — ${inc.attack_type} (${inc.severity}, ${inc.status})`,
            ]));
          });
        }
      });
    });
  }

  return { render };
})();
