/* Incident Triage — the analyst's main workspace. Full filterable,
   sortable incident table with status workflow built in via the shared
   Drawer component. Security Analyst section. */

const TriageSection = (() => {
  let allIncidents = [];
  let filtered = [];
  let sortKey = 'occurred_at';
  let sortDir = 'desc';
  let page = 1;
  const PAGE_SIZE = 15;

  const STATUS_COLOR = { New: '#7C8798', 'Under Analysis': '#5B9BD5', Confirmed: '#F5A623', Resolved: '#3FB68B' };

  async function render(container, ctx) {
    container.innerHTML = `
      <div class="cpanel">
        <div class="cpanel-head">
          <div><h3>Incident Triage Queue</h3><p>Work incidents through New → Under Analysis → Confirmed → Resolved</p></div>
        </div>
        <div class="cpanel-body" style="padding-bottom:0;">
          <div class="incidents-toolbar" style="margin-bottom:14px;">
            <input type="text" class="toolbar-input" id="triage-search" placeholder="Search by user, IP, or attack type…" />
            <select class="toolbar-select" id="triage-filter-severity">
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
            <select class="toolbar-select" id="triage-filter-status">
              <option value="">All Statuses</option>
              <option value="New">New</option>
              <option value="Under Analysis">Under Analysis</option>
              <option value="Confirmed">Confirmed</option>
              <option value="Resolved">Resolved</option>
            </select>
            <span class="toolbar-count" id="triage-count">— results</span>
          </div>
        </div>
        <div class="table-wrap" style="border:none;">
          <table class="incidents-table">
            <thead>
              <tr>
                <th data-sort="occurred_at">Occurred</th>
                <th data-sort="incident_id">ID</th>
                <th data-sort="status">Status</th>
                <th data-sort="user">User</th>
                <th data-sort="attack_type">Attack</th>
                <th data-sort="severity">Severity</th>
                <th data-sort="mttd_minutes">MTTD</th>
                <th data-sort="mttr_minutes">MTTR</th>
              </tr>
            </thead>
            <tbody id="triage-tbody"></tbody>
          </table>
        </div>
        <div class="incidents-pagination">
          <span id="triage-page-info">—</span>
          <div>
            <button class="page-btn" id="triage-prev">← Prev</button>
            <button class="page-btn" id="triage-next">Next →</button>
          </div>
        </div>
      </div>
    `;

    allIncidents = await API.incidents();
    filtered = [...allIncidents];
    sortFiltered();
    renderTable();

    document.getElementById('triage-search').addEventListener('input', applyFilters);
    document.getElementById('triage-filter-severity').addEventListener('change', applyFilters);
    document.getElementById('triage-filter-status').addEventListener('change', applyFilters);
    document.getElementById('triage-prev').addEventListener('click', () => { if (page > 1) { page--; renderTable(); } });
    document.getElementById('triage-next').addEventListener('click', () => { page++; renderTable(); });

    container.querySelectorAll('th[data-sort]').forEach((th) => {
      th.style.cursor = 'pointer';
      th.addEventListener('click', () => {
        const key = th.dataset.sort;
        sortDir = sortKey === key && sortDir === 'asc' ? 'desc' : 'asc';
        sortKey = key;
        sortFiltered();
        renderTable();
      });
    });
  }

  function applyFilters() {
    const q = document.getElementById('triage-search').value.trim().toLowerCase();
    const sev = document.getElementById('triage-filter-severity').value;
    const status = document.getElementById('triage-filter-status').value;

    filtered = allIncidents.filter((inc) => {
      if (sev && inc.severity !== sev) return false;
      if (status && inc.status !== status) return false;
      if (q) {
        const haystack = `${inc.user} ${inc.source_ip} ${inc.dst_ip} ${inc.attack_type} ${inc.incident_id}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
    sortFiltered();
    page = 1;
    renderTable();
  }

  function sortFiltered() {
    filtered.sort((a, b) => {
      let av = a[sortKey], bv = b[sortKey];
      if (typeof av === 'string') av = av.toLowerCase();
      if (typeof bv === 'string') bv = bv.toLowerCase();
      if (av == null) av = '';
      if (bv == null) bv = '';
      if (av < bv) return sortDir === 'asc' ? -1 : 1;
      if (av > bv) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }

  function statusBadge(status) {
    const color = STATUS_COLOR[status] || '#7C8798';
    return `<span class="risk-badge" style="background:${color}22;color:${color};">${status}</span>`;
  }

  function renderTable() {
    const tbody = document.getElementById('triage-tbody');
    const countEl = document.getElementById('triage-count');
    const pageInfo = document.getElementById('triage-page-info');
    if (!tbody) return;

    countEl.textContent = `${filtered.length} result${filtered.length === 1 ? '' : 's'}`;

    if (!filtered.length) {
      tbody.innerHTML = `<tr><td colspan="8"><div class="empty-state"><div class="empty-state-icon">◌</div><h4>No incidents match these filters</h4><p>Try clearing the search or filters above.</p></div></td></tr>`;
      pageInfo.textContent = 'Page 0 of 0';
      return;
    }

    const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
    page = Math.min(page, totalPages);
    const items = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

    tbody.innerHTML = items.map((inc) => `
      <tr data-id="${inc.incident_id}">
        <td class="mono">${Util.fmtTime(inc.occurred_at)}</td>
        <td class="mono">${inc.incident_id}</td>
        <td>${statusBadge(inc.status)}</td>
        <td>${inc.user}</td>
        <td>${inc.attack_type}</td>
        <td><span class="sev-pill ${Util.severityClass(inc.severity)}" style="color:${Util.SEVERITY_COLOR[inc.severity]}">${inc.severity}</span></td>
        <td class="mono">${Util.fmtMinutes(inc.mttd_minutes)}</td>
        <td class="mono">${inc.mttr_minutes != null ? Util.fmtMinutes(inc.mttr_minutes) : '—'}</td>
      </tr>
    `).join('');

    tbody.querySelectorAll('tr').forEach((tr) => {
      tr.style.cursor = 'pointer';
      tr.addEventListener('click', async () => {
        const inc = await API.incident(tr.dataset.id);
        await Drawer.showIncident(inc);
      });
    });

    pageInfo.textContent = `Page ${page} of ${totalPages} · ${filtered.length} total`;
    document.getElementById('triage-prev').disabled = page <= 1;
    document.getElementById('triage-next').disabled = page >= totalPages;
  }

  function onIncidentChanged(updated) {
    const idx = allIncidents.findIndex((i) => i.incident_id === updated.incident_id);
    if (idx !== -1) allIncidents[idx] = updated;
    const fidx = filtered.findIndex((i) => i.incident_id === updated.incident_id);
    if (fidx !== -1) filtered[fidx] = updated;
    renderTable();
  }

  return { render, onIncidentChanged };
})();
