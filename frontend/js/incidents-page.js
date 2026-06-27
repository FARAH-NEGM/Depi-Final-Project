/* Incidents page controller — fetch, filter, sort, paginate, and render the
   full incident table. Independent of the dashboard's feed.js (different
   page, different needs: persistent table, not a scrolling stream). */

(function () {
  let allIncidents = [];
  let filtered = [];
  let sortKey = 'occurred_at';
  let sortDir = 'desc';
  let page = 1;
  const PAGE_SIZE = 20;

  const tbody = document.getElementById('incidents-tbody');
  const resultCount = document.getElementById('result-count');
  const pageInfo = document.getElementById('page-info');
  const prevBtn = document.getElementById('prev-page');
  const nextBtn = document.getElementById('next-page');

  // ---------------- Skeleton / empty states ----------------
  function renderSkeleton() {
    tbody.innerHTML = '';
    for (let i = 0; i < 8; i++) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="9"><div class="skeleton" style="height:16px;width:${70 + (i % 3) * 8}%;">&nbsp;</div></td>`;
      tbody.appendChild(tr);
    }
  }

  function renderEmpty(message) {
    tbody.innerHTML = `
      <tr><td colspan="9">
        <div class="incidents-empty">
          <div class="incidents-empty-icon">◌</div>
          <h3>No incidents match these filters</h3>
          <p>${message || 'Try clearing the search or filters above.'}</p>
        </div>
      </td></tr>`;
  }

  function renderErrorRow(err) {
    tbody.innerHTML = `
      <tr><td colspan="9">
        <div class="incidents-empty">
          <div class="incidents-empty-icon" style="color:#E5484D;">⚠</div>
          <h3 style="color:#E5484D;">Couldn't load incidents</h3>
          <p>${err.message || err}</p>
        </div>
      </td></tr>`;
  }

  // ---------------- Filtering ----------------
  function applyFilters() {
    const q = document.getElementById('search-input').value.trim().toLowerCase();
    const sev = document.getElementById('filter-severity').value;
    const attack = document.getElementById('filter-attack').value;
    const action = document.getElementById('filter-action').value;

    filtered = allIncidents.filter((inc) => {
      if (sev && inc.severity !== sev) return false;
      if (attack && inc.attack_type !== attack) return false;
      if (action && inc.action_taken !== action) return false;
      if (q) {
        const haystack = `${inc.user} ${inc.source_ip} ${inc.dst_ip} ${inc.attack_type} ${inc.incident_id}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });

    sortFiltered();
    page = 1;
    render();
  }

  function sortFiltered() {
    filtered.sort((a, b) => {
      let av = a[sortKey];
      let bv = b[sortKey];
      if (typeof av === 'string') av = av.toLowerCase();
      if (typeof bv === 'string') bv = bv.toLowerCase();
      if (av < bv) return sortDir === 'asc' ? -1 : 1;
      if (av > bv) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }

  // ---------------- Rendering ----------------
  function severityDot(sev) {
    const color = Util.SEVERITY_COLOR[sev] || '#7C8798';
    return `<span class="sev-pill ${Util.severityClass(sev)}" style="color:${color}">${sev}</span>`;
  }

  function render() {
    resultCount.textContent = `${filtered.length} result${filtered.length === 1 ? '' : 's'}`;

    if (filtered.length === 0) {
      renderEmpty();
      pageInfo.textContent = 'Page 0 of 0';
      prevBtn.disabled = true;
      nextBtn.disabled = true;
      return;
    }

    const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
    page = Math.min(page, totalPages);
    const start = (page - 1) * PAGE_SIZE;
    const pageItems = filtered.slice(start, start + PAGE_SIZE);

    tbody.innerHTML = '';
    pageItems.forEach((inc) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mono">${Util.fmtTime(inc.occurred_at)}</td>
        <td class="mono">${inc.incident_id}</td>
        <td>${inc.user}</td>
        <td>${inc.attack_type}</td>
        <td>${severityDot(inc.severity)}</td>
        <td class="mono">${inc.network_segment}</td>
        <td>${inc.action_taken}</td>
        <td class="mono">${Util.fmtMinutes(inc.mttd_minutes)}</td>
        <td class="mono">${Util.fmtMinutes(inc.mttr_minutes)}</td>
      `;
      tr.addEventListener('click', () => openIncidentDrawer(inc));
      tbody.appendChild(tr);
    });

    pageInfo.textContent = `Page ${page} of ${totalPages} · ${filtered.length} total`;
    prevBtn.disabled = page <= 1;
    nextBtn.disabled = page >= totalPages;
  }

  // ---------------- Drawer (incident detail) ----------------
  function openIncidentDrawer(inc) {
    const techniques = (inc.mitre_techniques || [])
      .map((t) => `${t.technique_id} (${t.technique_name})`)
      .join(', ');

    const rows = [
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
    ];

    document.getElementById('drawer-title').textContent = `Incident — ${inc.incident_id}`;
    const body = document.getElementById('drawer-body');
    body.innerHTML = '';
    rows.forEach(([k, v]) => {
      const row = document.createElement('div');
      row.className = 'drawer-row';
      row.innerHTML = `<span class="k">${k}</span><span class="v">${v}</span>`;
      body.appendChild(row);
    });

    document.getElementById('drawer').classList.add('open');
    document.getElementById('drawer-backdrop').classList.add('open');
  }

  document.getElementById('drawer-close').onclick = () => {
    document.getElementById('drawer').classList.remove('open');
    document.getElementById('drawer-backdrop').classList.remove('open');
  };
  document.getElementById('drawer-backdrop').onclick = () => {
    document.getElementById('drawer').classList.remove('open');
    document.getElementById('drawer-backdrop').classList.remove('open');
  };

  // ---------------- Sorting via header clicks ----------------
  document.querySelectorAll('th[data-sort]').forEach((th) => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (sortKey === key) {
        sortDir = sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        sortKey = key;
        sortDir = 'asc';
      }
      document.querySelectorAll('th[data-sort]').forEach((h) => h.classList.remove('sorted'));
      th.classList.add('sorted');
      th.querySelector('.sort-arrow').textContent = sortDir === 'asc' ? '▴' : '▾';
      sortFiltered();
      render();
    });
  });

  // ---------------- Filter / search wiring ----------------
  ['search-input'].forEach((id) =>
    document.getElementById(id).addEventListener('input', applyFilters)
  );
  ['filter-severity', 'filter-attack', 'filter-action'].forEach((id) =>
    document.getElementById(id).addEventListener('change', applyFilters)
  );

  prevBtn.addEventListener('click', () => {
    if (page > 1) { page -= 1; render(); }
  });
  nextBtn.addEventListener('click', () => {
    page += 1;
    render();
  });

  // ---------------- Boot ----------------
  (async function init() {
    renderSkeleton();
    try {
      allIncidents = await API.incidents();

      // populate attack-type filter dynamically from real data
      const attackTypes = [...new Set(allIncidents.map((i) => i.attack_type))].sort();
      const attackSelect = document.getElementById('filter-attack');
      attackTypes.forEach((t) => {
        const opt = document.createElement('option');
        opt.value = t;
        opt.textContent = t;
        attackSelect.appendChild(opt);
      });

      filtered = [...allIncidents];
      sortFiltered();
      render();
    } catch (err) {
      console.error('Failed to load incidents:', err);
      renderErrorRow(err);
    }
  })();
})();
