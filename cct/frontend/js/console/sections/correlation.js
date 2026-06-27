/* Correlation Engine — explains and visualizes how raw events get grouped
   into incidents and user "threads." Shared by both roles, since
   understanding correlation logic matters for analysts and managers alike. */

const CorrelationSection = (() => {
  async function render(container, ctx) {
    container.innerHTML = `
      <div class="console-grid cols-2">
        <div class="cpanel">
          <div class="cpanel-head"><div><h3>How Correlation Works</h3><p>Real logic, not a black box</p></div></div>
          <div class="cpanel-body" style="font-size:13px;line-height:1.7;color:var(--text-dim);">
            <p>Every incoming event becomes its own <b style="color:var(--text-main);">Incident</b> — single,
            self-contained security events are realistic on their own. Separately, every incident is tagged
            with a <b style="color:var(--text-main);">thread_id</b> shared by every other incident involving
            the same user account.</p>
            <p>This dataset's source IPs are all unique (synthetic traffic), so IP-based time-window
            correlation wouldn't find anything real. User-account correlation is the genuine signal here:
            it surfaces <b style="color:var(--accent);" id="corr-repeat-count">—</b> accounts with more than
            one incident on record — exactly what the Trust Score engine uses to compute behavioral risk.</p>
          </div>
        </div>
        <div class="cpanel">
          <div class="cpanel-head"><div><h3>Repeat-Offender Threads</h3><p>Users with 2+ correlated incidents</p></div></div>
          <div class="cpanel-body flush" id="corr-threads" style="max-height:280px;overflow-y:auto;"></div>
        </div>
      </div>
      <div class="cpanel" style="margin-top:16px;height:480px;">
        <div class="cpanel-head">
          <div><h3>Cyber Digital Twin</h3><p>Click any node to inspect it; click a thread above to highlight that user</p></div>
          <span class="panel-tag"><span id="twin-node-count">—</span> · <span id="twin-edge-count">—</span></span>
        </div>
        <div id="corr-twin" style="flex:1;min-height:0;"></div>
      </div>
    `;

    const incidents = await API.incidents();
    const threads = {};
    incidents.forEach((inc) => {
      threads[inc.thread_id] = threads[inc.thread_id] || { user: inc.user, incidents: [] };
      threads[inc.thread_id].incidents.push(inc);
    });
    const repeatThreads = Object.values(threads).filter((t) => t.incidents.length > 1);

    document.getElementById('corr-repeat-count').textContent = repeatThreads.length;
    renderThreads(repeatThreads);

    try {
      await Twin.init('corr-twin', (data) => {
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
      document.getElementById('corr-twin').innerHTML = `<div class="empty-state"><p>Graph failed to load: ${err.message}</p></div>`;
    }
  }

  function renderThreads(threads) {
    const wrap = document.getElementById('corr-threads');
    if (!threads.length) {
      wrap.innerHTML = `<div class="empty-state"><div class="empty-state-icon">◌</div><h4>No repeat offenders</h4><p>Every user currently has exactly one incident.</p></div>`;
      return;
    }
    threads.sort((a, b) => b.incidents.length - a.incidents.length);
    wrap.innerHTML = threads.map((t) => `
      <div class="crow" data-user="${encodeURIComponent(t.user)}">
        <div class="crow-main">
          <span class="crow-title">${t.user}</span>
        </div>
        <div class="crow-right">
          <span class="crow-meta">${t.incidents.length} incidents</span>
        </div>
      </div>
    `).join('');

    wrap.querySelectorAll('.crow').forEach((row) => {
      row.addEventListener('click', () => {
        Twin.highlightUser(decodeURIComponent(row.dataset.user));
      });
    });
  }

  return { render };
})();
