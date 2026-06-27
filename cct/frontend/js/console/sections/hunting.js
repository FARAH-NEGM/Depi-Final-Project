/* Threat Hunting — runs real predicate-based queries against the ingested
   event set (see backend/hunting/queries.py). Security Analyst section. */

const HuntingSection = (() => {
  let queries = [];
  let activeQueryId = null;

  async function render(container, ctx) {
    container.innerHTML = `
      <div class="console-grid sidebar-right">
        <div class="cpanel">
          <div class="cpanel-head">
            <div><h3 id="hunt-result-title">Select a query</h3><p id="hunt-result-sub">Choose a saved hunt from the right to run it against ingested events</p></div>
          </div>
          <div class="cpanel-body flush" id="hunt-results"></div>
        </div>
        <div class="cpanel">
          <div class="cpanel-head"><div><h3>Saved Hunt Queries</h3><p>Real predicates over real events</p></div></div>
          <div class="cpanel-body" id="hunt-query-list" style="display:flex;flex-direction:column;gap:10px;"></div>
        </div>
      </div>
    `;

    queries = await API.huntQueries();
    renderQueryList();
    renderEmptyResults();
  }

  function renderQueryList() {
    const wrap = document.getElementById('hunt-query-list');
    wrap.innerHTML = queries.map((q) => `
      <div class="hunt-query-card ${q.query_id === activeQueryId ? 'active' : ''}" data-id="${q.query_id}">
        <h4>${q.label}</h4>
        <p>${q.description}</p>
        <span class="hunt-match-count">${q.match_count} current match${q.match_count === 1 ? '' : 'es'}</span>
      </div>
    `).join('');

    wrap.querySelectorAll('.hunt-query-card').forEach((card) => {
      card.addEventListener('click', () => runQuery(card.dataset.id));
    });
  }

  function renderEmptyResults() {
    document.getElementById('hunt-results').innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">⌖</div>
        <h4>No query running</h4>
        <p>Pick a saved hunt query to see real matching events from the ingested log.</p>
      </div>
    `;
  }

  async function runQuery(queryId) {
    activeQueryId = queryId;
    renderQueryList();

    document.getElementById('hunt-results').innerHTML = `<div class="console-loading">Running query…</div>`;

    try {
      const result = await API.runHunt(queryId);
      document.getElementById('hunt-result-title').textContent = result.label;
      document.getElementById('hunt-result-sub').textContent = `${result.match_count} matching event(s) — ${result.description}`;

      const wrap = document.getElementById('hunt-results');
      if (!result.matches.length) {
        wrap.innerHTML = `<div class="empty-state"><div class="empty-state-icon">◌</div><h4>No matches</h4><p>This query found nothing in the current event set — a genuinely clean result, not an error.</p></div>`;
        return;
      }

      wrap.innerHTML = result.matches.map((e) => `
        <div class="crow not-clickable">
          <div class="crow-main">
            <span class="sev-pill ${Util.severityClass(e.severity)}" style="color:${Util.SEVERITY_COLOR[e.severity]}">${e.severity}</span>
            <span class="crow-title">${e.attack_type} — ${e.src_ip} → ${e.dst_ip}</span>
          </div>
          <div class="crow-right">
            <span class="crow-meta">${e.protocol}</span>
            <span class="crow-meta">${Util.fmtTime(e.timestamp)}</span>
          </div>
        </div>
      `).join('');
    } catch (err) {
      document.getElementById('hunt-results').innerHTML = `<div class="empty-state"><p style="color:var(--sev-critical);">Query failed: ${err.message}</p></div>`;
    }
  }

  return { render };
})();
