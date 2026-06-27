/* Incident feed — renders either:
     - the full correlated incident list (Full Analysis mode), or
     - a live-polling stream that adds one new incident every few seconds,
       looping over the dataset forever (Live Feed mode).
*/

const Feed = (() => {
  let allIncidents = [];
  let liveTimer = null;
  let liveCursor = 0;
  const LIVE_INTERVAL_MS = 2500;
  const MAX_LIVE_ITEMS = 40;

  function feedItemNode(inc, onClick) {
    const sevClass = Util.severityClass(inc.severity);
    return Util.el('div', { class: `feed-item ${sevClass}`, onclick: () => onClick && onClick(inc) }, [
      Util.el('span', { class: 'feed-time' }, [Util.fmtTime(inc.occurred_at)]),
      Util.el('span', { class: 'feed-id' }, [inc.incident_id]),
      Util.el('span', { class: 'feed-desc' }, [
        Util.el('b', {}, [inc.attack_type]),
        ` — ${inc.user} (${inc.network_segment})`,
      ]),
      Util.el('span', { class: `sev-pill ${sevClass}` }, [inc.severity]),
      Util.el('span', { class: 'feed-action' }, [inc.action_taken]),
    ]);
  }

  async function initFullAnalysis(onClick) {
    document.getElementById('feed-title').textContent = 'Incident Feed';
    document.getElementById('feed-tag').textContent = 'All correlated incidents';

    allIncidents = await API.incidents();
    const list = document.getElementById('feed-list');
    list.innerHTML = '';
    // newest first for the static analysis view
    [...allIncidents].reverse().forEach((inc) => list.appendChild(feedItemNode(inc, onClick)));
  }

  async function startLive(onClick) {
    stopLive();
    document.getElementById('feed-title').textContent = 'Live SOC Feed';
    document.getElementById('feed-tag').textContent = 'Simulated real-time stream';

    const list = document.getElementById('feed-list');
    list.innerHTML = '';
    liveCursor = 0;

    const pushNext = async () => {
      const page = await API.liveFeed(liveCursor, 1);
      liveCursor = page.next_cursor;
      const inc = page.items[0];
      if (!inc) return;

      const node = feedItemNode(inc, onClick);
      list.insertBefore(node, list.firstChild);

      while (list.children.length > MAX_LIVE_ITEMS) {
        list.removeChild(list.lastChild);
      }
    };

    await pushNext();
    liveTimer = setInterval(pushNext, LIVE_INTERVAL_MS);
  }

  function stopLive() {
    if (liveTimer) {
      clearInterval(liveTimer);
      liveTimer = null;
    }
  }

  return { initFullAnalysis, startLive, stopLive };
})();
