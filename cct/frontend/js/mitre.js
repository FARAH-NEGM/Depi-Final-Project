/* MITRE ATT&CK heatmap — bar-style frequency view of which techniques show
   up most often across correlated incidents. */

const Mitre = (() => {
  async function init() {
    const heatmap = await API.mitreHeatmap();
    render(heatmap);
    return heatmap;
  }

  function render(heatmap) {
    const container = document.getElementById('mitre-heatmap');
    container.innerHTML = '';

    const max = Math.max(...heatmap.map((h) => h.incident_count), 1);

    heatmap.forEach((row) => {
      const pct = (row.incident_count / max) * 100;

      const el = Util.el('div', { class: 'mitre-row' }, [
        Util.el('span', { class: 'mitre-id' }, [row.technique_id]),
        Util.el('span', { class: 'mitre-name', title: row.technique_name }, [row.technique_name]),
        Util.el('span', { class: 'mitre-tactic' }, [row.tactic]),
        Util.el('span', { class: 'mitre-count' }, [String(row.incident_count)]),
        Util.el('div', { class: 'mitre-bar-track' }, [
          Util.el('div', { class: 'mitre-bar-fill', style: `width:${pct}%` }),
        ]),
      ]);

      container.appendChild(el);
    });
  }

  return { init };
})();
