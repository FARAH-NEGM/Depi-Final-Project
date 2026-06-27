/* Thin wrapper around fetch() for every backend endpoint. Keeps each
   feature module free of URL strings / fetch boilerplate. */

const API = {
  async _get(path) {
    const res = await fetch(path);
    if (!res.ok) {
      throw new Error(`Request failed: ${path} (${res.status})`);
    }
    return res.json();
  },

  summary: () => API._get('/api/summary'),
  events: () => API._get('/api/events'),
  incidents: () => API._get('/api/incidents'),
  incident: (id) => API._get(`/api/incidents/${encodeURIComponent(id)}`),
  mitreHeatmap: () => API._get('/api/mitre/heatmap'),
  mitreCatalog: () => API._get('/api/mitre/catalog'),
  trustScores: (order = 'ascending') => API._get(`/api/trust-scores?order=${order}`),
  trustScoreUser: (user) => API._get(`/api/trust-scores/${encodeURIComponent(user)}`),
  metrics: () => API._get('/api/metrics'),
  graph: () => API._get('/api/graph'),
  liveFeed: (cursor = 0, pageSize = 1) => API._get(`/api/live-feed?cursor=${cursor}&page_size=${pageSize}`),
};
