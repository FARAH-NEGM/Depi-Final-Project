/* Thin wrapper around fetch() for every backend endpoint. Keeps each
   feature module free of URL strings / fetch boilerplate. */

const API = {
  async _get(path) {
    const res = await fetch(path);
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      const err = new Error(body.error || `Request failed: ${path} (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return res.json();
  },

  async _post(path, body) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || `Request failed: ${path} (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return data;
  },

  // ---- read-only analytical views ----
  summary: () => API._get('/api/summary'),
  events: () => API._get('/api/events'),
  incidents: (status) => API._get(`/api/incidents${status ? `?status=${encodeURIComponent(status)}` : ''}`),
  incident: (id) => API._get(`/api/incidents/${encodeURIComponent(id)}`),
  incidentHistory: (id) => API._get(`/api/incidents/${encodeURIComponent(id)}/history`),
  mitreHeatmap: () => API._get('/api/mitre/heatmap'),
  mitreCatalog: () => API._get('/api/mitre/catalog'),
  trustScores: (order = 'ascending') => API._get(`/api/trust-scores?order=${order}`),
  trustScoreUser: (user) => API._get(`/api/trust-scores/${encodeURIComponent(user)}`),
  metrics: () => API._get('/api/metrics'),
  graph: () => API._get('/api/graph'),
  liveFeed: (cursor = 0, pageSize = 1) => API._get(`/api/live-feed?cursor=${cursor}&page_size=${pageSize}`),

  // ---- auth ----
  me: () => API._get('/api/auth/me'),
  login: (username, password) => API._post('/api/auth/login', { username, password }),
  logout: () => API._post('/api/auth/logout'),

  // ---- incident state machine / response / propagation (mutating) ----
  transitionIncident: (id, toStatus, note) =>
    API._post(`/api/incidents/${encodeURIComponent(id)}/transition`, { to_status: toStatus, note }),
  assignIncident: (id, username) =>
    API._post(`/api/incidents/${encodeURIComponent(id)}/assign`, { username }),
  respondToIncident: (id) => API._post(`/api/incidents/${encodeURIComponent(id)}/respond`),
  incidentResponses: (id) => API._get(`/api/incidents/${encodeURIComponent(id)}/responses`),
  allResponses: () => API._get('/api/responses'),
  getPropagation: (id) => API._get(`/api/incidents/${encodeURIComponent(id)}/propagation`),
  simulateAttack: (id) => API._post(`/api/incidents/${encodeURIComponent(id)}/simulate-attack`),

  // ---- assets ----
  assets: () => API._get('/api/assets'),
  assetsSummary: () => API._get('/api/assets/summary'),
  assetIncidents: (ip) => API._get(`/api/assets/${encodeURIComponent(ip)}/incidents`),

  // ---- audit trail (SOC Manager only) ----
  auditTrail: (limit = 200) => API._get(`/api/audit?limit=${limit}`),
  auditSummary: () => API._get('/api/audit/summary'),

  // ---- threat hunting ----
  huntQueries: () => API._get('/api/hunting/queries'),
  runHunt: (queryId) => API._post(`/api/hunting/queries/${encodeURIComponent(queryId)}/run`),
};
