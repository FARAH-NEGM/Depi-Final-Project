/* Shared formatting / color helpers used across the dashboard modules. */

const Util = {
  SEVERITY_COLOR: {
    Critical: '#E5484D',
    High: '#F5A623',
    Medium: '#E8C547',
    Low: '#3FB68B',
  },

  RISK_COLOR: {
    'Critical Risk': '#E5484D',
    'High Risk': '#F5A623',
    'Medium Risk': '#E8C547',
    'Low Risk': '#3FB68B',
  },

  severityClass(sev) {
    return `sev-${(sev || '').toLowerCase()}-bg`;
  },

  fmtMinutes(mins) {
    if (mins == null) return '—';
    if (mins < 60) return `${mins.toFixed(1)}m`;
    return `${(mins / 60).toFixed(1)}h`;
  },

  fmtTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit',
    });
  },

  fmtClock(date) {
    return date.toLocaleTimeString(undefined, { hour12: false });
  },

  truncate(str, n) {
    if (!str) return '';
    return str.length > n ? str.slice(0, n - 1) + '…' : str;
  },

  el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k === 'html') node.innerHTML = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const child of children) {
      if (child == null) continue;
      node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    }
    return node;
  },
};
