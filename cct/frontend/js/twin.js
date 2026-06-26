/* Cyber Digital Twin — renders the org's IP / user / segment graph with
   Cytoscape.js, colored by risk score. This is the visual centerpiece of
   the dashboard. */

const Twin = (() => {
  let cy = null;

  const TYPE_COLOR = {
    ip: '#5B9BD5',
    user: '#B084E8',
    segment: '#6B7785',
  };

  function riskColor(score) {
    if (score >= 80) return '#E5484D';
    if (score >= 50) return '#F5A623';
    if (score >= 20) return '#E8C547';
    return '#3FB68B';
  }

  function nodeColor(data) {
    // Segments are structural, not risk-bearing — color by type.
    if (data.type === 'segment') return TYPE_COLOR.segment;
    // IPs/users: color by risk if they have any signal, else by type (muted).
    if (data.risk_score > 0) return riskColor(data.risk_score);
    return TYPE_COLOR[data.type] || '#6B7785';
  }

  function nodeSize(data) {
    const base = data.type === 'segment' ? 36 : 14;
    const bump = Math.min(data.event_count || 0, 6) * 2;
    return base + bump;
  }

  async function init(containerId, onNodeClick) {
    const graphData = await API.graph();

    const elements = [
      ...graphData.nodes.map((n) => ({
        data: { ...n.data, color: nodeColor(n.data), size: nodeSize(n.data) },
      })),
      ...graphData.edges.map((e) => ({ data: e.data })),
    ];

    cy = cytoscape({
      container: document.getElementById(containerId),
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            width: 'data(size)',
            height: 'data(size)',
            'border-width': 1.5,
            'border-color': 'rgba(255,255,255,0.15)',
            label: 'data(label)',
            'font-size': 8,
            'font-family': 'IBM Plex Mono, monospace',
            color: '#7C8798',
            'text-valign': 'bottom',
            'text-margin-y': 4,
            'text-opacity': 0,
          },
        },
        {
          selector: 'node[type = "segment"]',
          style: {
            'border-width': 2,
            'border-color': '#F5A623',
            'border-style': 'dashed',
            'text-opacity': 1,
            'font-size': 11,
            color: '#E4E8EE',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1,
            'line-color': 'rgba(124,135,152,0.25)',
            'target-arrow-shape': 'none',
            'curve-style': 'haystack',
            'haystack-radius': 0.3,
          },
        },
        {
          selector: 'edge[relation = "communicates_with"]',
          style: { 'line-color': 'rgba(229,72,77,0.30)' },
        },
        {
          selector: '.highlighted',
          style: {
            'background-color': '#F5A623',
            'text-opacity': 1,
            'z-index': 999,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
            'border-color': '#F5A623',
            'text-opacity': 1,
          },
        },
      ],
      layout: {
        name: 'cose',
        animate: false,
        nodeRepulsion: 8000,
        idealEdgeLength: 60,
        gravity: 0.25,
        numIter: 800,
      },
      minZoom: 0.2,
      maxZoom: 3,
      wheelSensitivity: 0.3,
    });

    cy.on('tap', 'node', (evt) => {
      const data = evt.target.data();
      if (onNodeClick) onNodeClick(data);
    });

    cy.on('mouseover', 'node', (evt) => {
      evt.target.addClass('highlighted');
    });
    cy.on('mouseout', 'node', (evt) => {
      evt.target.removeClass('highlighted');
    });

    document.getElementById('twin-node-count').textContent = `${graphData.nodes.length} nodes`;
    document.getElementById('twin-edge-count').textContent = `${graphData.edges.length} edges`;

    return cy;
  }

  function highlightUser(userName) {
    if (!cy) return;
    cy.elements().removeClass('highlighted');
    const node = cy.getElementById(userName);
    if (node) {
      node.addClass('highlighted');
      cy.animate({ center: { eles: node }, zoom: 1.4 }, { duration: 400 });
    }
  }

  return { init, highlightUser };
})();
