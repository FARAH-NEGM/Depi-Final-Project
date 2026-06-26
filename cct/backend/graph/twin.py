"""
Cyber Digital Twin  (Graph Layer)
===================================
Builds a graph representation of the organisation's network as observed
through the event log: hosts (IPs), users, and network segments as nodes,
with edges representing relationships ("communicates_with", "operates_from",
"flagged_in") seen in the data. The frontend renders this with Cytoscape.js.

Node types:
  - ip        : a source or destination IP address
  - user      : a user account
  - segment   : a network segment (Segment A/B/C/D)

Edge types:
  - communicates_with : src_ip -> dst_ip (an observed network flow)
  - operates_from      : user -> src_ip  (the user account associated with traffic)
  - located_in         : ip -> segment   (which segment that IP's traffic was seen in)

Node risk colouring
--------------------
Each `ip` and `user` node carries a `risk_score` (0-100, higher = riskier)
derived from the worst severity event associated with it, so the frontend
can colour nodes red/orange/yellow/green without recomputing anything.
"""

from __future__ import annotations

from typing import Optional

import networkx as nx

from ingestion.loader import Event, get_events

SEVERITY_TO_RISK = {"Critical": 100, "High": 70, "Medium": 40, "Low": 15}


def build_graph(events: Optional[list[Event]] = None) -> nx.DiGraph:
    events = events if events is not None else get_events()
    g = nx.DiGraph()

    for e in events:
        risk = SEVERITY_TO_RISK.get(e.severity, 30)

        # --- IP nodes ---
        for ip in (e.src_ip, e.dst_ip):
            if g.has_node(ip):
                g.nodes[ip]["risk_score"] = max(g.nodes[ip]["risk_score"], risk if ip == e.src_ip else 0)
                g.nodes[ip]["event_count"] += 1
            else:
                g.add_node(
                    ip,
                    type="ip",
                    label=ip,
                    risk_score=risk if ip == e.src_ip else 0,
                    event_count=1,
                )

        # --- user node ---
        if g.has_node(e.user):
            g.nodes[e.user]["risk_score"] = max(g.nodes[e.user]["risk_score"], risk)
            g.nodes[e.user]["event_count"] += 1
        else:
            g.add_node(e.user, type="user", label=e.user, risk_score=risk, event_count=1)

        # --- segment node ---
        if not g.has_node(e.network_segment):
            g.add_node(e.network_segment, type="segment", label=e.network_segment, risk_score=0, event_count=0)
        g.nodes[e.network_segment]["event_count"] += 1

        # --- edges ---
        g.add_edge(
            e.src_ip,
            e.dst_ip,
            relation="communicates_with",
            attack_type=e.attack_type,
            severity=e.severity,
            event_id=e.event_id,
        )
        g.add_edge(e.user, e.src_ip, relation="operates_from", event_id=e.event_id)
        g.add_edge(e.src_ip, e.network_segment, relation="located_in", event_id=e.event_id)

    return g


def graph_to_cytoscape(g: Optional[nx.DiGraph] = None) -> dict:
    """Serialise the networkx graph into Cytoscape.js elements format."""
    g = g if g is not None else build_graph()

    nodes = []
    for node_id, data in g.nodes(data=True):
        nodes.append(
            {
                "data": {
                    "id": node_id,
                    "label": data.get("label", node_id),
                    "type": data.get("type", "unknown"),
                    "risk_score": data.get("risk_score", 0),
                    "event_count": data.get("event_count", 0),
                }
            }
        )

    edges = []
    for idx, (u, v, data) in enumerate(g.edges(data=True)):
        edges.append(
            {
                "data": {
                    "id": f"e{idx}",
                    "source": u,
                    "target": v,
                    "relation": data.get("relation"),
                    "attack_type": data.get("attack_type"),
                    "severity": data.get("severity"),
                }
            }
        )

    return {"nodes": nodes, "edges": edges}


_CACHE: nx.DiGraph | None = None


def get_graph(force_reload: bool = False) -> nx.DiGraph:
    global _CACHE
    if _CACHE is None or force_reload:
        _CACHE = build_graph()
    return _CACHE


if __name__ == "__main__":
    g = get_graph()
    print(f"Graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
    by_type: dict[str, int] = {}
    for _, data in g.nodes(data=True):
        by_type[data["type"]] = by_type.get(data["type"], 0) + 1
    print("Node types:", by_type)

    cyto = graph_to_cytoscape(g)
    print(f"Cytoscape export: {len(cyto['nodes'])} nodes, {len(cyto['edges'])} edges")
