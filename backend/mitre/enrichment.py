"""
Incident -> MITRE enrichment helper.

Keeps the Correlation Engine and MITRE Mapping Layer decoupled (the
correlation engine doesn't need to know about MITRE, and the MITRE module
doesn't need to know about incidents) while giving the API layer a single
call to get "incidents with MITRE techniques attached".
"""

from __future__ import annotations

from correlation.engine import Incident, get_incidents
from mitre.mapping import map_attack_type


def enrich_incident(incident: Incident) -> dict:
    techniques = map_attack_type(incident.attack_type)
    d = incident.to_dict()
    d["mitre_techniques"] = [
        {"technique_id": t.technique_id, "technique_name": t.technique_name, "tactic": t.tactic}
        for t in techniques
    ]
    return d


def enrich_incidents(incidents: list[Incident] | None = None) -> list[dict]:
    incidents = incidents if incidents is not None else get_incidents()
    return [enrich_incident(i) for i in incidents]


def mitre_heatmap(incidents: list[Incident] | None = None) -> list[dict]:
    """Count incidents per MITRE technique, for the ATT&CK heatmap view."""
    incidents = incidents if incidents is not None else get_incidents()
    counts: dict[str, dict] = {}

    for inc in incidents:
        for t in map_attack_type(inc.attack_type):
            key = t.technique_id
            if key not in counts:
                counts[key] = {
                    "technique_id": t.technique_id,
                    "technique_name": t.technique_name,
                    "tactic": t.tactic,
                    "incident_count": 0,
                }
            counts[key]["incident_count"] += 1

    return sorted(counts.values(), key=lambda x: x["incident_count"], reverse=True)


if __name__ == "__main__":
    heatmap = mitre_heatmap()
    for row in heatmap:
        print(row)
