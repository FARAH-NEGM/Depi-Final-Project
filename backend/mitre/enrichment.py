"""
Incident -> MITRE enrichment helper  —  v2
==========================================
v2 changes:
- Uses map_attack_dynamic() instead of map_attack_type() so technique
  selection accounts for attack_signature, protocol, and severity.
- Enriched incident includes: tactic_chain, technique list with
  sub_technique + confidence_score.
- Backward compatible: enrich_incident / enrich_incidents / mitre_heatmap
  all keep the same signatures.
"""

from __future__ import annotations

from correlation.engine import Incident, get_incidents, SEVERITY_RISK, TACTIC_CRITICALITY
from ingestion.loader import get_events
import math
from mitre.mapping import map_attack_dynamic, build_mitre_tactic_chain


# Build a quick event lookup so we can pull protocol/signature per incident
def _get_event_lookup() -> dict[str, object]:
    return {e.event_id: e for e in get_events()}


def explain_risk(incident: Incident) -> dict:
    """
    Explain the risk score using the same weighted model as the correlation
    engine. This makes the score auditable instead of a black-box number.
    """
    severity_score = SEVERITY_RISK.get(incident.severity, 40)
    count_score = min(100.0, 100 * math.log1p(incident.event_count) / math.log1p(20))
    chain_score = min(100.0, (incident.chain_confidence or 0.0) * 100)
    tactic_score = (
        sum(TACTIC_CRITICALITY.get(t, 0.5) for t in incident.mitre_chain) / len(incident.mitre_chain) * 100
        if incident.mitre_chain else 40.0
    )

    factors = [
        {
            "label": "Severity impact",
            "weight": "40%",
            "input": incident.severity,
            "component_score": round(severity_score, 2),
            "weighted_points": round(0.40 * severity_score, 2),
        },
        {
            "label": "Related event volume",
            "weight": "20%",
            "input": f"{incident.event_count} event(s)",
            "component_score": round(count_score, 2),
            "weighted_points": round(0.20 * count_score, 2),
        },
        {
            "label": "Attack chain confidence",
            "weight": "20%",
            "input": f"{round((incident.chain_confidence or 0.0) * 100)}%",
            "component_score": round(chain_score, 2),
            "weighted_points": round(0.20 * chain_score, 2),
        },
        {
            "label": "MITRE tactic criticality",
            "weight": "20%",
            "input": " → ".join(incident.mitre_chain) if incident.mitre_chain else "No tactic chain",
            "component_score": round(tactic_score, 2),
            "weighted_points": round(0.20 * tactic_score, 2),
        },
    ]
    return {
        "formula": "40% severity + 20% event volume + 20% attack-chain confidence + 20% MITRE tactic criticality",
        "score": incident.risk_score,
        "level": incident.risk_level,
        "factors": factors,
    }


def enrich_incident(incident: Incident, event_lookup: dict | None = None) -> dict:
    if event_lookup is None:
        event_lookup = _get_event_lookup()

    ev = event_lookup.get(incident.event_id)
    techniques = map_attack_dynamic(
        attack_type      = incident.attack_type,
        attack_signature = getattr(ev, "attack_signature", "") if ev else "",
        protocol         = getattr(ev, "protocol",         "") if ev else "",
        severity         = incident.severity,
        payload          = getattr(ev, "payload_snippet",  "") if ev else "",
    )

    tactic_chain = build_mitre_tactic_chain(techniques)

    d = incident.to_dict()
    d["mitre_techniques"] = [
        {
            "technique_id":    t.technique_id,
            "technique_name":  t.technique_name,
            "tactic":          t.tactic,
            "sub_technique":   t.sub_technique,
            "confidence_score": t.confidence_score,
        }
        for t in techniques
    ]
    d["tactic_chain"] = tactic_chain
    d["risk_explanation"] = explain_risk(incident)

    # mitre_chain on the incident itself (from correlation engine) takes
    # precedence if non-empty; otherwise fall back to tactic_chain
    if not d.get("mitre_chain"):
        d["mitre_chain"] = tactic_chain

    return d


def enrich_incidents(incidents: list[Incident] | None = None) -> list[dict]:
    incidents    = incidents if incidents is not None else get_incidents()
    event_lookup = _get_event_lookup()
    return [enrich_incident(i, event_lookup) for i in incidents]


def mitre_heatmap(incidents: list[Incident] | None = None) -> list[dict]:
    """Count incidents per MITRE technique, for the ATT&CK heatmap view."""
    incidents    = incidents if incidents is not None else get_incidents()
    event_lookup = _get_event_lookup()
    counts: dict[str, dict] = {}

    for inc in incidents:
        ev = event_lookup.get(inc.event_id)
        techniques = map_attack_dynamic(
            inc.attack_type,
            attack_signature = getattr(ev, "attack_signature", "") if ev else "",
            protocol         = getattr(ev, "protocol",         "") if ev else "",
            severity         = inc.severity,
        )
        for t in techniques:
            key = t.technique_id
            if key not in counts:
                counts[key] = {
                    "technique_id":    t.technique_id,
                    "technique_name":  t.technique_name,
                    "tactic":          t.tactic,
                    "sub_technique":   t.sub_technique,
                    "incident_count":  0,
                    "avg_confidence":  0.0,
                    "_conf_sum":       0.0,
                }
            counts[key]["incident_count"] += 1
            counts[key]["_conf_sum"]      += t.confidence_score

    # Compute average confidence, drop internal key
    result = []
    for row in counts.values():
        row["avg_confidence"] = round(row.pop("_conf_sum") / row["incident_count"], 3)
        result.append(row)

    return sorted(result, key=lambda x: x["incident_count"], reverse=True)


if __name__ == "__main__":
    heatmap = mitre_heatmap()
    print(f"Unique techniques in heatmap: {len(heatmap)}")
    for row in heatmap[:5]:
        print(row)
